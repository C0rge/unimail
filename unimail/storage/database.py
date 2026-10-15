"""加密数据库：优先 SQLCipher，缺失时降级为 SQLite + 字段级加密。

加密等级是**确定性行为**而不是「取决于可选依赖」：
    - 库文件由哪种驱动创建，记录在 sidecar（`*.meta.json` 的 driver 字段）
      与库内 `meta.driver` 两处；打开时以 sidecar 为准决定是否下发 `PRAGMA key`，
      从而避免「明文库被当成加密库打开」→ `file is not a database` → 应用打不开。
    - 环境缺少 SQLCipher 但库是加密库时**快速失败**并给出可操作提示，
      而不是抛出难懂的底层错误。
    - 幂等的迁移入口：`migrate_to_encrypted()` / `migrate_to_plaintext()`。

并发：
    每个线程一条连接（thread-local），写入路径由 `_write_lock` 串行化；
    `transaction()` 会持有同一把锁，保证事务边界不被其它线程的 autocommit 打断。
    连接注册表保证退出时能回收**所有**线程的连接。
"""
from __future__ import annotations

import contextlib
import logging
import os
import sqlite3
import threading
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ..config import (
    DB_BUSY_TIMEOUT_MS,
    DB_CACHE_KIB,
    DB_VERSION,
    sqlcipher_pip_hint,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------- 驱动探测
_SQLCIPHER_AVAILABLE = False
try:  # pragma: no cover - 依赖环境
    from sqlcipher3 import dbapi2 as sqlcipher_db  # type: ignore
    _SQLCIPHER_AVAILABLE = True
except ImportError:
    sqlcipher_db = None  # type: ignore

def sqlcipher_available() -> bool:
    """当前环境是否具备 SQLCipher 驱动。

    **唯一的查询入口**。历史上同时存在「模块级常量 `SQLCIPHER_AVAILABLE`」与
    「内部变量 `_SQLCIPHER_AVAILABLE`」两份事实源：前者在导入期被各模块按值绑定，
    后者在本模块内实时读取。两者一旦不同步（例如测试中替换开关、或将来做运行时
    探测），就会出现「Database 认为自己加密、调用方认为环境缺依赖」的分裂。
    因此统一改成函数调用，取值永远反映当下状态。
    """
    return _SQLCIPHER_AVAILABLE


# 兼容旧引用：新代码请使用 sqlcipher_available()。此名在导入期绑定，仅作兼容保留。
SQLCIPHER_AVAILABLE = _SQLCIPHER_AVAILABLE

DRIVER_SQLCIPHER = "sqlcipher"
DRIVER_SQLITE3 = "sqlite3"

# SQLCipher 与标准库 sqlite3 是两套彼此独立的 C 扩展：Row / Cursor / 异常类型
# 之间不存在继承关系（sqlite3.Row 只接受 sqlite3.Cursor 作参数）。因此凡是两种
# 驱动都要走的代码，都必须按当前连接实际使用的驱动取对应的类型，不能混用。
_DB_ERRORS: tuple[type[Exception], ...] = (sqlite3.DatabaseError,)
if _SQLCIPHER_AVAILABLE:
    _DB_ERRORS += (sqlcipher_db.DatabaseError,)


class DatabaseError(RuntimeError):
    """数据库无法打开或状态异常（面向用户的可读错误）。"""


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    id              TEXT PRIMARY KEY,
    platform        TEXT NOT NULL,
    email           TEXT NOT NULL,
    display_name    TEXT DEFAULT '',
    imap_host       TEXT NOT NULL,
    imap_port       INTEGER NOT NULL,
    use_ssl         INTEGER NOT NULL DEFAULT 1,
    username        TEXT NOT NULL,
    sync_interval   INTEGER NOT NULL DEFAULT 300,
    last_synced_at  TEXT,
    status          TEXT NOT NULL DEFAULT 'ok',
    created_at      TEXT NOT NULL,
    UNIQUE(platform, email)
);

CREATE TABLE IF NOT EXISTS credentials (
    id          TEXT PRIMARY KEY,
    ciphertext  BLOB NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    FOREIGN KEY(id) REFERENCES accounts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sync_cursors (
    account_id   TEXT NOT NULL,
    folder       TEXT NOT NULL,
    last_uid     INTEGER NOT NULL DEFAULT 0,
    uid_validity INTEGER,
    updated_at   TEXT,
    PRIMARY KEY(account_id, folder),
    FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS mails (
    id              TEXT PRIMARY KEY,
    account_id      TEXT NOT NULL,
    platform        TEXT NOT NULL,
    folder          TEXT NOT NULL DEFAULT 'INBOX',
    uid             TEXT NOT NULL,
    uid_validity    INTEGER NOT NULL DEFAULT 0,
    message_id      TEXT,
    subject         TEXT,
    from_name       TEXT,
    from_addr       TEXT,
    to_addrs        TEXT,
    date            TEXT NOT NULL,
    preview         TEXT,
    body_text       TEXT,
    body_html       TEXT,
    has_attachments INTEGER NOT NULL DEFAULT 0,
    is_read         INTEGER NOT NULL DEFAULT 0,
    is_starred      INTEGER NOT NULL DEFAULT 0,
    raw_size        INTEGER DEFAULT 0,
    created_at      TEXT NOT NULL,
    UNIQUE(account_id, folder, uid)
);

CREATE TABLE IF NOT EXISTS attachments (
    id           TEXT PRIMARY KEY,
    mail_id      TEXT NOT NULL,
    filename     TEXT,
    content_type TEXT,
    size         INTEGER,
    stored_path  TEXT,
    content_id   TEXT,
    part_index   TEXT,
    FOREIGN KEY(mail_id) REFERENCES mails(id) ON DELETE CASCADE
);
"""

# 索引与表分开：老库在迁移补齐列之前，引用新列的索引是无法建立的，
# 因此索引必须**在所有迁移完成之后**再创建。
#
# 索引设计要点：
#   * 列表排序统一是 `ORDER BY date DESC`，所以凡是带筛选维度的索引都把
#     `date DESC` 放在末尾，才能既做过滤又免掉 `TEMP B-TREE` 排序。
#   * 「仅未读」在历史实现里走 `idx_mails_read(is_read)`，取完全部未读再全量排序
#     （实测 2 万封 14.8 ms）。改成 `(is_read, date DESC)` 后过滤与排序一次完成。
#   * 账号维度是 UI 最常用的组合，补 `(account_id, is_read, date DESC)`，
#     它同时能高效服务「按账号统计未读数」的 GROUP BY。
INDEXES = """
CREATE INDEX IF NOT EXISTS idx_mails_date     ON mails(date DESC);
CREATE INDEX IF NOT EXISTS idx_mails_account  ON mails(account_id, date DESC);
CREATE INDEX IF NOT EXISTS idx_mails_platform ON mails(platform, date DESC);
CREATE INDEX IF NOT EXISTS idx_mails_read     ON mails(is_read, date DESC);
CREATE INDEX IF NOT EXISTS idx_mails_acc_read ON mails(account_id, is_read, date DESC);
CREATE INDEX IF NOT EXISTS idx_mails_folder   ON mails(account_id, folder, uid);
CREATE INDEX IF NOT EXISTS idx_mails_validity ON mails(account_id, folder, uid_validity);
CREATE INDEX IF NOT EXISTS idx_attach_mail    ON attachments(mail_id);
"""

# 需要重建的索引：定义已变更，`CREATE INDEX IF NOT EXISTS` 对同名旧索引无效，
# 必须先 DROP 再建，否则老库会一直沿用旧定义。
REBUILT_INDEXES = {
    "idx_mails_read": "CREATE INDEX IF NOT EXISTS idx_mails_read "
                      "ON mails(is_read, date DESC)",
}


class Database:
    """线程安全的加密数据库封装。

    每次操作从线程本地连接取连接，避免跨线程共享 sqlite 连接。
    """

    def __init__(self, path: Path, db_key: bytes | None = None,
                 encrypted: bool | None = None) -> None:
        """打开数据库。

        encrypted=None 时按历史行为推断（装有 SQLCipher 且有密钥即加密）。
        显式传入 encrypted 可精确控制——这是打通「降级/升级路径」的关键：
        明文库必须以明文方式打开，否则 `PRAGMA key` 会让整个库变成
        `file is not a database`，用户彻底打不开应用。
        """
        self.path = Path(path)
        self._db_key = db_key
        self._local = threading.local()
        self._write_lock = threading.RLock()
        self._conns: list[Any] = []
        self._conns_lock = threading.Lock()
        self._closed = False

        if encrypted is None:
            encrypted = _SQLCIPHER_AVAILABLE and db_key is not None
        if encrypted and not _SQLCIPHER_AVAILABLE:
            raise DatabaseError(
                "该数据库使用 SQLCipher 整库加密，但当前环境未安装 sqlcipher3。\n"
                "请先安装依赖后重新启动：\n"
                f"    {sqlcipher_pip_hint()}\n"
                "（切勿删除数据库文件，安装依赖后即可正常打开。）"
            )
        if encrypted and db_key is None:
            raise DatabaseError("数据库为加密库，但未提供解锁密钥")

        self._encrypted = bool(encrypted)
        self.encrypted = self._encrypted
        self._init_connection()

    # ------------------------------------------------------------ 连接
    @property
    def driver_name(self) -> str:
        """创建/打开本库所使用的驱动标识，用于写入 sidecar 与 meta。"""
        return DRIVER_SQLCIPHER if self._encrypted else DRIVER_SQLITE3

    @property
    def encryption_level(self) -> str:
        if self._encrypted:
            return "整库加密 (SQLCipher AES-256)"
        if _SQLCIPHER_AVAILABLE:
            return "字段级加密（数据库为明文，可迁移为整库加密）"
        return "字段级加密（未安装 SQLCipher，整库为明文）"

    @property
    def rekey_supported(self) -> bool:
        """是否支持整库重加密（仅以加密方式打开的库支持）。"""
        return self._encrypted

    @property
    def _key_hex(self) -> str:
        """当前整库密钥的 hex（SQLCipher 用 `x'…'` 形式接收）。

        构造函数已保证「encrypted ⇒ db_key 非空」，这里再兜一次：
        密钥缺失时必须是可读错误，而不是 `None.hex()` 的 AttributeError。
        """
        if self._db_key is None:
            raise DatabaseError("数据库为加密库，但未提供解锁密钥")
        return self._db_key.hex()

    def _new_connection(self):
        if self._encrypted:
            conn = sqlcipher_db.connect(str(self.path), check_same_thread=False)
            conn.execute(f"PRAGMA key = \"x'{self._key_hex}'\"")
            conn.execute("PRAGMA cipher_memory_security = ON")
            # 必须用 SQLCipher 自己的 Row：sqlite3.Row 会拒绝 sqlcipher3 的 Cursor，
            # 抛 "Row() argument 1 must be sqlite3.Cursor"。
            row_factory = getattr(sqlcipher_db, "Row", sqlite3.Row)
        else:
            conn = sqlite3.connect(str(self.path), check_same_thread=False)
            row_factory = sqlite3.Row
        conn.row_factory = row_factory
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute(f"PRAGMA busy_timeout = {int(DB_BUSY_TIMEOUT_MS)}")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute(f"PRAGMA cache_size = {-abs(int(DB_CACHE_KIB))}")
        with self._conns_lock:
            self._conns.append(conn)
        return conn

    def _conn(self):
        if self._closed:
            raise DatabaseError("数据库连接已关闭")
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._new_connection()
            self._local.conn = conn
        return conn

    def _init_connection(self) -> None:
        conn = self._conn()
        try:
            # 触发一次真实读，尽早暴露「密钥错误 / 驱动不匹配 / 文件损坏」
            conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
        except _DB_ERRORS as exc:
            raise DatabaseError(self._open_error_hint(exc)) from exc

        conn.executescript(SCHEMA)
        conn.commit()
        row = self.query_one("SELECT value FROM meta WHERE key = 'db_version'")
        if row is None:
            self.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?)", ("db_version", str(DB_VERSION))
            )
        else:
            self._migrate(int(row["value"] or 1))
        # 列已补齐，此时创建索引才不会撞上老库缺列的 schema
        conn.executescript(INDEXES)
        conn.commit()
        self.set_registered_driver()

    def _open_error_hint(self, exc: Exception) -> str:
        mode = "SQLCipher 加密" if self._encrypted else "明文 SQLite"
        return (
            f"无法以「{mode}」方式打开数据库 {self.path.name}：{exc}\n"
            "数据库文件可能不是该加密模式的库，或已被损坏。\n"
            "请检查 *.meta.json 中的 driver 字段是否与实际库文件一致；"
            "不要删除文件，可先备份后联系维护者协助恢复。"
        )

    def _migrate(self, from_version: int) -> None:
        """按版本依次升级表结构。"""
        current = from_version
        if current < 2:
            self._add_column_if_missing("attachments", "part_index", "TEXT")
            current = 2
            log.info("数据库已从 v%d 迁移到 v2（新增 attachments.part_index）", from_version)
        if current < 3:
            # 记录每封邮件所属的 UIDVALIDITY：服务器端邮箱重建后 UID 会复用，
            # 只有带上该维度才能识别「本地副本已全部失效」并正确清理。
            self._add_column_if_missing("mails", "uid_validity", "INTEGER NOT NULL DEFAULT 0")
            self.execute(
                "UPDATE mails SET uid_validity = COALESCE(("
                "    SELECT s.uid_validity FROM sync_cursors s"
                "    WHERE s.account_id = mails.account_id AND s.folder = mails.folder"
                "), 0) WHERE uid_validity IS NULL OR uid_validity = 0"
            )
            current = 3
            log.info("数据库已从 v%d 迁移到 v3（新增 mails.uid_validity）", from_version)
        if current < 4:
            # 索引定义变更（v4：idx_mails_read 由单列改为 (is_read, date DESC)）。
            # `CREATE INDEX IF NOT EXISTS` 遇到同名旧索引会直接跳过，因此必须
            # 先显式删除；重建交给 `_init_connection` 里统一执行 INDEXES。
            for name in REBUILT_INDEXES:
                self.execute(f"DROP INDEX IF EXISTS {name}")
            current = 4
            log.info("数据库已从 v%d 迁移到 v4（重建列表筛选相关索引）", from_version)
        if current != from_version:
            self.set_meta("db_version", str(current))

    def _add_column_if_missing(self, table: str, column: str, coltype: str) -> None:
        cols = {r["name"] for r in self.query_all(f"PRAGMA table_info({table})")}
        if column not in cols:
            self.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")

    def registered_driver(self) -> str | None:
        """库内记录的驱动（供 sidecar 缺失时交叉校验）。"""
        try:
            return self.get_meta("driver")
        except DatabaseError:
            return None

    def set_registered_driver(self) -> None:
        self.set_meta("driver", self.driver_name)

    def close(self) -> None:
        """关闭**所有线程**的数据库连接（退出前调用）。

        历史实现只关掉当前线程的连接，后台同步线程的连接会一直挂着，
        长会话下句柄与内存持续累积。
        """
        with self._conns_lock:
            conns = self._conns
            self._conns = []
        for conn in conns:
            # 关闭路径尽力而为：连接可能已因底层错误失效，
            # 任何一步失败都不应阻止其余连接被回收。
            with contextlib.suppress(Exception):
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            with contextlib.suppress(Exception):
                conn.close()
        self._local.conn = None
        self._closed = True

    def open_count(self) -> int:
        """当前登记的连接数（用于诊断与测试）。"""
        with self._conns_lock:
            return len(self._conns)

    # ------------------------------------------------------------ 查询
    def _tx_depth(self) -> int:
        return int(getattr(self._local, "tx_depth", 0))

    def execute(self, sql: str, params: Iterable[Any] = ()) -> Any:
        with self._write_lock:
            conn = self._conn()
            cur = conn.execute(sql, tuple(params))
            # 处于显式事务中时不要擅自提交，否则会破坏事务边界
            if self._tx_depth() == 0:
                conn.commit()
            return cur

    def executemany(self, sql: str, seq: Iterable[Iterable[Any]]) -> None:
        with self._write_lock:
            conn = self._conn()
            conn.executemany(sql, [tuple(p) for p in seq])
            if self._tx_depth() == 0:
                conn.commit()

    def query_all(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        conn = self._conn()
        cur = conn.execute(sql, tuple(params))
        return [dict(r) for r in cur.fetchall()]

    def query_one(self, sql: str, params: Iterable[Any] = ()) -> dict | None:
        conn = self._conn()
        cur = conn.execute(sql, tuple(params))
        row = cur.fetchone()
        return dict(row) if row else None

    def scalar(self, sql: str, params: Iterable[Any] = ()) -> Any:
        row = self.query_one(sql, params)
        if row is None:
            return None
        return next(iter(row.values()), None)

    # ------------------------------------------------------------ 事务
    def transaction(self):
        """上下文管理器：批量写入时使用。

        会持有写锁直到事务结束，避免与其它线程的 autocommit 写入交错，
        也避免同线程内的 `execute()` 提前 commit 破坏事务边界。
        """
        outer = self

        class _Tx:
            def __enter__(self_inner):
                self_inner._lock = outer._write_lock
                self_inner._lock.acquire()
                depth = outer._tx_depth()
                outer._local.tx_depth = depth + 1
                try:
                    self_inner.conn = outer._conn()
                    if depth == 0:
                        self_inner.conn.execute("BEGIN")
                except Exception:
                    outer._local.tx_depth = depth
                    self_inner._lock.release()
                    raise
                return self_inner.conn

            def __exit__(self_inner, exc_type, exc, tb):
                depth = outer._tx_depth()
                try:
                    if depth <= 1:
                        if exc_type is None:
                            self_inner.conn.commit()
                        else:
                            self_inner.conn.rollback()
                finally:
                    outer._local.tx_depth = max(depth - 1, 0)
                    self_inner._lock.release()
                return False

        return _Tx()

    # ------------------------------------------------------------ 元信息
    def get_meta(self, key: str) -> str | None:
        return self.scalar("SELECT value FROM meta WHERE key = ?", (key,))

    def set_meta(self, key: str, value: str) -> None:
        self.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def rekey(self, new_key: bytes) -> None:
        """更换整库加密密钥（仅加密库支持）。"""
        if not self._encrypted:
            raise DatabaseError("当前数据库未整库加密，不支持 rekey")
        conn = self._conn()
        conn.execute(f"PRAGMA rekey = \"x'{new_key.hex()}'\"")
        conn.commit()
        self._db_key = new_key

    # ------------------------------------------------------------ 加密迁移
    def migrate_to_encrypted(self, new_key: bytes) -> None:
        """明文库 → SQLCipher 加密库（官方 sqlcipher_export 配方 + 原子替换）。

        迁移前会保留 `*.plaintext.bak`；迁移后的文件会先校验（能否用新密钥打开、
        行数是否一致）再替换，任一步失败都保持原库不变、并清掉半成品临时文件。

        已知残留风险：最终是两次 `os.replace`（先备份原库、再把新库改名就位），
        两者之间掉电会留下「原库已改名为 .bak、主文件缺失」的状态。这不是可以
        用一次 rename 消除的问题（跨文件系统无法原子重命名两个文件），
        但此时数据完整地躺在 `.plaintext.bak` 里，日志与错误提示都会给出该路径。
        """
        if not _SQLCIPHER_AVAILABLE:
            raise DatabaseError("未安装 sqlcipher3，无法启用整库加密")
        if self._encrypted:
            return
        src = self.path
        if not src.exists():
            raise DatabaseError("数据库文件不存在，无法迁移")

        expect = self.scalar("SELECT COUNT(*) FROM mails") or 0
        self.close()
        self._remove_sidecar_files(src)

        tmp = src.with_name(src.name + ".enc-tmp")
        if tmp.exists():
            tmp.unlink()

        conn = sqlcipher_db.connect(str(src))
        try:
            conn.execute("PRAGMA key = ''")   # 以明文方式打开源库
            conn.execute(
                f"ATTACH DATABASE ? AS encrypted KEY \"x'{new_key.hex()}'\"", (str(tmp),)
            )
            conn.execute("SELECT sqlcipher_export('encrypted')")
            conn.execute("DETACH DATABASE encrypted")
            conn.commit()
        except Exception as exc:
            if tmp.exists():
                tmp.unlink()
            self._reopen()
            raise DatabaseError(f"整库加密失败，数据库保持原状：{exc}") from exc
        finally:
            conn.close()

        # 校验不通过时：清掉半成品、把连接恢复回原库。
        # 不这样做的话，迁移失败会把 Database 对象永远留在「已关闭」状态，
        # 用户看到的是「迁移失败」之后连原库也用不了，只能重启程序。
        try:
            self._verify_migrated_file(tmp, new_key, expect, encrypted=True)
        except BaseException:
            tmp.unlink(missing_ok=True)
            self._reopen()
            raise

        backup = src.with_name(src.name + ".plaintext.bak")
        if backup.exists():
            backup.unlink()
        os.replace(src, backup)
        os.replace(tmp, src)

        self._db_key = new_key
        self._encrypted = True
        self.encrypted = True
        self._reopen()
        log.info("数据库已迁移为整库加密（原明文库备份为 %s）", backup.name)

    def migrate_to_plaintext(self) -> None:
        """SQLCipher 加密库 → 明文库（官方配方 + 原子替换）。

        迁移前保留 `*.encrypted.bak`。明文落盘会失去整库加密保护，
        仅供排障或用户明确要求时使用。
        """
        if not _SQLCIPHER_AVAILABLE:
            raise DatabaseError("未安装 sqlcipher3，无法解析加密库")
        if not self._encrypted:
            return
        src = self.path
        if not src.exists():
            raise DatabaseError("数据库文件不存在，无法迁移")

        old_key = self._key_hex
        expect = self.scalar("SELECT COUNT(*) FROM mails") or 0
        self.close()
        self._remove_sidecar_files(src)

        tmp = src.with_name(src.name + ".plain-tmp")
        if tmp.exists():
            tmp.unlink()

        conn = sqlcipher_db.connect(str(src))
        try:
            conn.execute(f"PRAGMA key = \"x'{old_key}'\"")
            conn.execute("ATTACH DATABASE ? AS plaintext KEY ''", (str(tmp),))
            conn.execute("SELECT sqlcipher_export('plaintext')")
            conn.execute("DETACH DATABASE plaintext")
            conn.commit()
        except Exception as exc:
            if tmp.exists():
                tmp.unlink()
            self._reopen()
            raise DatabaseError(f"解除整库加密失败，数据库保持原状：{exc}") from exc
        finally:
            conn.close()

        try:
            self._verify_migrated_file(tmp, None, expect, encrypted=False)
        except BaseException:
            # 同 migrate_to_encrypted：失败要清临时文件并把连接恢复回原库
            tmp.unlink(missing_ok=True)
            self._reopen()
            raise

        backup = src.with_name(src.name + ".encrypted.bak")
        if backup.exists():
            backup.unlink()
        os.replace(src, backup)
        os.replace(tmp, src)

        self._encrypted = False
        self.encrypted = False
        self._reopen()
        log.info("数据库已解除整库加密（原加密库备份为 %s）", backup.name)

    @staticmethod
    def _remove_sidecar_files(src: Path) -> None:
        for suffix in ("-wal", "-shm", "-journal"):
            p = Path(str(src) + suffix)
            if p.exists():
                try:
                    p.unlink()
                except OSError:
                    log.warning("无法删除 %s", p)

    def _verify_migrated_file(self, path: Path, key: bytes | None,
                              expect_rows: int, encrypted: bool) -> None:
        """替换前校验迁移结果：可打开、可读、行数一致。"""
        if encrypted:
            if key is None:
                raise DatabaseError("内部错误：校验加密库时缺少密钥")
            conn = sqlcipher_db.connect(str(path))
            conn.execute(f"PRAGMA key = \"x'{key.hex()}'\"")
        else:
            conn = sqlite3.connect(str(path))
        try:
            rows = conn.execute("SELECT COUNT(*) FROM mails").fetchone()[0]
        except Exception as exc:
            conn.close()
            path.unlink(missing_ok=True)
            raise DatabaseError(f"迁移结果校验失败（无法读取新库）：{exc}") from exc
        conn.close()
        if int(rows) != int(expect_rows):
            path.unlink(missing_ok=True)
            raise DatabaseError(
                f"迁移结果校验失败：邮件行数不一致（原 {expect_rows}，新 {rows}），已放弃迁移"
            )

    def _reopen(self) -> None:
        """迁移后重建连接（原连接已随 close() 一起释放）。"""
        self._closed = False
        self._local.conn = None
        self._init_connection()

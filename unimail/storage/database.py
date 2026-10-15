"""加密数据库：优先 SQLCipher，缺失时降级为 SQLite + 字段级加密。

降级说明：
    若环境中没有 sqlcipher3，则使用标准 sqlite3 建库，此时**整库不加密**，
    但账号密码仍在 credentials 表中以 Fernet 密文存储（字段级加密）。
    程序启动时会明确提示当前加密等级，避免用户误以为已全库加密。
"""
from __future__ import annotations

import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

from ..config import DB_VERSION

log = logging.getLogger(__name__)

# ---------------------------------------------------------------- 驱动探测
_SQLCIPHER_AVAILABLE = False
try:  # pragma: no cover - 依赖环境
    from sqlcipher3 import dbapi2 as sqlcipher_db  # type: ignore
    _SQLCIPHER_AVAILABLE = True
except ImportError:
    sqlcipher_db = None  # type: ignore


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
    FOREIGN KEY(mail_id) REFERENCES mails(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mails_date     ON mails(date DESC);
CREATE INDEX IF NOT EXISTS idx_mails_account  ON mails(account_id, date DESC);
CREATE INDEX IF NOT EXISTS idx_mails_platform ON mails(platform, date DESC);
CREATE INDEX IF NOT EXISTS idx_mails_read     ON mails(is_read);
CREATE INDEX IF NOT EXISTS idx_mails_folder   ON mails(account_id, folder, uid);
CREATE INDEX IF NOT EXISTS idx_attach_mail    ON attachments(mail_id);
"""


class Database:
    """线程安全的加密数据库封装。

    每次操作从线程本地连接取连接，避免跨线程共享 sqlite 连接。
    """

    def __init__(self, path: Path, db_key: bytes | None = None) -> None:
        self.path = Path(path)
        self._db_key = db_key
        self._local = threading.local()
        self._write_lock = threading.RLock()
        self.encrypted = _SQLCIPHER_AVAILABLE and db_key is not None
        self._init_connection()

    # ------------------------------------------------------------ 连接
    @property
    def encryption_level(self) -> str:
        if self.encrypted:
            return "整库加密 (SQLCipher AES-256)"
        if _SQLCIPHER_AVAILABLE:
            return "未提供密钥"
        return "字段级加密（未安装 SQLCipher，整库为明文）"

    def _new_connection(self):
        if _SQLCIPHER_AVAILABLE:
            conn = sqlcipher_db.connect(str(self.path), check_same_thread=False)
            if self._db_key is not None:
                key_hex = self._db_key.hex()
                conn.execute(f"PRAGMA key = \"x'{key_hex}'\"")
                conn.execute("PRAGMA cipher_memory_security = ON")
        else:
            conn = sqlite3.connect(str(self.path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def _conn(self):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._new_connection()
            self._local.conn = conn
        return conn

    def _init_connection(self) -> None:
        conn = self._conn()
        conn.executescript(SCHEMA)
        conn.commit()
        row = self.query_one("SELECT value FROM meta WHERE key = 'db_version'")
        if row is None:
            self.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?)", ("db_version", str(DB_VERSION))
            )
        self.set_registered_driver()

    def set_registered_driver(self) -> None:
        self.execute(
            "INSERT INTO meta(key, value) VALUES('driver', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            ("sqlcipher" if _SQLCIPHER_AVAILABLE else "sqlite3",),
        )

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
            self._local.conn = None

    # ------------------------------------------------------------ 查询
    def execute(self, sql: str, params: Iterable[Any] = ()) -> Any:
        with self._write_lock:
            conn = self._conn()
            cur = conn.execute(sql, tuple(params))
            conn.commit()
            return cur

    def executemany(self, sql: str, seq: Iterable[Iterable[Any]]) -> None:
        with self._write_lock:
            conn = self._conn()
            conn.executemany(sql, [tuple(p) for p in seq])
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
        """上下文管理器：批量写入时使用（注意：非跨线程事务）。"""
        outer = self

        class _Tx:
            def __enter__(self_inner):
                self_inner.conn = outer._conn()
                self_inner.conn.execute("BEGIN")
                return self_inner.conn

            def __exit__(self_inner, exc_type, exc, tb):
                if exc_type is None:
                    self_inner.conn.commit()
                else:
                    self_inner.conn.rollback()
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
        """更换整库加密密钥（仅 SQLCipher 支持）。"""
        if not _SQLCIPHER_AVAILABLE:
            self._db_key = new_key
            return
        conn = self._conn()
        conn.execute(f"PRAGMA rekey = \"x'{new_key.hex()}'\"")
        conn.commit()
        self._db_key = new_key
        self.encrypted = True

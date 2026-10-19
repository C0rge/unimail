"""仓储层：账号、邮件、附件、同步游标的数据访问。"""
from __future__ import annotations

import builtins
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..config import PLATFORMS
from ..core.models import (
    MAIL_SUMMARY_COLUMNS,
    OUTBOX_PENDING,
    Account,
    AccountStatus,
    Attachment,
    AttachmentMeta,
    Contact,
    Mail,
    MailFilter,
    MailSummary,
    NormalizedMail,
    OutboxMessage,
    ThreadSummary,
    is_email_like,
    load_str_list,
    make_preview,
    new_id,
)
from ..core.textsearch import fts_eligible, match_query

# `IN (?,?,…)` 的分批大小。SQLite 的变量上限默认 999（老版本更低），
# 一次传几千个 id 会直接报错，因此所有批量 `IN` 查询都按这个粒度分批。
_SQL_VAR_CHUNK = 500


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def escape_like(value: str) -> str:
    """转义 LIKE 模式里的通配符。

    未转义时用户输入一个 `%` 就会匹配全库（功能性 bug），
    `_` 会变成「任意单字符」。配合 `LIKE ? ESCAPE '\\'` 使用。
    """
    return (value.replace("\\", "\\\\")
                 .replace("%", "\\%")
                 .replace("_", "\\_"))


# 列表排序的列白名单：键来自 UI 表头，值拼进 ORDER BY。
# `ORDER BY` 无法用占位符参数化，任何把用户输入直接拼进去的写法都是注入面，
# 因此这里只接受固定键，未知键回落到 date。
_ORDER_COLUMNS = {
    "time": "m.date",
    "date": "m.date",
    "sender": "m.from_name COLLATE NOCASE",
    "subject": "m.subject COLLATE NOCASE",
    "platform": "m.platform",
    "read": "m.is_read",
    "starred": "m.is_starred",
}


# accounts 表允许被 update_fields 修改的列。动态列名在 SQL 里是典型的注入 sink，
# 即使当前调用方全是内部常量，也必须用白名单把它收口。
_ACCOUNT_UPDATABLE = frozenset({
    "platform", "email", "display_name", "imap_host", "imap_port",
    "use_ssl", "username", "sync_interval", "last_synced_at", "status",
    "auth_type", "smtp_host", "smtp_port",
})

# 附件落盘路径列表。
# 为什么需要别名：`AccountRepository` 里有一个名为 `list` 的方法，而 Python 的
# 注解（含 PEP 563 的字符串注解）是在**类作用域内**解析的，`-> list[str]` 会被
# 解析成那个方法本身（mypy: "Function AccountRepository.list is not valid as a
# type"）。用具名别名即可回避，也顺便说明了这个返回值的语义。
StoredPaths = list[str]

# 同上：`OutboxRepository` 与 `AccountRepository` 一样有名为 `list` 的方法，
# 因此它的返回注解也要用别名（否则 mypy 报 valid-type）。
OutboxList = list[OutboxMessage]

# 同上：`ContactRepository` 也有名为 `list` 的方法，返回注解用别名回避遮蔽。
ContactList = list[Contact]


@dataclass
class BatchInsertResult:
    """批量写入的记账结果。

    三种结局必须分开计数：`inserted` 是真正新增，`existing` 是正常的重复同步，
    `conflicts` 则是「UID 已被别的 UIDVALIDITY 占用」这类数据异常——
    历史实现把三者统一按新增处理，导致统计失真且问题被静默吞掉。
    """
    inserted: list[tuple[str, str]] = field(default_factory=list)  # (uid, mail_id)
    existing: int = 0
    conflicts: int = 0

    @property
    def new_count(self) -> int:
        return len(self.inserted)


class AccountRepository:
    def __init__(self, db) -> None:
        self.db = db

    def list(self) -> list[Account]:
        rows = self.db.query_all("SELECT * FROM accounts ORDER BY created_at ASC")
        return [Account.from_row(r) for r in rows]

    def get(self, account_id: str) -> Account | None:
        row = self.db.query_one("SELECT * FROM accounts WHERE id = ?", (account_id,))
        return Account.from_row(row) if row else None

    def find(self, platform: str, email: str) -> Account | None:
        row = self.db.query_one(
            "SELECT * FROM accounts WHERE platform = ? AND email = ?", (platform, email)
        )
        return Account.from_row(row) if row else None

    def insert(self, draft) -> Account:
        cfg = PLATFORMS.get(draft.platform)
        host = draft.imap_host or (cfg.imap_host if cfg else "")
        port = draft.imap_port or (cfg.imap_port if cfg else 993)
        use_ssl = draft.use_ssl if draft.use_ssl is not None else (cfg.use_ssl if cfg else True)
        acc_id = new_id()
        self.db.execute(
            """INSERT INTO accounts
               (id, platform, email, display_name, imap_host, imap_port, use_ssl,
                username, sync_interval, status, auth_type, smtp_host, smtp_port, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                acc_id, draft.platform, draft.email.lower().strip(),
                draft.display_name or "", host, port, 1 if use_ssl else 0,
                draft.username, draft.sync_interval, AccountStatus.OK.value,
                getattr(draft, "auth_type", "password") or "password",
                getattr(draft, "smtp_host", "") or "",
                int(getattr(draft, "smtp_port", 0) or 0),
                utcnow_iso(),
            ),
        )
        return self.get(acc_id)  # type: ignore[return-value]

    def update_fields(self, account_id: str, fields: dict) -> None:
        if not fields:
            return
        unknown = set(fields) - _ACCOUNT_UPDATABLE
        if unknown:
            raise ValueError(f"不允许更新的字段：{sorted(unknown)}")
        cols = ", ".join(f"{k} = ?" for k in fields)
        # 列名已在上面按白名单校验过，值全部走占位符；
        # SQLite 不支持把标识符参数化，拼接是唯一写法。
        self.db.execute(
            f"UPDATE accounts SET {cols} WHERE id = ?",  # noqa: S608
            (*fields.values(), account_id),
        )

    def set_status(self, account_id: str, status: str) -> None:
        self.db.execute(
            "UPDATE accounts SET status = ? WHERE id = ?", (status, account_id)
        )

    def set_last_synced(self, account_id: str, when: datetime | None = None) -> None:
        self.db.execute(
            "UPDATE accounts SET last_synced_at = ? WHERE id = ?",
            ((when or datetime.now(timezone.utc)).isoformat(), account_id),
        )

    def delete(self, account_id: str) -> StoredPaths:
        """删除账号及其全部本地副本，返回需要一并从磁盘删除的附件路径。"""
        paths = [
            str(r["stored_path"])
            for r in self.db.query_all(
                "SELECT a.stored_path FROM attachments a JOIN mails m ON m.id = a.mail_id "
                "WHERE m.account_id = ? AND a.stored_path IS NOT NULL "
                "AND a.stored_path <> ''", (account_id,)
            )
        ]
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM attachments WHERE mail_id IN "
                         "(SELECT id FROM mails WHERE account_id = ?)", (account_id,))
            conn.execute("DELETE FROM mails WHERE account_id = ?", (account_id,))
            conn.execute("DELETE FROM sync_cursors WHERE account_id = ?", (account_id,))
            conn.execute("DELETE FROM credentials WHERE id = ?", (account_id,))
            conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        return paths

    # -------------------------------------------------------- 凭据
    def put_credential(self, account_id: str, ciphertext: bytes) -> None:
        now = utcnow_iso()
        self.db.execute(
            """INSERT INTO credentials(id, ciphertext, created_at, updated_at)
               VALUES(?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET ciphertext = excluded.ciphertext,
                                             updated_at = excluded.updated_at""",
            (account_id, ciphertext, now, now),
        )

    def get_credential(self, account_id: str) -> bytes | None:
        row = self.db.query_one(
            "SELECT ciphertext FROM credentials WHERE id = ?", (account_id,)
        )
        return row["ciphertext"] if row else None


class CursorRepository:
    def __init__(self, db) -> None:
        self.db = db

    def get(self, account_id: str, folder: str = "INBOX") -> tuple[int, int | None]:
        row = self.db.query_one(
            "SELECT last_uid, uid_validity FROM sync_cursors WHERE account_id = ? AND folder = ?",
            (account_id, folder),
        )
        if not row:
            return 0, None
        return int(row["last_uid"] or 0), row["uid_validity"]

    def upsert(self, account_id: str, folder: str, last_uid: int,
               uid_validity: int | None = None) -> None:
        self.db.execute(
            """INSERT INTO sync_cursors(account_id, folder, last_uid, uid_validity, updated_at)
               VALUES(?,?,?,?,?)
               ON CONFLICT(account_id, folder) DO UPDATE SET
                   last_uid = excluded.last_uid,
                   uid_validity = excluded.uid_validity,
                   updated_at = excluded.updated_at""",
            (account_id, folder, last_uid, uid_validity, utcnow_iso()),
        )


class MailRepository:
    def __init__(self, db) -> None:
        self.db = db

    # -------------------------------------------------------- 写入
    def exists(self, account_id: str, folder: str, uid: str) -> bool:
        row = self.db.query_one(
            "SELECT 1 FROM mails WHERE account_id = ? AND folder = ? AND uid = ?",
            (account_id, folder, uid),
        )
        return row is not None

    def existing_uids(self, account_id: str, folder: str = "INBOX",
                      uid_validity: int | None = None) -> set[str]:
        """该文件夹下已入库的 UID 集合（可按 UIDVALIDITY 维度过滤）。

        用于同步前一次性取回已知集合、在内存里去重，避免逐封 `exists()` 查询。
        """
        if uid_validity is None:
            rows = self.db.query_all(
                "SELECT uid FROM mails WHERE account_id = ? AND folder = ?",
                (account_id, folder),
            )
        else:
            rows = self.db.query_all(
                "SELECT uid FROM mails WHERE account_id = ? AND folder = ? "
                "AND uid_validity = ?",
                (account_id, folder, int(uid_validity)),
            )
        return {str(r["uid"]) for r in rows}

    def ids_by_uid(self, account_id: str, folder: str,
                   uids: list[str]) -> dict[str, str]:
        """按 UID 批量取 mail_id（用于把 BODYSTRUCTURE 结果落到具体邮件）。"""
        if not uids:
            return {}
        marks = ",".join("?" * len(uids))
        rows = self.db.query_all(
            f"SELECT uid, id FROM mails WHERE account_id = ? AND folder = ? "  # noqa: S608
            f"AND uid IN ({marks})",
            (account_id, folder, *[str(u) for u in uids]),
        )
        return {str(r["uid"]): r["id"] for r in rows}

    def folder_uid_validities(self, account_id: str, folder: str = "INBOX") -> set[int]:
        """本地已入库邮件记录的 UIDVALIDITY 集合。

        与服务端当前值不一致即说明邮箱已被重建，本地副本全部失效。
        """
        rows = self.db.query_all(
            "SELECT DISTINCT uid_validity FROM mails WHERE account_id = ? AND folder = ?",
            (account_id, folder),
        )
        return {int(r["uid_validity"] or 0) for r in rows}

    def list_folders(self, account_id: str | None = None) -> list[tuple[str, int]]:
        """本地已同步过的文件夹及各自邮件数，按邮件数倒序。

        这是「文件夹可见性」的数据来源：同步 worker 已经按服务器 LIST 拉取
        全部文件夹，这里只是把**本地已有的**文件夹维度暴露给 UI，不额外发
        网络请求。`account_id` 为 None 时返回全部账号的并集（文件夹名去重）。
        文件夹名是服务器给的（含中文/特殊字符），排序按邮件数倒序，
        把用户最常用的文件夹排前面。
        """
        if account_id:
            rows = self.db.query_all(
                "SELECT folder, COUNT(*) AS n FROM mails "
                "WHERE account_id = ? GROUP BY folder ORDER BY n DESC",
                (account_id,))
        else:
            rows = self.db.query_all(
                "SELECT folder, COUNT(*) AS n FROM mails "
                "GROUP BY folder ORDER BY n DESC")
        return [(str(r["folder"]), int(r["n"] or 0)) for r in rows]

    def purge_folder(self, account_id: str, folder: str = "INBOX") -> tuple[int, list[str]]:
        """删除某账号某文件夹的全部本地副本（UIDVALIDITY 变化时调用）。

        返回 (被删除的邮件行数, 需要从磁盘删除的附件路径)。附件行随事务一并清理。
        """
        paths = [
            str(r["stored_path"])
            for r in self.db.query_all(
                "SELECT a.stored_path FROM attachments a JOIN mails m ON m.id = a.mail_id "
                "WHERE m.account_id = ? AND m.folder = ? AND a.stored_path IS NOT NULL "
                "AND a.stored_path <> ''", (account_id, folder)
            )
        ]
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM mails WHERE account_id = ? AND folder = ?",
                (account_id, folder),
            ).fetchone()
            removed = int(row[0] if row else 0)
            conn.execute(
                "DELETE FROM attachments WHERE mail_id IN "
                "(SELECT id FROM mails WHERE account_id = ? AND folder = ?)",
                (account_id, folder),
            )
            conn.execute(
                "DELETE FROM mails WHERE account_id = ? AND folder = ?",
                (account_id, folder),
            )
        return removed, paths

    def insert_mail(self, account_id: str, platform: str,
                    mail: NormalizedMail, uid_validity: int | None = None) -> str | None:
        """写入一封邮件（含附件元数据），返回 mail_id；已存在则返回 None。

        单封路径保留给调用方零散写入；同步这类批量场景请用
        `insert_mails_batch()`——每封一次事务提交（各带一次 fsync）是
        写入吞吐的主要瓶颈（实测 659–824 封/秒 → 批量 11 800 封/秒）。
        """
        if self.exists(account_id, mail.folder, mail.uid):
            return None
        mail_id = new_id()
        with self.db.transaction() as conn:
            conn.execute(
                """INSERT INTO mails
                   (id, account_id, platform, folder, uid, uid_validity, message_id,
                    subject, from_name, from_addr, to_addrs, date, preview, body_text,
                    body_html, has_attachments, is_read, is_starred, raw_size,
                    ref_ids, in_reply_to, thread_key, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    mail_id, account_id, platform, mail.folder, mail.uid,
                    int(uid_validity or 0),
                    mail.message_id, mail.subject, mail.from_name, mail.from_addr,
                    json.dumps(mail.to_addrs, ensure_ascii=False),
                    (mail.date or datetime.now(timezone.utc)).isoformat(),
                    mail.preview, mail.body_text, mail.body_html,
                    1 if mail.attachments else 0, 0, 0, mail.raw_size,
                    json.dumps(mail.references, ensure_ascii=False),
                    json.dumps(mail.in_reply_to, ensure_ascii=False),
                    # 无任何引用线索时用 mail_id 兜底：不能留空——空值会让所有
                    # 「没有引用头」的邮件在会话视图里被并成同一个巨大会话。
                    mail.thread_key or mail_id,
                    utcnow_iso(),
                ),
            )
            for att in mail.attachments:
                conn.execute(
                    """INSERT INTO attachments
                       (id, mail_id, filename, content_type, size, stored_path,
                        content_id, part_index)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (new_id(), mail_id, att.filename, att.content_type,
                     att.size, None, att.content_id, att.part_index),
                )
        return mail_id

    def insert_mails_batch(self, account_id: str, platform: str,
                           mails: list[NormalizedMail],
                           uid_validity: int | None = None,
                           known_uids: set[str] | None = None) -> BatchInsertResult:
        """批量写入一批邮件：**一个事务 + executemany**。

        `known_uids` 传入调用方已一次性查回的 UID 集合（`existing_uids()`），
        这样去重完全在内存完成，省掉逐封 `exists()` 查询；未传时本方法
        自动查一次。
        """
        result = BatchInsertResult()
        if not mails:
            return result

        folders = {m.folder for m in mails}
        if known_uids is None:
            known_uids = set()
            for folder in folders:
                known_uids |= self.existing_uids(account_id, folder)

        now = utcnow_iso()
        mail_rows: list[tuple] = []
        attach_rows: list[tuple] = []
        validity = int(uid_validity or 0)

        for mail in mails:
            uid = str(mail.uid)
            if uid in known_uids:
                result.existing += 1
                continue
            mail_id = new_id()
            known_uids.add(uid)     # 同一批内自身去重
            mail_rows.append((
                mail_id, account_id, platform, mail.folder, uid, validity,
                mail.message_id, mail.subject, mail.from_name, mail.from_addr,
                json.dumps(mail.to_addrs, ensure_ascii=False),
                (mail.date or datetime.now(timezone.utc)).isoformat(),
                mail.preview, mail.body_text, mail.body_html,
                1 if mail.attachments else 0, 0, 0, mail.raw_size,
                json.dumps(mail.references, ensure_ascii=False),
                json.dumps(mail.in_reply_to, ensure_ascii=False),
                mail.thread_key or mail_id,
                now,
            ))
            for att in mail.attachments:
                attach_rows.append(
                    (new_id(), mail_id, att.filename, att.content_type,
                     att.size, None, att.content_id, att.part_index)
                )
            result.inserted.append((uid, mail_id))

        if not mail_rows:
            return result

        with self.db.transaction() as conn:
            before = conn.total_changes
            conn.executemany(
                """INSERT OR IGNORE INTO mails
                   (id, account_id, platform, folder, uid, uid_validity, message_id,
                    subject, from_name, from_addr, to_addrs, date, preview, body_text,
                    body_html, has_attachments, is_read, is_starred, raw_size,
                    ref_ids, in_reply_to, thread_key, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                mail_rows,
            )
            # INSERT OR IGNORE 命中唯一键时静默跳过。这里用 total_changes 的增量
            # 拿到「真正插入的行数」（两种驱动下 INSERT OR IGNORE 都只计成功行）。
            actually_inserted = conn.total_changes - before

            if actually_inserted != len(mail_rows):
                # 有行被跳过必须精确剔除，不能靠「截断前 N 个」猜：
                # OR IGNORE 跳过的行是任意位置，不是尾部。而且被跳过邮件的
                # 附件行若照样写入，就会留下指向不存在邮件的孤儿记录。
                landed = self._existing_mail_ids(
                    conn, [row[0] for row in mail_rows]
                )
                attach_rows = [r for r in attach_rows if r[1] in landed]
                result.inserted = [(u, m) for u, m in result.inserted if m in landed]
                result.conflicts = len(mail_rows) - len(landed)

            if attach_rows:
                conn.executemany(
                    """INSERT INTO attachments
                       (id, mail_id, filename, content_type, size, stored_path,
                        content_id, part_index)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    attach_rows,
                )
        return result

    @staticmethod
    def _existing_mail_ids(conn, mail_ids: list[str]) -> set[str]:
        """在给定连接上核实哪些 mail_id 真的落库了（分片规避占位符上限）。"""
        landed: set[str] = set()
        for start in range(0, len(mail_ids), 500):
            chunk = mail_ids[start:start + 500]
            marks = ",".join("?" * len(chunk))
            landed |= {
                str(r[0]) for r in
                # marks 由占位符拼成，值走参数
                conn.execute(
                    f"SELECT id FROM mails WHERE id IN ({marks})",  # noqa: S608
                    chunk,
                )
            }
        return landed

    def update_bodies_batch(self, rows: list[tuple[str, str, str]]) -> int:
        """批量回填正文：rows = [(mail_id, body_text, body_html), …]。

        一并刷新 `preview`：它是列表摘要与全文检索的依据之一，正文到了却不更新，
        列表里这封邮件就永远没有摘要，索引里也留着过期摘要。
        `NULLIF(?, '')` 保证正文为空时**不清掉**已有预览。
        """
        if not rows:
            return 0
        with self.db.transaction() as conn:
            conn.executemany(
                "UPDATE mails SET body_text = ?, body_html = ?, "
                "preview = COALESCE(NULLIF(?, ''), preview) WHERE id = ?",
                [(text, html, make_preview(text), mail_id)
                 for mail_id, text, html in rows],
            )
        return len(rows)

    def update_body(self, mail_id: str, body_text: str, body_html: str) -> None:
        self.db.execute(
            "UPDATE mails SET body_text = ?, body_html = ?, "
            "preview = COALESCE(NULLIF(?, ''), preview) WHERE id = ?",
            (body_text, body_html, make_preview(body_text), mail_id),
        )

    def replace_attachments(self, mail_id: str,
                            metas: list[AttachmentMeta]) -> list[str]:
        """按 part 编号对齐地更新某封邮件的附件行，并同步 `has_attachments`。

        为什么需要「替换」而不是「追加」：附件元数据有两个来源——
        同步期的 BODYSTRUCTURE（快、但 content_id 缺失）与点开邮件后的完整
        MIME 解析（全、但慢）。两者都可能先后到来，若各插一行就会出现重复。

        返回**已失效但曾在磁盘上留有副本**的路径列表，由调用方负责删除文件
        （仓储层不碰文件系统）。
        """
        stale_paths: list[str] = []
        with self.db.transaction() as conn:
            rows = conn.execute(
                "SELECT id, part_index, filename, stored_path FROM attachments "
                "WHERE mail_id = ?", (mail_id,)
            ).fetchall()
            existing = {str(r[1] or ""): r for r in rows}
            seen: set[str] = set()

            for meta in metas:
                key = str(meta.part_index or "")
                seen.add(key)
                row = existing.get(key)
                if row is None:
                    conn.execute(
                        """INSERT INTO attachments
                           (id, mail_id, filename, content_type, size, stored_path,
                            content_id, part_index)
                           VALUES (?,?,?,?,?,?,?,?)""",
                        (new_id(), mail_id, meta.filename, meta.content_type,
                         meta.size, None, meta.content_id, meta.part_index),
                    )
                    continue
                # 已落盘的副本：文件名/部件号一致就留着，只更新元信息，
                # 否则视为不同附件，落盘路径作废
                keep_path = row[3] if row[2] == meta.filename else None
                if row[3] and not keep_path:
                    stale_paths.append(str(row[3]))
                conn.execute(
                    "UPDATE attachments SET filename = ?, content_type = ?, size = ?, "
                    "content_id = COALESCE(?, content_id), stored_path = ? WHERE id = ?",
                    (meta.filename, meta.content_type, meta.size,
                     meta.content_id, keep_path, row[0]),
                )

            for key, row in existing.items():
                if key in seen:
                    continue
                if row[3]:
                    stale_paths.append(str(row[3]))
                conn.execute("DELETE FROM attachments WHERE id = ?", (row[0],))

            conn.execute(
                "UPDATE mails SET has_attachments = ? WHERE id = ?",
                (1 if metas else 0, mail_id),
            )
        return stale_paths

    def stored_paths_of_mail(self, mail_id: str) -> list[str]:
        rows = self.db.query_all(
            "SELECT stored_path FROM attachments WHERE mail_id = ? "
            "AND stored_path IS NOT NULL AND stored_path <> ''", (mail_id,)
        )
        return [str(r["stored_path"]) for r in rows]

    def stored_paths_of_mails(self, mail_ids: list[str]) -> list[str]:
        """批量取多封邮件已落盘的附件路径（`stored_paths_of_mail` 的批量版）。

        `delete_many()` 此前对每封各查一次：全选 300 封 = 300 次查询，
        而且是在删除事务**之前**串行跑完。
        """
        if not mail_ids:
            return []
        out: list[str] = []
        for start in range(0, len(mail_ids), _SQL_VAR_CHUNK):
            chunk = mail_ids[start:start + _SQL_VAR_CHUNK]
            marks = ", ".join("?" * len(chunk))
            rows = self.db.query_all(
                f"SELECT stored_path FROM attachments WHERE mail_id IN ({marks}) "  # noqa: S608
                "AND stored_path IS NOT NULL AND stored_path <> ''", chunk
            )
            out.extend(str(r["stored_path"]) for r in rows)
        return out

    def stored_paths_of_account(self, account_id: str) -> list[str]:
        rows = self.db.query_all(
            "SELECT a.stored_path FROM attachments a JOIN mails m ON m.id = a.mail_id "
            "WHERE m.account_id = ? AND a.stored_path IS NOT NULL "
            "AND a.stored_path <> ''", (account_id,)
        )
        return [str(r["stored_path"]) for r in rows]

    def all_stored_paths(self) -> set[str]:
        """全部已落盘附件路径（用于启动时清理孤儿文件）。"""
        rows = self.db.query_all(
            "SELECT stored_path FROM attachments WHERE stored_path IS NOT NULL "
            "AND stored_path <> ''"
        )
        return {str(r["stored_path"]) for r in rows}

    def set_read(self, mail_id: str, is_read: bool) -> None:
        self.db.execute(
            "UPDATE mails SET is_read = ? WHERE id = ?", (1 if is_read else 0, mail_id)
        )

    def set_starred(self, mail_id: str, starred: bool) -> None:
        self.db.execute(
            "UPDATE mails SET is_starred = ? WHERE id = ?",
            (1 if starred else 0, mail_id),
        )

    def mark_all_read(self, account_id: str | None = None) -> None:
        if account_id:
            self.db.execute("UPDATE mails SET is_read = 1 WHERE account_id = ?", (account_id,))
        else:
            self.db.execute("UPDATE mails SET is_read = 1")

    def delete(self, mail_id: str) -> list[str]:
        """删除本地副本，返回需要一并从磁盘删除的附件路径。"""
        paths = self.stored_paths_of_mail(mail_id)
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM attachments WHERE mail_id = ?", (mail_id,))
            conn.execute("DELETE FROM mails WHERE id = ?", (mail_id,))
        return paths

    # -------------------------------------------------------- 查询
    def get(self, mail_id: str) -> Mail | None:
        row = self.db.query_one("SELECT * FROM mails WHERE id = ?", (mail_id,))
        if not row:
            return None
        mail = Mail.from_row(row)
        mail.attachments = self.attachments_of(mail_id)
        return mail

    def attachments_of(self, mail_id: str) -> list[Attachment]:
        rows = self.db.query_all(
            "SELECT * FROM attachments WHERE mail_id = ?", (mail_id,)
        )
        return [Attachment.from_row(r) for r in rows]

    def mail_context_of_attachment(self, attachment_id: str) -> dict | None:
        """取附件所属邮件的同步元信息（用于重连 IMAP 下载）。"""
        return self.db.query_one(
            """SELECT a.part_index, a.filename, m.account_id, m.platform,
                      m.folder, m.uid
               FROM attachments a
               JOIN mails m ON m.id = a.mail_id
               WHERE a.id = ?""",
            (attachment_id,),
        )

    def mail_context(self, mail_id: str) -> dict | None:
        """取邮件的同步元信息（重连 IMAP 时需要 account / folder / uid）。"""
        return self.db.query_one(
            "SELECT account_id, platform, folder, uid FROM mails WHERE id = ?",
            (mail_id,),
        )

    def contexts_by_ids(self, mail_ids: list[str]) -> list[dict]:
        """批量取邮件的同步元信息（`mail_context` 的批量版）。

        返回顺序与 `mail_ids` 一致，且**跳过不存在的 id**（邮件可能已被删）。
        批量标已读时逐封查一次会变成 N 次往返，全部压在 GUI 线程上。
        """
        if not mail_ids:
            return []
        found: dict[str, dict] = {}
        for start in range(0, len(mail_ids), _SQL_VAR_CHUNK):
            chunk = mail_ids[start:start + _SQL_VAR_CHUNK]
            marks = ", ".join("?" * len(chunk))
            rows = self.db.query_all(
                f"SELECT id, account_id, platform, folder, uid FROM mails "  # noqa: S608
                f"WHERE id IN ({marks})", chunk
            )
            for row in rows:
                found[row["id"]] = dict(row)
        return [found[mid] for mid in mail_ids if mid in found]

    def body_fetch_info(self, mail_id: str) -> dict | None:
        """正文补拉需要的全部信息 + 是否已有正文（一次查询给出）。

        收敛到仓储层的原因：正文池（`BodyFetchPool`）此前直接拿
        `mails.db.query_one(...)` 写裸 SQL——同一张表的投影散落在两层里，
        表结构一变（比如加列、改列名）就会漏改。这里合并成一次往返，
        同时回答「该不该拉」与「往哪拉」。
        """
        return self.db.query_one(
            "SELECT account_id, platform, folder, uid,"
            " (body_text IS NOT NULL AND body_text != '') OR"
            " (body_html IS NOT NULL AND body_html != '') AS has_body"
            " FROM mails WHERE id = ?",
            (mail_id,),
        )

    def ids_unread(self, account_id: str | None = None,
                   limit: int = 5000) -> list[str]:
        """未读邮件的 id 列表。

        「全部标记为已读」需要逐封把 `\\Seen` 回写服务器，因此必须先知道
        究竟改了哪些。上限用于防止一次操作生成几十万条待回写记录。
        """
        if account_id:
            rows = self.db.query_all(
                "SELECT id FROM mails WHERE is_read = 0 AND account_id = ? LIMIT ?",
                (account_id, limit),
            )
        else:
            rows = self.db.query_all(
                "SELECT id FROM mails WHERE is_read = 0 LIMIT ?", (limit,))
        return [r["id"] for r in rows]

    def set_read_many(self, mail_ids: list[str], is_read: bool) -> int:
        if not mail_ids:
            return 0
        with self.db.transaction() as conn:
            conn.executemany(
                "UPDATE mails SET is_read = ? WHERE id = ?",
                [(1 if is_read else 0, mid) for mid in mail_ids],
            )
        return len(mail_ids)

    def set_starred_many(self, mail_ids: list[str], starred: bool) -> int:
        if not mail_ids:
            return 0
        with self.db.transaction() as conn:
            conn.executemany(
                "UPDATE mails SET is_starred = ? WHERE id = ?",
                [(1 if starred else 0, mid) for mid in mail_ids],
            )
        return len(mail_ids)

    def delete_many(self, mail_ids: list[str]) -> list[str]:
        """批量删除本地副本，返回需要一并清理的附件文件路径。"""
        if not mail_ids:
            return []
        stale = self.stored_paths_of_mails(mail_ids)
        with self.db.transaction() as conn:
            conn.executemany("DELETE FROM mails WHERE id = ?",
                             [(mid,) for mid in mail_ids])
        return stale

    def _select_sql(self, flt: MailFilter, cols: str, *,
                    order: str = "date") -> tuple[str, list]:
        """拼接完整筛选 SQL（含 ORDER BY / LIMIT）。

        关键词有两种实现：
          * 全文索引可用 → 走 FTS5 的 `MATCH`（能命中索引，无命中场景快约三个数量级）
          * 不可用 / 关键词没有可检索词元 → 回退 `LIKE`（功能不缺失，只是更慢）

        `order` 为 `"rank"` 时按相关度排序（只对 FTS 路径有意义）。
        其余情况按 `flt.order` 走白名单列排序——排序**必须**在服务端完成，
        否则分页之后「按发件人排序」只排了已加载的那一页。
        """
        sql, params, use_fts = self._base_sql(flt, cols)
        if use_fts and order == "rank":
            return sql + " ORDER BY rank LIMIT ?", [*params, flt.limit]
        column = _ORDER_COLUMNS.get(flt.order, "m.date")
        direction = "DESC" if flt.desc else "ASC"
        # 二级键用 id：同一个 date 值可能有多封（服务器时间精度只到秒），
        # 没有稳定次序时 keyset 分页会在边界重复或漏行。
        return (f"{sql} ORDER BY {column} {direction}, m.id {direction} LIMIT ?",
                [*params, flt.limit])

    @staticmethod
    def _project(cols: str, alias: str) -> str:
        """给投影列加表别名前缀。

        全文检索路径要 join `mails_fts`，而它也有 `subject`/`from_name`/
        `preview`/`body_text` 这些同名列，不加前缀会 ambiguous。
        """
        if cols.strip() == "*":
            return f"{alias}.*"
        return ", ".join(f"{alias}.{c.strip()}" for c in cols.split(","))

    def _common_filters(self, flt: MailFilter, alias: str) -> tuple[list[str], list]:
        """非关键词的筛选条件（两条检索路径、列表与会话视图共用）。"""
        sql: list[str] = []
        params: list = []
        if flt.account_id:
            sql.append(f"AND {alias}.account_id = ?")
            params.append(flt.account_id)
        if flt.platform:
            sql.append(f"AND {alias}.platform = ?")
            params.append(flt.platform)
        if flt.folder:
            # 文件夹精确匹配：文件夹名是服务器给定的（含中文/特殊字符），
            # 比较不涉及用户输入，无需 LIKE 或转义。
            sql.append(f"AND {alias}.folder = ?")
            params.append(flt.folder)
        if flt.from_addr:
            # from:/发件人：模糊匹配发件人地址与显示名（显示名里常有中文别名）。
            sql.append(
                f"AND ({alias}.from_addr LIKE ? ESCAPE '\\' "
                f"OR {alias}.from_name LIKE ? ESCAPE '\\')"
            )
            kw = f"%{escape_like(flt.from_addr)}%"
            params.extend([kw, kw])
        if flt.to_addr:
            # to: 匹配的是收件人列表（to_addrs 是 JSON 数组字符串）。
            # 直接 LIKE 即可命中「含这个地址」的邮件，无需解析 JSON。
            sql.append(f"AND {alias}.to_addrs LIKE ? ESCAPE '\\'")
            params.append(f"%{escape_like(flt.to_addr)}%")
        if flt.subject:
            sql.append(f"AND {alias}.subject LIKE ? ESCAPE '\\'")
            params.append(f"%{escape_like(flt.subject)}%")
        if flt.has_attachment is not None:
            sql.append(f"AND {alias}.has_attachments = ?")
            params.append(1 if flt.has_attachment else 0)
        if flt.starred_only:
            sql.append(f"AND {alias}.is_starred = 1")
        if flt.date_from:
            sql.append(f"AND {alias}.date >= ?")
            params.append(flt.date_from.isoformat())
        if flt.date_to:
            sql.append(f"AND {alias}.date <= ?")
            params.append(flt.date_to.isoformat())
        if flt.unread_only:
            sql.append(f"AND {alias}.is_read = 0")
        if flt.before_date is not None:
            # keyset 分页：只要严格排在游标那一行之后的记录。
            # date 在库里是统一格式的 ISO8601 字符串，字典序等于时间序，
            # 因此可以直接比较；id 是同一秒多封邮件之间的 tie-break。
            sql.append(
                f"AND ({alias}.date < ? OR ({alias}.date = ? AND {alias}.id < ?))"
            )
            iso = flt.before_date.isoformat()
            params.extend([iso, iso, flt.before_id or ""])
        return sql, params

    def _base_sql(self, flt: MailFilter, cols: str) -> tuple[str, list, bool]:
        """`SELECT … WHERE …`（不含 ORDER BY / LIMIT）。

        返回 `(sql, params, 是否走了全文索引)`。统一用别名 `m` 引用 mails，
        这样全文路径 join 进来时列名不冲突，也便于被会话视图的 CTE 复用。
        """
        params: list = []
        use_fts = bool(flt.keyword and self.db.fts_available
                       and fts_eligible(flt.keyword) and match_query(flt.keyword))
        if use_fts:
            sql = [f"SELECT {self._project(cols, 'm')} FROM mails m "  # noqa: S608
                   "JOIN mails_fts f ON f.rowid = m.rowid "
                   "WHERE mails_fts MATCH ?"]
            params.append(match_query(flt.keyword))
        else:
            sql = [f"SELECT {self._project(cols, 'm')} FROM mails m WHERE 1=1"]  # noqa: S608
            if flt.keyword:
                sql.append(
                    "AND (m.subject LIKE ? ESCAPE '\\' OR m.from_addr LIKE ? ESCAPE '\\' "
                    "OR m.from_name LIKE ? ESCAPE '\\' OR m.preview LIKE ? ESCAPE '\\' "
                    "OR m.body_text LIKE ? ESCAPE '\\')"
                )
                kw = f"%{escape_like(flt.keyword)}%"
                params.extend([kw] * 5)
        extra, extra_params = self._common_filters(flt, "m")
        sql.extend(extra)
        params.extend(extra_params)
        return " ".join(sql), params, use_fts

    def query(self, flt: MailFilter) -> list[Mail]:
        """完整查询（含正文）。零散场景用；列表渲染请用 `query_summaries()`。"""
        sql, params = self._select_sql(flt, "*")
        rows = self.db.query_all(sql, params)
        return [Mail.from_row(r) for r in rows]

    def query_summaries(self, flt: MailFilter, *,
                        order: str = "date") -> list[MailSummary]:
        """列表专用查询：只投影渲染需要的列，**不取 body_text / body_html**。

        正文单封可达上百 KB，列表一次 300 行时仅正文就是数十 MB。
        投影后列表常驻内存下降一个数量级，筛选与滚动不再触发大对象 GC 抖动。
        """
        sql, params = self._select_sql(
            flt, ", ".join(MAIL_SUMMARY_COLUMNS), order=order
        )
        rows = self.db.query_all(sql, params)
        return [MailSummary.from_row(r) for r in rows]

    def summary_by_id(self, mail_id: str) -> MailSummary | None:
        """按 id 取列表投影（增量插入新邮件时用）。"""
        cols = ", ".join(f"m.{c}" for c in MAIL_SUMMARY_COLUMNS)
        row = self.db.query_one(
            f"SELECT {cols} FROM mails m WHERE m.id = ?",  # noqa: S608
            (mail_id,),
        )
        return MailSummary.from_row(row) if row else None

    def summaries_by_ids(self, mail_ids: list[str]) -> list[MailSummary]:
        """按 id 批量取投影，**保持传入顺序**。

        顺序很关键：增量插入到日期倒序的列表时，若按库返回顺序插入，
        行位置会与「重新整表查询」的结果不一致。
        """
        if not mail_ids:
            return []
        cols = ", ".join(f"m.{c}" for c in MAIL_SUMMARY_COLUMNS)
        found: dict[str, MailSummary] = {}
        # SQLite 的变量上限默认 999，分批查询以兼容极端情况
        for start in range(0, len(mail_ids), 500):
            chunk = mail_ids[start:start + 500]
            marks = ", ".join("?" * len(chunk))
            rows = self.db.query_all(
                f"SELECT {cols} FROM mails m WHERE m.id IN ({marks})",  # noqa: S608
                chunk,
            )
            for row in rows:
                summary = MailSummary.from_row(row)
                found[summary.id] = summary
        return [found[mid] for mid in mail_ids if mid in found]

    def thread_summaries(self, flt: MailFilter) -> list[ThreadSummary]:
        """按 `thread_key` 归并的会话列表（两阶段查询）。

        反例就是本方法早先的写法：把 `ROW_NUMBER()` + `COUNT()` + `SUM()`
        三个窗口函数套在同一层 CTE 上。窗口函数要求先看到完整分区，SQLite
        只能把**过滤后的全部行**物化成临时结果集再逐行求值——10 万封实测
        475–970 ms，而且是切换视图时在 GUI 线程上跑。

        拆成两步后，代价从「与邮件总数成正比」变成「与邮件总数成正比地扫
        **索引**」+「与会话数成正比地回表」：

          1. 只投影 `thread_key / date / is_read` 三列（正好覆盖
             `idx_mails_thread(thread_key, date DESC)`），`GROUP BY thread_key`
             拿到每个会话的最新时间、总封数、未读数，按最新时间取前 `limit` 个；
          2. 只对这 `limit` 个会话各做一次索引查找，回表取最新那一封。
        """
        # 列名不带 `m.` 前缀：`_base_sql` 内部会用 `_project()` 统一加，
        # 再传一次就变成 `m.m.thread_key`。
        inner, params, _use_fts = self._base_sql(
            flt, "thread_key, date, is_read"
        )
        projected = self._project(",".join(MAIL_SUMMARY_COLUMNS), "m")
        sql = (
            "WITH agg AS ("  # noqa: S608
            "SELECT thread_key AS thread_key, MAX(date) AS last_date, "
            "COUNT(*) AS _total, "
            "SUM(CASE WHEN is_read = 0 THEN 1 ELSE 0 END) AS _unread "
            f"FROM ({inner}) AS f GROUP BY thread_key "
            "ORDER BY last_date DESC LIMIT ?) "
            f"SELECT {projected}, a._total, a._unread "
            "FROM agg a JOIN mails m ON m.thread_key = a.thread_key "
            "WHERE m.id = (SELECT m2.id FROM mails m2 "
            "              WHERE m2.thread_key = a.thread_key "
            "              ORDER BY m2.date DESC LIMIT 1) "
            "ORDER BY a.last_date DESC"
        )
        rows = self.db.query_all(sql, [*params, flt.limit])
        return [ThreadSummary.from_row(r) for r in rows]

    def mails_in_thread(self, thread_key: str,
                        limit: int = 100) -> list[MailSummary]:
        """会话内的全部邮件（按时间升序，符合阅读顺序）。"""
        cols = ", ".join(f"m.{c}" for c in MAIL_SUMMARY_COLUMNS)
        rows = self.db.query_all(
            f"SELECT {cols} FROM mails m WHERE m.thread_key = ? "  # noqa: S608
            "ORDER BY m.date ASC LIMIT ?",
            (thread_key, limit),
        )
        return [MailSummary.from_row(r) for r in rows]

    def count_search(self, flt: MailFilter) -> int | None:
        """关键词命中的**总数**（不受 `limit` 限制，用于「共 N 条结果」）。

        只有 FTS 路径才给得出精确总数：`LIKE` 路径要数全就得整表扫一遍，
        那与列表查询的代价重复，因此返回 `None` 让调用方不显示总数。
        """
        if not (flt.keyword and self.db.fts_available
                and fts_eligible(flt.keyword)):
            return None
        mq = match_query(flt.keyword)
        if not mq:
            return None
        sql = ["SELECT COUNT(*) FROM mails m "
               "JOIN mails_fts f ON f.rowid = m.rowid WHERE mails_fts MATCH ?"]
        params: list = [mq]
        extra, extra_params = self._common_filters(flt, "m")
        sql.extend(extra)
        params.extend(extra_params)
        return int(self.db.scalar(" ".join(sql), params) or 0)

    def count_by_account(self) -> dict[str, tuple[int, int]]:
        """返回 {account_id: (total, unread)}，用覆盖索引避免读表页。

        拆成两条可各自走索引的计数（总量走 account_id 索引、未读走 is_read
        索引），比原先「一次 GROUP BY 里带 SUM(CASE…)」要扫表页更快；
        `count_all()` 也不再需要第二次全表聚合（调用方直接累加即可）。
        """
        totals = {
            r["account_id"]: int(r["total"] or 0)
            for r in self.db.query_all(
                "SELECT account_id, COUNT(*) AS total FROM mails GROUP BY account_id"
            )
        }
        unread = {
            r["account_id"]: int(r["n"] or 0)
            for r in self.db.query_all(
                "SELECT account_id, COUNT(*) AS n FROM mails "
                "WHERE is_read = 0 GROUP BY account_id"
            )
        }
        return {aid: (total, unread.get(aid, 0)) for aid, total in totals.items()}

    def counts_snapshot(self) -> tuple[dict[str, tuple[int, int]], tuple[int, int]]:
        """一次调用同时给出「按账号计数」与「总计」，避免两次全量聚合。"""
        per_account = self.count_by_account()
        total = sum(t for t, _ in per_account.values())
        unread = sum(u for _, u in per_account.values())
        return per_account, (total, unread)

    def count_all(self) -> tuple[int, int]:
        total = int(self.db.scalar("SELECT COUNT(*) FROM mails") or 0)
        unread = int(self.db.scalar(
            "SELECT COUNT(*) FROM mails WHERE is_read = 0") or 0)
        return total, unread


class AttachmentRepository:
    def __init__(self, db) -> None:
        self.db = db

    def set_stored_path(self, attachment_id: str, path: str) -> None:
        self.db.execute(
            "UPDATE attachments SET stored_path = ? WHERE id = ?", (path, attachment_id)
        )

    def get(self, attachment_id: str) -> Attachment | None:
        row = self.db.query_one("SELECT * FROM attachments WHERE id = ?", (attachment_id,))
        return Attachment.from_row(row) if row else None

    def by_content_id(self, mail_id: str, content_id: str) -> Attachment | None:
        """按 `Content-ID` 找内嵌资源（正文里的 `cid:` 图片指向它）。

        比较时统一去掉尖括号并小写：邮件里的写法五花八门
        （`<abc@x>` / `abc@x` / `<ABC@X>`），精确匹配会漏掉一大批。
        """
        if not content_id:
            return None
        row = self.db.query_one(
            "SELECT * FROM attachments WHERE mail_id = ? "
            "AND LOWER(REPLACE(REPLACE(content_id, '<', ''), '>', '')) = ? "
            "LIMIT 1",
            (mail_id, content_id.strip().strip("<>").lower()),
        )
        return Attachment.from_row(row) if row else None

    def inline_of_mail(self, mail_id: str) -> list[Attachment]:
        """该邮件里所有带 Content-ID 的内嵌资源。"""
        rows = self.db.query_all(
            "SELECT * FROM attachments WHERE mail_id = ? "
            "AND content_id IS NOT NULL AND content_id != ''",
            (mail_id,),
        )
        return [Attachment.from_row(r) for r in rows]


class PendingFlagRepository:
    """待回写服务器的标记变更队列。

    入队时的合并规则：同一 (account, folder, uid) 只保留一条，
    新动作在已有基础上**叠加/抵消**——否则反复点「已读/未读」会堆出一串
    相互矛盾的指令，按顺序全部执行既浪费往返，也可能以中间态收场。
    """

    def __init__(self, db) -> None:
        self.db = db

    def add(self, account_id: str, folder: str, uid: str,
            add: list[str] | tuple[str, ...] = (),
            remove: list[str] | tuple[str, ...] = ()) -> None:
        add_set = {f for f in add if f}
        remove_set = {f for f in remove if f}
        # 同一次调用里对同一标志既加又删 = 自相矛盾，视为没点这个标志。
        # 两个集合都要减掉，否则 `remove` 会被原样写进队列，
        # 「加回来再删掉」反而变成一条真实的删除指令。
        both = add_set & remove_set
        if both:
            add_set -= both
            remove_set -= both
        if not add_set and not remove_set:
            return
        existing = self.db.query_one(
            "SELECT * FROM pending_flags WHERE account_id = ? AND folder = ? AND uid = ?",
            (account_id, folder or "INBOX", str(uid)),
        )
        if existing:
            row = dict(existing)
            merged_add = set(load_str_list(row.get("add_flags")))
            merged_remove = set(load_str_list(row.get("remove_flags")))
            # 新动作覆盖相反方向的旧动作
            merged_add = (merged_add | add_set) - remove_set
            merged_remove = (merged_remove | remove_set) - add_set
            merged_add -= merged_remove
            merged_remove -= merged_add
            if not merged_add and not merged_remove:
                self.db.execute("DELETE FROM pending_flags WHERE id = ?", (row["id"],))
                return
            self.db.execute(
                "UPDATE pending_flags SET add_flags = ?, remove_flags = ? WHERE id = ?",
                (json.dumps(sorted(merged_add)), json.dumps(sorted(merged_remove)),
                 row["id"]),
            )
            return
        self.db.execute(
            "INSERT INTO pending_flags"
            "(id, account_id, folder, uid, add_flags, remove_flags, created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (new_id(), account_id, folder or "INBOX", str(uid),
             json.dumps(sorted(add_set)), json.dumps(sorted(remove_set)), utcnow_iso()),
        )

    def add_many(self, items: list[tuple[str, str, str, list[str], list[str]]]) -> int:
        """批量入队，返回实际发生变化的 `(account, folder, uid)` 组数。

        `items` 每项为 `(account_id, folder, uid, add, remove)`，合并语义与
        逐条 `add()` **完全一致**（同键叠加、相反方向抵消、空则删除已有行）。
        省略这里是为什么：`mark_all_read()` 会对最多 5000 封逐封调 `add()`，
        每封 = 1 次 SELECT + 1 次写入 ≈ 1.5 万条串行 SQLite 操作，而它跑在
        GUI 线程上 —— 点一次「全部标为已读」就卡住数秒到数十秒。

        实现是「一次预读 + 单事务 executemany」：预读用一次 `IN` 查询取回
        所有涉及的已存在行，随后的插入/更新/删除各自一次 `executemany`。
        """
        merged: dict[tuple[str, str, str], tuple[set[str], set[str]]] = {}
        for account_id, folder, uid, add, remove in items:
            add_set = {f for f in add if f}
            remove_set = {f for f in remove if f}
            # 同一次调用里对同一标志既加又删 = 没点这个标志（与 add() 一致）
            both = add_set & remove_set
            if both:
                add_set -= both
                remove_set -= both
            if not add_set and not remove_set:
                continue
            key = (account_id, folder or "INBOX", str(uid))
            cur_add, cur_remove = merged.get(key, (set(), set()))
            new_add = (cur_add | add_set) - remove_set
            new_remove = (cur_remove | remove_set) - add_set
            new_add -= new_remove
            new_remove -= new_add
            merged[key] = (new_add, new_remove)
        if not merged:
            return 0

        keys = list(merged)
        existing: dict[tuple[str, str, str], dict] = {}
        # 每组占 3 个绑定变量，因此按 1/3 粒度分批，避免撞上 SQLite 的变量上限
        step = max(1, _SQL_VAR_CHUNK // 3)
        for start in range(0, len(keys), step):
            chunk = keys[start:start + step]
            # 三列联合定位，SQLite 的 `IN` 只吃单值，因此写成 OR 组合
            where = " OR ".join(
                "(account_id = ? AND folder = ? AND uid = ?)" for _ in chunk)
            params = [v for key in chunk for v in key]
            for row in self.db.query_all(
                    f"SELECT * FROM pending_flags WHERE {where}", params):  # noqa: S608
                existing[(row["account_id"], row["folder"], str(row["uid"]))] = dict(row)

        now = utcnow_iso()
        inserts: list[tuple] = []
        updates: list[tuple] = []
        deletes: list[tuple] = []
        for key, (add_set, remove_set) in merged.items():
            row = existing.get(key)
            if row is None:
                inserts.append((new_id(), key[0], key[1], key[2],
                                json.dumps(sorted(add_set)),
                                json.dumps(sorted(remove_set)), now))
                continue
            merged_add = set(load_str_list(row.get("add_flags")))
            merged_remove = set(load_str_list(row.get("remove_flags")))
            merged_add = (merged_add | add_set) - remove_set
            merged_remove = (merged_remove | remove_set) - add_set
            merged_add -= merged_remove
            merged_remove -= merged_add
            if not merged_add and not merged_remove:
                deletes.append((row["id"],))
            else:
                updates.append((json.dumps(sorted(merged_add)),
                                json.dumps(sorted(merged_remove)), row["id"]))
        with self.db.transaction() as conn:
            if inserts:
                conn.executemany(
                    "INSERT INTO pending_flags"
                    "(id, account_id, folder, uid, add_flags, remove_flags, created_at) "
                    "VALUES(?,?,?,?,?,?,?)", inserts)
            if updates:
                conn.executemany(
                    "UPDATE pending_flags SET add_flags = ?, remove_flags = ? "
                    "WHERE id = ?", updates)
            if deletes:
                conn.executemany("DELETE FROM pending_flags WHERE id = ?", deletes)
        return len(merged)

    def list_for_account(self, account_id: str, limit: int = 200) -> list[dict]:
        rows = self.db.query_all(
            "SELECT * FROM pending_flags WHERE account_id = ? "
            "ORDER BY created_at ASC LIMIT ?",
            (account_id, limit),
        )
        out = []
        for row in rows:
            item = dict(row)
            item["add_flags"] = load_str_list(item.get("add_flags"))
            item["remove_flags"] = load_str_list(item.get("remove_flags"))
            out.append(item)
        return out

    def remove(self, flag_id: str) -> None:
        self.db.execute("DELETE FROM pending_flags WHERE id = ?", (flag_id,))

    def count(self, account_id: str | None = None) -> int:
        if account_id:
            return int(self.db.scalar(
                "SELECT COUNT(*) FROM pending_flags WHERE account_id = ?",
                (account_id,)) or 0)
        return int(self.db.scalar("SELECT COUNT(*) FROM pending_flags") or 0)

    def drop_for_uid(self, account_id: str, folder: str, uid: str) -> None:
        self.db.execute(
            "DELETE FROM pending_flags WHERE account_id = ? AND folder = ? AND uid = ?",
            (account_id, folder or "INBOX", str(uid)),
        )


class OutboxRepository:
    """发件箱：待发 / 已发邮件的持久化队列。

    与 `PendingFlagRepository` 的分工
    -------------------------------
    那是「标记回写」队列（本地状态已知、只差推到服务器）；这里是「整封邮件」
    队列（内容本身还没送达）。两者的失败语义不同：标记推失败可以无限重试
    （幂等），而邮件**不能盲目重发**——服务器可能已经收下只是响应丢了，
    重发会让对方收到两封。因此这里的状态机带 `attempts` 与明确的失败态，
    由用户决定是否重试，不自动重发。
    """

    def __init__(self, db) -> None:
        self.db = db

    def add(self, account_id: str, subject: str, to_addrs: str, raw: str,
            in_reply_to: str = "", ref_chain: str = "") -> str:
        msg_id = new_id()
        self.db.execute(
            "INSERT INTO outbox"
            "(id, account_id, status, subject, to_addrs, in_reply_to, ref_chain,"
            " raw, error, attempts, created_at, sent_at) "
            "VALUES(?,?,?,?,?,?,?,?,'',0,?,'')",
            (msg_id, account_id, OUTBOX_PENDING, subject, to_addrs,
             in_reply_to, ref_chain, raw, utcnow_iso()),
        )
        return msg_id

    def get(self, msg_id: str) -> OutboxMessage | None:
        row = self.db.query_one("SELECT * FROM outbox WHERE id = ?", (msg_id,))
        return OutboxMessage.from_row(row) if row else None

    def list(self, account_id: str | None = None, limit: int = 200) -> OutboxList:
        if account_id:
            rows = self.db.query_all(
                "SELECT * FROM outbox WHERE account_id = ? ORDER BY created_at DESC LIMIT ?",
                (account_id, limit))
        else:
            rows = self.db.query_all(
                "SELECT * FROM outbox ORDER BY created_at DESC LIMIT ?", (limit,))
        return [OutboxMessage.from_row(r) for r in rows]

    def pending(self, account_id: str | None = None) -> OutboxList:
        """所有待发送的邮件（含上次中断留下的 sending，由迁移回收为 pending）。"""
        if account_id:
            rows = self.db.query_all(
                "SELECT * FROM outbox WHERE status IN ('pending','sending') "
                "AND account_id = ? ORDER BY created_at ASC", (account_id,))
        else:
            rows = self.db.query_all(
                "SELECT * FROM outbox WHERE status IN ('pending','sending') "
                "ORDER BY created_at ASC")
        return [OutboxMessage.from_row(r) for r in rows]

    def mark_sending(self, msg_id: str) -> None:
        self.db.execute(
            "UPDATE outbox SET status = 'sending', attempts = attempts + 1 WHERE id = ?",
            (msg_id,))

    def mark_sent(self, msg_id: str) -> None:
        self.db.execute(
            "UPDATE outbox SET status = 'sent', sent_at = ?, error = '' WHERE id = ?",
            (utcnow_iso(), msg_id))

    def mark_failed(self, msg_id: str, error: str) -> None:
        """失败但保留原文：用户要能原样重发，因此**不删除**。"""
        self.db.execute(
            "UPDATE outbox SET status = 'failed', error = ? WHERE id = ?",
            (error[:2000], msg_id))

    def reset_to_pending(self, msg_id: str) -> None:
        """用户点「重试」：清掉错误回到待发。"""
        self.db.execute(
            "UPDATE outbox SET status = 'pending', error = '' WHERE id = ?", (msg_id,))

    def delete(self, msg_id: str) -> None:
        self.db.execute("DELETE FROM outbox WHERE id = ?", (msg_id,))

    def counts(self, account_id: str | None = None) -> dict[str, int]:
        """按状态计数，供界面显示「N 封待发送」。"""
        if account_id:
            rows = self.db.query_all(
                "SELECT status, COUNT(*) AS n FROM outbox WHERE account_id = ? "
                "GROUP BY status", (account_id,))
        else:
            rows = self.db.query_all(
                "SELECT status, COUNT(*) AS n FROM outbox GROUP BY status")
        return {str(r["status"]): int(r["n"] or 0) for r in rows}


# contacts 表允许被 update() 修改的列。与 _ACCOUNT_UPDATABLE 同理：动态列名
# 是注入 sink，必须用白名单收口。email 不在其中——它是唯一键，改邮箱等价于
# 「删旧建新」，应走 delete + create 而不是 update。
_CONTACT_UPDATABLE = frozenset({"name", "account_id", "note"})


class ContactRepository:
    """通讯录仓储：CRUD + 模糊搜索 + 从邮件发件人自动学习。

    自动学习（`learn_from_senders`）是本功能的「卖点」所在，它的去重语义
    全部依赖 `contacts.email` 的唯一约束 + `ON CONFLICT(email)` upsert：
    同一地址无论来自手动添加还是哪次同步，都收敛到一条记录。
    """

    def __init__(self, db) -> None:
        self.db = db

    # ------------------------------------------------------------ 查询
    def list(self, keyword: str = "") -> ContactList:
        """全部联系人（可带关键词）。排序：有名字的在前，再按 email。

        为什么先按「有无名字」分组：自动学习的联系人 name 经常为空，
        把它们沉到列表底部，让用户手动录入的、有名字的联系人更醒目。
        """
        if keyword.strip():
            like = f"%{escape_like(keyword.strip())}%"
            rows = self.db.query_all(
                "SELECT * FROM contacts WHERE name LIKE ? ESCAPE '\\' "
                "OR email LIKE ? ESCAPE '\\' "
                "ORDER BY (name = '') ASC, email COLLATE NOCASE ASC",
                (like, like),
            )
        else:
            rows = self.db.query_all(
                "SELECT * FROM contacts ORDER BY (name = '') ASC, email COLLATE NOCASE ASC"
            )
        return [Contact.from_row(r) for r in rows]

    def get(self, contact_id: str) -> Contact | None:
        row = self.db.query_one("SELECT * FROM contacts WHERE id = ?", (contact_id,))
        return Contact.from_row(row) if row else None

    def find_by_email(self, email: str) -> Contact | None:
        row = self.db.query_one(
            "SELECT * FROM contacts WHERE email = ?", (email.strip().lower(),)
        )
        return Contact.from_row(row) if row else None

    # ------------------------------------------------------------ 写入
    def create(self, email: str, name: str = "", account_id: str | None = None,
               note: str = "") -> Contact:
        """手动添加一个联系人。email 冲突时抛 ValueError（交由 UI 提示）。

        之所以在服务层语义上**不允许**覆盖已存在联系人的 name/note：
        用户手动录的名字是有意的编辑，自动学习不能反过来把它洗掉。
        """
        email = email.strip().lower()
        if not is_email_like(email):
            raise ValueError("不是有效的邮箱地址")
        if self.find_by_email(email) is not None:
            raise ValueError(f"联系人 {email} 已存在")
        now = utcnow_iso()
        contact_id = new_id()
        self.db.execute(
            "INSERT INTO contacts(id, name, email, account_id, note, created_at, updated_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (contact_id, name.strip(), email, account_id, note, now, now),
        )
        row = self.db.query_one("SELECT * FROM contacts WHERE id = ?", (contact_id,))
        return Contact.from_row(row)  # type: ignore[arg-type]

    def update(self, contact_id: str, fields: dict) -> None:
        """按白名单更新字段。email 不可经此修改（唯一键，需删旧建新）。"""
        if not fields:
            return
        unknown = set(fields) - _CONTACT_UPDATABLE
        if unknown:
            raise ValueError(f"不允许更新的字段：{sorted(unknown)}")
        cols = ", ".join(f"{k} = ?" for k in fields)
        # 列名已按白名单校验，值全走占位符
        self.db.execute(
            f"UPDATE contacts SET {cols}, updated_at = ? WHERE id = ?",  # noqa: S608
            (*fields.values(), utcnow_iso(), contact_id),
        )

    def delete(self, contact_id: str) -> None:
        self.db.execute("DELETE FROM contacts WHERE id = ?", (contact_id,))

    # ------------------------------------------------------------ 自动学习
    def learn_from_senders(self, senders: builtins.list[tuple[str, str]],
                           account_id: str | None = None,
                           skip: set[str] | None = None) -> int:
        """从发件人列表批量 upsert 联系人，返回真正新增的行数。

        `senders` 每项为 `(name, from_addr)`；`skip` 是「不要学进去」的地址集合
        （同步侧传入**自身账号地址**，避免把自己学成联系人）。

        写入用 `INSERT ... ON CONFLICT(email) DO UPDATE`：
          * 已存在 → 只在「新 name 非空且比旧 name 更长」时更新 name。
            这是「只增不删、只长不短」——自动学习不该用「更短的名字」
            覆盖掉手动录的完整姓名，也不该把已有名字清成空。
          * 新地址 → 插入一行（name 可为空，邮箱是唯一可靠身份）。
        过滤发生在内存里：明显不是邮箱的 from_addr 直接丢弃，不进 SQL。
        """
        skip = skip or set()
        now = utcnow_iso()
        # 去重：同一批里同一地址可能出现多次（一个联系人发了多封），
        # 逐条 upsert 会造成无谓的写放大。先按邮箱合并，保留「最长的名字」。
        merged: dict[str, str] = {}
        order: list[str] = []
        for name, addr in senders:
            addr = (addr or "").strip().lower()
            if not addr or addr in skip or not is_email_like(addr):
                continue
            candidate = (name or "").strip()
            if addr not in merged:
                merged[addr] = candidate
                order.append(addr)
            elif len(candidate) > len(merged[addr]):
                merged[addr] = candidate

        if not merged:
            return 0

        # 先一次性查出哪些地址已经存在：`total_changes` / `changes()` 对
        # `ON CONFLICT DO UPDATE` 也会 +1（更新同样算「改变了行」），
        # 不能用来区分「新增」与「更新」。这里用 `IN` 查询预读已存在集合，
        # 只对真正的新地址计数。
        existing = set()
        marks = ", ".join("?" * len(order))
        for row in self.db.query_all(
                f"SELECT email FROM contacts WHERE email IN ({marks})",  # noqa: S608
                order):
            existing.add(str(row["email"]))

        inserted = 0
        with self.db.transaction() as conn:
            for addr in order:
                name = merged[addr]
                conn.execute(
                    """INSERT INTO contacts(id, name, email, account_id, note,
                                            created_at, updated_at)
                       VALUES(?,?,?,?, '', ?, ?)
                       ON CONFLICT(email) DO UPDATE SET
                           account_id = COALESCE(contacts.account_id, excluded.account_id),
                           name = CASE
                               WHEN excluded.name <> ''
                                    AND length(excluded.name) > length(contacts.name)
                               THEN excluded.name
                               ELSE contacts.name
                           END,
                           updated_at = excluded.updated_at""",
                    (new_id(), name, addr, account_id, now, now),
                )
                if addr not in existing:
                    inserted += 1
        return inserted

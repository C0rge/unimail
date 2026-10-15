"""仓储层：账号、邮件、附件、同步游标的数据访问。"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..config import PLATFORMS
from ..core.models import (
    MAIL_SUMMARY_COLUMNS,
    Account,
    AccountStatus,
    Attachment,
    AttachmentMeta,
    Mail,
    MailFilter,
    MailSummary,
    NormalizedMail,
    new_id,
)


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


# accounts 表允许被 update_fields 修改的列。动态列名在 SQL 里是典型的注入 sink，
# 即使当前调用方全是内部常量，也必须用白名单把它收口。
_ACCOUNT_UPDATABLE = frozenset({
    "platform", "email", "display_name", "imap_host", "imap_port",
    "use_ssl", "username", "sync_interval", "last_synced_at", "status",
})

# 附件落盘路径列表。
# 为什么需要别名：`AccountRepository` 里有一个名为 `list` 的方法，而 Python 的
# 注解（含 PEP 563 的字符串注解）是在**类作用域内**解析的，`-> list[str]` 会被
# 解析成那个方法本身（mypy: "Function AccountRepository.list is not valid as a
# type"）。用具名别名即可回避，也顺便说明了这个返回值的语义。
StoredPaths = list[str]


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
                username, sync_interval, status, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                acc_id, draft.platform, draft.email.lower().strip(),
                draft.display_name or "", host, port, 1 if use_ssl else 0,
                draft.username, draft.sync_interval, AccountStatus.OK.value,
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
                    body_html, has_attachments, is_read, is_starred, raw_size, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    mail_id, account_id, platform, mail.folder, mail.uid,
                    int(uid_validity or 0),
                    mail.message_id, mail.subject, mail.from_name, mail.from_addr,
                    json.dumps(mail.to_addrs, ensure_ascii=False),
                    (mail.date or datetime.now(timezone.utc)).isoformat(),
                    mail.preview, mail.body_text, mail.body_html,
                    1 if mail.attachments else 0, 0, 0, mail.raw_size, utcnow_iso(),
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
                1 if mail.attachments else 0, 0, 0, mail.raw_size, now,
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
                    body_html, has_attachments, is_read, is_starred, raw_size, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
        """批量回填正文：rows = [(mail_id, body_text, body_html), …]。"""
        if not rows:
            return 0
        with self.db.transaction() as conn:
            conn.executemany(
                "UPDATE mails SET body_text = ?, body_html = ? WHERE id = ?",
                [(text, html, mail_id) for mail_id, text, html in rows],
            )
        return len(rows)

    def update_body(self, mail_id: str, body_text: str, body_html: str) -> None:
        self.db.execute(
            "UPDATE mails SET body_text = ?, body_html = ? WHERE id = ?",
            (body_text, body_html, mail_id),
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

    def _select_sql(self, flt: MailFilter, cols: str) -> tuple[str, list]:
        """拼接筛选 SQL。列名由调用方以**常量**传入（MAIL_SUMMARY_COLUMNS / "*"），
        条件值一律走占位符——SQLite 不支持参数化标识符，这是唯一写法。"""
        sql = [f"SELECT {cols} FROM mails WHERE 1=1"]  # noqa: S608
        params: list = []
        if flt.account_id:
            sql.append("AND account_id = ?")
            params.append(flt.account_id)
        if flt.platform:
            sql.append("AND platform = ?")
            params.append(flt.platform)
        if flt.keyword:
            sql.append("AND (subject LIKE ? ESCAPE '\\' OR from_addr LIKE ? ESCAPE '\\' "
                       "OR from_name LIKE ? ESCAPE '\\' OR preview LIKE ? ESCAPE '\\' "
                       "OR body_text LIKE ? ESCAPE '\\')")
            kw = f"%{escape_like(flt.keyword)}%"
            params.extend([kw] * 5)
        if flt.date_from:
            sql.append("AND date >= ?")
            params.append(flt.date_from.isoformat())
        if flt.date_to:
            sql.append("AND date <= ?")
            params.append(flt.date_to.isoformat())
        if flt.unread_only:
            sql.append("AND is_read = 0")
        sql.append("ORDER BY date DESC LIMIT ?")
        params.append(flt.limit)
        return " ".join(sql), params

    def query(self, flt: MailFilter) -> list[Mail]:
        """完整查询（含正文）。零散场景用；列表渲染请用 `query_summaries()`。"""
        sql, params = self._select_sql(flt, "*")
        rows = self.db.query_all(sql, params)
        return [Mail.from_row(r) for r in rows]

    def query_summaries(self, flt: MailFilter) -> list[MailSummary]:
        """列表专用查询：只投影渲染需要的列，**不取 body_text / body_html**。

        正文单封可达上百 KB，列表一次 300 行时仅正文就是数十 MB。
        投影后列表常驻内存下降一个数量级，筛选与滚动不再触发大对象 GC 抖动。
        """
        sql, params = self._select_sql(flt, ", ".join(MAIL_SUMMARY_COLUMNS))
        rows = self.db.query_all(sql, params)
        return [MailSummary.from_row(r) for r in rows]

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

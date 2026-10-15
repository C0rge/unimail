"""仓储层：账号、邮件、附件、同步游标的数据访问。"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from ..core.models import (
    Account,
    AccountStatus,
    Attachment,
    AttachmentMeta,
    Mail,
    MailFilter,
    NormalizedMail,
    new_id,
)
from ..config import PLATFORMS


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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
        cols = ", ".join(f"{k} = ?" for k in fields)
        self.db.execute(
            f"UPDATE accounts SET {cols} WHERE id = ?", (*fields.values(), account_id)
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

    def delete(self, account_id: str) -> None:
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM attachments WHERE mail_id IN "
                         "(SELECT id FROM mails WHERE account_id = ?)", (account_id,))
            conn.execute("DELETE FROM mails WHERE account_id = ?", (account_id,))
            conn.execute("DELETE FROM sync_cursors WHERE account_id = ?", (account_id,))
            conn.execute("DELETE FROM credentials WHERE id = ?", (account_id,))
            conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))

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

    def folder_uid_validities(self, account_id: str, folder: str = "INBOX") -> set[int]:
        """本地已入库邮件记录的 UIDVALIDITY 集合。

        与服务端当前值不一致即说明邮箱已被重建，本地副本全部失效。
        """
        rows = self.db.query_all(
            "SELECT DISTINCT uid_validity FROM mails WHERE account_id = ? AND folder = ?",
            (account_id, folder),
        )
        return {int(r["uid_validity"] or 0) for r in rows}

    def purge_folder(self, account_id: str, folder: str = "INBOX") -> int:
        """删除某账号某文件夹的全部本地副本（UIDVALIDITY 变化时调用）。

        返回被删除的邮件行数。附件行随事务一并清理。
        """
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
        return removed

    def insert_mail(self, account_id: str, platform: str,
                    mail: NormalizedMail, uid_validity: int | None = None) -> str | None:
        """写入一封邮件（含附件元数据），返回 mail_id；已存在则返回 None。"""
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

    def update_body(self, mail_id: str, body_text: str, body_html: str) -> None:
        self.db.execute(
            "UPDATE mails SET body_text = ?, body_html = ? WHERE id = ?",
            (body_text, body_html, mail_id),
        )

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

    def delete(self, mail_id: str) -> None:
        self.db.execute("DELETE FROM attachments WHERE mail_id = ?", (mail_id,))
        self.db.execute("DELETE FROM mails WHERE id = ?", (mail_id,))

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

    def query(self, flt: MailFilter) -> list[Mail]:
        sql = ["SELECT * FROM mails WHERE 1=1"]
        params: list = []
        if flt.account_id:
            sql.append("AND account_id = ?")
            params.append(flt.account_id)
        if flt.platform:
            sql.append("AND platform = ?")
            params.append(flt.platform)
        if flt.keyword:
            sql.append("AND (subject LIKE ? OR from_addr LIKE ? OR from_name LIKE ? "
                       "OR preview LIKE ? OR body_text LIKE ?)")
            kw = f"%{flt.keyword}%"
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
        rows = self.db.query_all(" ".join(sql), params)
        return [Mail.from_row(r) for r in rows]

    def count_by_account(self) -> dict[str, tuple[int, int]]:
        """返回 {account_id: (total, unread)}。"""
        rows = self.db.query_all(
            "SELECT account_id, COUNT(*) AS total, "
            "SUM(CASE WHEN is_read = 0 THEN 1 ELSE 0 END) AS unread "
            "FROM mails GROUP BY account_id"
        )
        return {
            r["account_id"]: (int(r["total"] or 0), int(r["unread"] or 0)) for r in rows
        }

    def count_all(self) -> tuple[int, int]:
        row = self.db.query_one(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN is_read = 0 THEN 1 ELSE 0 END) AS unread FROM mails"
        )
        if not row:
            return 0, 0
        return int(row["total"] or 0), int(row["unread"] or 0)


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

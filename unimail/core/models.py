"""领域模型：内存中的数据结构定义。"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


def new_id() -> str:
    return uuid.uuid4().hex


class AccountStatus(str, Enum):
    OK = "ok"
    SYNCING = "syncing"
    ERROR = "error"
    DISABLED = "disabled"


def _parse_dt(value: Any) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return None


@dataclass
class Account:
    """一个已绑定的邮箱账号。"""
    id: str
    platform: str
    email: str
    display_name: str = ""
    imap_host: str = ""
    imap_port: int = 993
    use_ssl: bool = True
    username: str = ""
    sync_interval: int = 300
    last_synced_at: datetime | None = None
    status: str = AccountStatus.OK.value
    unread_count: int = 0          # 运行时统计，非持久化
    total_count: int = 0

    @classmethod
    def from_row(cls, row: dict) -> "Account":
        return cls(
            id=row["id"],
            platform=row["platform"],
            email=row["email"],
            display_name=row.get("display_name") or "",
            imap_host=row["imap_host"],
            imap_port=row["imap_port"],
            use_ssl=bool(row["use_ssl"]),
            username=row["username"],
            sync_interval=row.get("sync_interval") or 300,
            last_synced_at=_parse_dt(row.get("last_synced_at")),
            status=row.get("status") or AccountStatus.OK.value,
        )

    @property
    def label(self) -> str:
        return self.display_name or self.email


@dataclass
class AccountDraft:
    """添加账号时的输入载体（含明文密码，仅存活于内存）。"""
    platform: str
    email: str
    password: str
    display_name: str = ""
    imap_host: str = ""
    imap_port: int = 993
    use_ssl: bool = True
    sync_interval: int = 300

    @property
    def username(self) -> str:
        return self.email


@dataclass
class AttachmentMeta:
    """从 MIME 结构解析出的附件元信息（未下载）。"""
    filename: str
    content_type: str
    size: int
    content_id: str | None = None
    part_index: str = ""       # IMAP part 编号，用于按需下载


@dataclass
class Attachment:
    id: str
    mail_id: str
    filename: str
    content_type: str
    size: int
    stored_path: str | None = None
    content_id: str | None = None
    part_index: str = ""      # IMAP part 编号，用于按需下载

    @classmethod
    def from_row(cls, row: dict) -> "Attachment":
        return cls(
            id=row["id"],
            mail_id=row["mail_id"],
            filename=row.get("filename") or "(未命名)",
            content_type=row.get("content_type") or "application/octet-stream",
            size=row.get("size") or 0,
            stored_path=row.get("stored_path"),
            content_id=row.get("content_id"),
            part_index=row.get("part_index") or "",
        )


@dataclass
class Mail:
    """统一邮件模型（已落库）。"""
    id: str
    account_id: str
    platform: str
    folder: str
    uid: str
    message_id: str = ""
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    to_addrs: list[str] = field(default_factory=list)
    date: datetime | None = None
    preview: str = ""
    body_text: str = ""
    body_html: str = ""
    has_attachments: bool = False
    is_read: bool = False
    is_starred: bool = False
    raw_size: int = 0
    attachments: list[Attachment] = field(default_factory=list)

    @classmethod
    def from_row(cls, row: dict) -> "Mail":
        import json
        try:
            to_addrs = json.loads(row.get("to_addrs") or "[]")
        except (ValueError, TypeError):
            to_addrs = []
        return cls(
            id=row["id"],
            account_id=row["account_id"],
            platform=row["platform"],
            folder=row.get("folder") or "INBOX",
            uid=str(row["uid"]),
            message_id=row.get("message_id") or "",
            subject=row.get("subject") or "(无主题)",
            from_name=row.get("from_name") or "",
            from_addr=row.get("from_addr") or "",
            to_addrs=to_addrs if isinstance(to_addrs, list) else [],
            date=_parse_dt(row.get("date")),
            preview=row.get("preview") or "",
            body_text=row.get("body_text") or "",
            body_html=row.get("body_html") or "",
            has_attachments=bool(row.get("has_attachments")),
            is_read=bool(row.get("is_read")),
            is_starred=bool(row.get("is_starred")),
            raw_size=row.get("raw_size") or 0,
        )

    @property
    def sender_display(self) -> str:
        return self.from_name or self.from_addr or "(未知发件人)"


@dataclass
class NormalizedMail:
    """平台适配层输出：统一的、尚未落库的邮件对象。"""
    uid: str
    folder: str = "INBOX"
    message_id: str = ""
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    to_addrs: list[str] = field(default_factory=list)
    date: datetime | None = None
    body_text: str = ""
    body_html: str = ""
    preview: str = ""
    attachments: list[AttachmentMeta] = field(default_factory=list)
    raw_size: int = 0


@dataclass
class MailFilter:
    """收件箱筛选条件。"""
    account_id: str | None = None      # None = 全部账号
    platform: str | None = None        # None = 全部平台
    keyword: str = ""
    date_from: datetime | None = None
    date_to: datetime | None = None
    unread_only: bool = False
    limit: int = 300

"""领域模型：内存中的数据结构定义。"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


def new_id() -> str:
    return uuid.uuid4().hex


# 判定「是否像真实邮箱地址」的正则。用于自动学习阶段过滤掉明显不是邮箱的
# from_addr（如 `=?utf-8?...?=` 解码残留、`noreply`、`MAILER-DAEMON`、
# 空白、`root@localhost` 这类本机回环名）。
#
# 要求：一个「本地部分@域」，域至少含一个点。这样 `root@localhost`、`a@b`
# 这类没有真实域后缀的字符串不会被当成联系人学进来。本地部分允许常见的
# `+`（Gmail 别名）与 `.`，域名允许连字符与多段。
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


def is_email_like(value: str | None) -> bool:
    """宽松地判断一个字符串是否可作联系人邮箱。

    自动学习是「顺手收集」，误收比漏收更糟（通讯录会被噪声污染），
    所以这里宁可严格一点。只在有 `@` 且域含点的完整地址上返回 True。
    """
    if not value:
        return False
    return bool(_EMAIL_RE.match(value.strip()))


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


def _load_str_list(value: Any) -> list[str]:
    """把库里存的 JSON 数组读成 str 列表；任何异常形态都退化为空列表。

    引用链字段（`ref_ids` / `in_reply_to`）是老库迁移后才出现的列，
    手改过库、或早期版本写入的脏值都可能不是合法 JSON——不能因此让整封邮件读不出来。
    """
    if not value:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v]
    try:
        parsed = json.loads(str(value))
    except (ValueError, TypeError):
        return []
    if isinstance(parsed, list):
        return [str(v) for v in parsed if v]
    return []


# 公开别名：仓储层也要把 JSON 列读成 str 列表，不必各写一份容错逻辑。
load_str_list = _load_str_list


PREVIEW_LIMIT = 200


def make_preview(text: str | None, limit: int = PREVIEW_LIMIT) -> str:
    """把正文压成单行摘要（列表展示与全文检索共用）。

    放在 core 层而不是解析层：正文回填（`update_body`）也必须刷新预览，
    而存储层不应依赖 `platforms`。摘要逻辑只有这一份实现。
    """
    flat = re.sub(r"\s+", " ", text or "").strip()
    return flat[:limit] + ("…" if len(flat) > limit else "")


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
    # 凭据类型：password（授权码/应用密码）或 oauth2_<platform>。
    # 它不是「界面选项」而是**认证协议的选择**：OAuth2 账号的凭据栏里
    # 存的是 refresh_token，登录走 `AUTHENTICATE XOAUTH2` 而不是 `LOGIN`。
    auth_type: str = "password"
    # SMTP 覆盖值。空 = 从 imap_host 推断（imap.qq.com → smtp.qq.com）。
    # 自定义 IMAP 必须显式填：自建服务器的 SMTP 与 IMAP 没有必然关系。
    smtp_host: str = ""
    smtp_port: int = 0
    unread_count: int = 0          # 运行时统计，非持久化
    total_count: int = 0

    @classmethod
    def from_row(cls, row: dict) -> Account:
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
            auth_type=row.get("auth_type") or "password",
            smtp_host=row.get("smtp_host") or "",
            smtp_port=int(row.get("smtp_port") or 0),
        )

    @property
    def label(self) -> str:
        return self.display_name or self.email


@dataclass
class AccountDraft:
    """添加账号时的输入载体（含明文密码/令牌，仅存活于内存）。"""
    platform: str
    email: str
    password: str
    display_name: str = ""
    imap_host: str = ""
    imap_port: int = 993
    use_ssl: bool = True
    sync_interval: int = 300
    # password 或 oauth2_<platform>。OAuth2 时 `password` 字段承载
    # refresh_token（仍然只在内存里短暂存在，落库前一律加密）。
    auth_type: str = "password"

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
    def from_row(cls, row: dict) -> Attachment:
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
    # 会话（线程）归并：`references` / `in_reply_to` 存的是 message-id 列表，
    # 落库列名为 `ref_ids` / `in_reply_to`（`references` 是 SQLite 保留字）。
    references: list[str] = field(default_factory=list)
    in_reply_to: list[str] = field(default_factory=list)
    thread_key: str = ""
    attachments: list[Attachment] = field(default_factory=list)

    @classmethod
    def from_row(cls, row: dict) -> Mail:
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
            references=_load_str_list(row.get("ref_ids")),
            in_reply_to=_load_str_list(row.get("in_reply_to")),
            thread_key=row.get("thread_key") or "",
        )

    @property
    def sender_display(self) -> str:
        return self.from_name or self.from_addr or "(未知发件人)"

    def to_summary(self) -> MailSummary:
        """降级为列表投影（丢弃正文与附件明细）。"""
        return MailSummary(
            id=self.id,
            account_id=self.account_id,
            platform=self.platform,
            folder=self.folder,
            uid=self.uid,
            subject=self.subject,
            from_name=self.from_name,
            from_addr=self.from_addr,
            date=self.date,
            preview=self.preview,
            has_attachments=self.has_attachments,
            is_read=self.is_read,
            is_starred=self.is_starred,
            raw_size=self.raw_size,
            thread_key=self.thread_key,
        )


@dataclass
class MailSummary:
    """列表投影：只含表格渲染需要的字段，**不含正文与附件明细**。

    列表是应用里刷新最频繁的视图，而 `body_html` 单封可达上百 KB。
    此前列表直接持有完整 `Mail`，300 行即是数十 MB 常驻内存，且每次筛选
    都要重新反序列化这些大字段。列表只需要下面这十几个标量字段；
    正文/附件在真正点开某封邮件时按 id 单独取（`MailService.get`）。
    """
    id: str
    account_id: str
    platform: str
    folder: str
    uid: str
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    date: datetime | None = None
    preview: str = ""
    has_attachments: bool = False
    is_read: bool = False
    is_starred: bool = False
    raw_size: int = 0
    thread_key: str = ""

    @classmethod
    def from_row(cls, row: dict) -> MailSummary:
        return cls(
            id=row["id"],
            account_id=row["account_id"],
            platform=row["platform"],
            folder=row.get("folder") or "INBOX",
            uid=str(row["uid"]),
            subject=row.get("subject") or "(无主题)",
            from_name=row.get("from_name") or "",
            from_addr=row.get("from_addr") or "",
            date=_parse_dt(row.get("date")),
            preview=row.get("preview") or "",
            has_attachments=bool(row.get("has_attachments")),
            is_read=bool(row.get("is_read")),
            is_starred=bool(row.get("is_starred")),
            raw_size=row.get("raw_size") or 0,
            thread_key=row.get("thread_key") or "",
        )

    @property
    def sender_display(self) -> str:
        return self.from_name or self.from_addr or "(未知发件人)"


# 列表投影所需的列（与 MailSummary.from_row 一一对应）。
MAIL_SUMMARY_COLUMNS = (
    "id", "account_id", "platform", "folder", "uid", "subject",
    "from_name", "from_addr", "date", "preview",
    "has_attachments", "is_read", "is_starred", "raw_size", "thread_key",
)


@dataclass
class ThreadSummary:
    """会话（线程）投影：折叠态显示「最新一封 + 组内统计」。

    归并键是 `thread_key`（由 References / In-Reply-To 推出，见解析层）。
    这里刻意组合而不是继承 `MailSummary`：折叠行需要额外两个统计量，
    而 `from_row` 要多读两列，继承会让「上下文列」与「投影列」的映射变模糊。
    """
    latest: MailSummary
    total: int = 1
    unread: int = 0

    @property
    def thread_key(self) -> str:
        return self.latest.thread_key or self.latest.id

    @property
    def id(self) -> str:
        return self.latest.id

    @property
    def is_read(self) -> bool:
        return self.unread == 0

    @classmethod
    def from_row(cls, row: dict) -> ThreadSummary:
        return cls(
            latest=MailSummary.from_row(row),
            total=int(row.get("_total") or 1),
            unread=int(row.get("_unread") or 0),
        )


@dataclass
class PendingFlag:
    """一条待回写服务器的「标已读 / 星标」变更（离线队列）。"""
    id: str
    account_id: str
    folder: str
    uid: str
    add_flags: list[str] = field(default_factory=list)
    remove_flags: list[str] = field(default_factory=list)
    created_at: str = ""

    @classmethod
    def from_row(cls, row: dict) -> PendingFlag:
        return cls(
            id=row["id"],
            account_id=row["account_id"],
            folder=row.get("folder") or "INBOX",
            uid=str(row["uid"]),
            add_flags=_load_str_list(row.get("add_flags")),
            remove_flags=_load_str_list(row.get("remove_flags")),
            created_at=row.get("created_at") or "",
        )


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
    # 会话归并（解析层产出）：References / In-Reply-To 里的 message-id 列表，
    # 以及算好的归并键。三者都缺失时 `thread_key` 为空，由落库侧用 mail_id 兜底。
    references: list[str] = field(default_factory=list)
    in_reply_to: list[str] = field(default_factory=list)
    thread_key: str = ""


@dataclass
class MailFilter:
    """收件箱筛选条件。"""
    account_id: str | None = None      # None = 全部账号
    platform: str | None = None        # None = 全部平台
    folder: str | None = None          # None = 全部文件夹；否则只取该文件夹
    keyword: str = ""
    # ---- 结构化搜索（from:/to:/subject:/has:/is: 前缀语法）----
    from_addr: str = ""                # 模糊匹配 from_addr / from_name
    to_addr: str = ""                  # 模糊匹配 to_addrs
    subject: str = ""                  # 模糊匹配 subject
    has_attachment: bool | None = None # has:attachment / None=不过滤
    starred_only: bool | None = None   # is:starred / None=不过滤
    date_from: datetime | None = None
    date_to: datetime | None = None
    unread_only: bool = False
    limit: int = 200
    # ---- keyset 分页游标（列表视图滚动加载）----
    # 只取「严格排在 (before_date, before_id) 之后」的行。
    # 不用 OFFSET：10 万封时 OFFSET 要先扫过前 N 行，而且同步进来的新邮件
    # 会让已经翻过的位置整体错位（要么重复、要么漏行）。
    # id 是必需的 tie-break —— 同一秒到达的多封邮件必须有稳定次序，
    # 否则边界那一行会在两页里各出现一次（或都不出现）。
    before_date: datetime | None = None
    before_id: str | None = None
    # ---- 服务端排序 ----
    # 只在当前页内排序会把「按发件人排序」变成误导：用户看到的是
    # 「已加载的 200 封里的顺序」。排序必须下推到 SQL。
    order: str = "date"                # 白名单：date/sender/subject/platform/read/starred
    desc: bool = True


# ---------------------------------------------------------------- 发信（outbox）
# 发信状态机的四个状态。刻意与「同步」的状态机分开：发送是一次性的
# 短连接动作，失败重试的语义是「这封还没出去」，而不是「这封的状态要回写」。
OUTBOX_PENDING = "pending"        # 已入队，尚未发送
OUTBOX_SENDING = "sending"        # 正在发送（崩溃后重启会被回收重试）
OUTBOX_SENT = "sent"              # 服务器已接收
OUTBOX_FAILED = "failed"          # 发送失败（保留原文与错误，供用户重试）


@dataclass
class OutboxMessage:
    """一封待发 / 已发的邮件。

    为什么整封邮件原文入库而不是只存「收件人 + 主题」
    -------------------------------------------------
    发送失败时用户需要能**原样重发**，包括附件。附件是二进制，单独存一张表
    会让「重发」变成一次跨表重组，而重组过程任何一步出错都会产出一封
    「少了附件」的邮件——那比发不出去更糟（对方以为附件是空的）。
    因此这里存完整的 RFC 5322 原文（`raw`），发送时原样交给 SMTP，
    重发时原样再交给 SMTP，中间不做任何解析与重组。

    `raw` 是明文：outbox 表在加密数据库里（整库 AES-256），
    与 credentials 同级保护，不额外加密。
    """
    id: str
    account_id: str
    status: str = OUTBOX_PENDING
    subject: str = ""
    to_addrs: str = ""              # 逗号分隔，仅用于列表展示
    in_reply_to: str = ""
    # 列名叫 ref_chain 而非 references：后者是 SQLite 保留字
    # （`near "references": syntax error`，v5 已为同一原因避开一次）。
    ref_chain: str = ""             # 空格分隔的 message-id 链
    raw: str = ""                   # 完整 RFC 5322 原文
    error: str = ""
    attempts: int = 0
    created_at: str = ""
    sent_at: str = ""

    @classmethod
    def from_row(cls, row: dict) -> OutboxMessage:
        return cls(
            id=row["id"],
            account_id=row["account_id"],
            status=row.get("status") or OUTBOX_PENDING,
            subject=row.get("subject") or "",
            to_addrs=row.get("to_addrs") or "",
            in_reply_to=row.get("in_reply_to") or "",
            ref_chain=row.get("ref_chain") or "",
            raw=row.get("raw") or "",
            error=row.get("error") or "",
            attempts=int(row.get("attempts") or 0),
            created_at=row.get("created_at") or "",
            sent_at=row.get("sent_at") or "",
        )


@dataclass
class Contact:
    """一条通讯录记录。

    来源有两个（都落在同一张表、由 email 唯一约束去重）：
      1. **自动学习**：同步/读信时从邮件发件人收集，name 只增不删、只长不短；
      2. **手动添加**：用户在通讯录对话框里新建，可带备注、可不关联账号。

    account_id 仅作「这人是哪个账号往来过的」提示信息，删账号不会删联系人
    （外键 ON DELETE SET NULL），所以它可能为 None，UI 要能正常显示。
    """
    id: str
    email: str
    name: str = ""
    account_id: str | None = None
    note: str = ""
    created_at: str = ""
    updated_at: str = ""

    @classmethod
    def from_row(cls, row: dict) -> Contact:
        return cls(
            id=row["id"],
            email=row["email"],
            name=row.get("name") or "",
            account_id=row.get("account_id"),
            note=row.get("note") or "",
            created_at=row.get("created_at") or "",
            updated_at=row.get("updated_at") or "",
        )

    @property
    def label(self) -> str:
        """列表展示名：有名显示名，无名退化为邮箱（与 Account.label 同策略）。"""
        return self.name or self.email

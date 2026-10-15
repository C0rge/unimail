"""应用服务层：用例编排（账号管理、邮件查询、附件）。"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from ..config import ATTACHMENT_DIR, DEFAULT_SYNC_INTERVAL, PLATFORMS
from ..platforms import ImapError, get_adapter, make_account_stub
from ..storage import (
    AccountRepository,
    AttachmentRepository,
    CursorRepository,
    MailRepository,
)
from .events import EventBus
from .models import Account, AccountDraft, AccountStatus, Mail, MailFilter
from .security import SecurityError, SecurityService

log = logging.getLogger(__name__)

_UNSAFE_FILENAME = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


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
        self.accounts.delete(account_id)
        if self._active_id == account_id:
            self._active_id = None
        log.info("已删除账号 %s", account.email if account else account_id)
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

    # ------------------------------------------------------------ 查询
    def inbox(self, flt: MailFilter) -> list[Mail]:
        return self.mails.query(flt)

    def get(self, mail_id: str) -> Mail | None:
        return self.mails.get(mail_id)

    def counts(self) -> dict[str, tuple[int, int]]:
        return self.mails.count_by_account()

    def total_counts(self) -> tuple[int, int]:
        return self.mails.count_all()

    # ------------------------------------------------------------ 状态
    def mark_read(self, mail_id: str, is_read: bool = True) -> None:
        self.mails.set_read(mail_id, is_read)
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
        self.bus.accounts_changed.emit()

    def delete(self, mail_id: str) -> None:
        self.mails.delete(mail_id)
        self.bus.mail_deleted.emit(mail_id)

    # ------------------------------------------------------------ 附件
    def download_attachment(self, attachment_id: str) -> Path:
        """从 IMAP 服务器拉取附件真实字节流并落盘。

        流程：查附件所属邮件的 account/folder/uid/part_index
              → 取该账号凭据 → 连接 IMAP → FETCH BODY[part] → 解码 → 写盘
        """
        att = self.attachments.get(attachment_id)
        if att is None:
            raise FileNotFoundError("附件记录不存在")

        # 已下载过则直接复用
        if att.stored_path and Path(att.stored_path).exists():
            return Path(att.stored_path)

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
            try:
                imap.select(ctx["folder"] or "INBOX", readonly=True)
            except Exception:  # noqa: BLE001
                pass
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

        safe = _UNSAFE_FILENAME.sub("_", att.filename or "attachment.bin")
        target = ATTACHMENT_DIR / f"{att.id[:8]}_{safe}"
        target.write_bytes(data)
        self.attachments.set_stored_path(attachment_id, str(target))
        log.info("附件已下载：%s (%d 字节)", target.name, len(data))
        return target

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
            if payload:
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

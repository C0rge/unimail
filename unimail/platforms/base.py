"""平台适配层基类与注册表。

所有平台差异（服务器参数、特殊命令、编码处理）都收敛在 Adapter 内部，
上层只面对统一的 NormalizedMail 与标准 IMAP 操作。
"""
from __future__ import annotations

import imaplib
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import timedelta

from ..config import FETCH_TIMEOUT, PLATFORMS, PlatformConfig
from ..core.models import Account, NormalizedMail
from . import parser

log = logging.getLogger(__name__)

imaplib._MAXLINE = 10_000_000  # type: ignore[attr-defined]  # 大邮件头


class ImapError(Exception):
    """IMAP 连接或操作失败（面向用户的可读错误）。"""


@dataclass
class Folder:
    name: str
    display: str


class ImapAdapter(ABC):
    """IMAP 平台适配器抽象基类。"""

    platform: str = "custom"

    def __init__(self, config: PlatformConfig | None = None) -> None:
        self.config = config or PLATFORMS.get(self.platform, PLATFORMS["custom"])

    # ------------------------------------------------------------ 连接
    def connect(self, account: Account, password: str) -> imaplib.IMAP4:
        host = account.imap_host or self.config.imap_host
        port = account.imap_port or self.config.imap_port
        if not host:
            raise ImapError("未配置 IMAP 服务器地址")

        try:
            if account.use_ssl:
                imap = imaplib.IMAP4_SSL(host, port, timeout=FETCH_TIMEOUT)
            else:
                imap = imaplib.IMAP4(host, port, timeout=FETCH_TIMEOUT)
                if port == 143:
                    try:
                        imap.starttls()
                    except (imaplib.IMAP4.error, OSError):
                        pass
        except OSError as exc:
            raise ImapError(f"无法连接 {host}:{port} — {exc}") from exc
        except imaplib.IMAP4.error as exc:
            raise ImapError(f"IMAP 握手失败：{exc}") from exc

        try:
            imap.login(account.username or account.email, password)
        except imaplib.IMAP4.error as exc:
            raise ImapError(self._login_error_hint(exc)) from exc
        except OSError as exc:
            raise ImapError(f"登录过程中连接中断：{exc}") from exc

        try:
            imap.select("INBOX", readonly=True)
        except imaplib.IMAP4.error:
            pass
        self.post_login(imap)
        return imap

    def _login_error_hint(self, exc: Exception) -> str:
        return (f"登录被拒绝：{exc}\n提示：{self.config.auth_hint}")

    def post_login(self, imap: imaplib.IMAP4) -> None:
        """登录后的平台特殊处理，默认空实现。"""
        return None

    @staticmethod
    def disconnect(imap: imaplib.IMAP4 | None) -> None:
        if imap is None:
            return
        try:
            imap.close()
        except (imaplib.IMAP4.error, OSError):
            pass
        try:
            imap.logout()
        except (imaplib.IMAP4.error, OSError):
            pass

    # ------------------------------------------------------------ 探测
    def verify(self, account: Account, password: str) -> None:
        """试连校验凭据，失败抛 ImapError。"""
        imap = None
        try:
            imap = self.connect(account, password)
        finally:
            self.disconnect(imap)

    def probe(self) -> tuple[int, int]:
        """返回 (邮件总数, 未读数) 用于连通性状态展示。"""
        raise NotImplementedError

    # ------------------------------------------------------------ 文件夹
    def list_folders(self, imap: imaplib.IMAP4) -> list[Folder]:
        try:
            typ, data = imap.list()
        except imaplib.IMAP4.error as exc:
            raise ImapError(f"获取文件夹失败：{exc}") from exc
        folders: list[Folder] = []
        for line in data or []:
            if not line:
                continue
            text = line.decode("utf-8", errors="replace") if isinstance(line, bytes) else str(line)
            # 形如: (\HasNoChildren) "/" "INBOX"
            parts = text.split(' "/" ')
            if len(parts) >= 2:
                name = parts[-1].strip().strip('"')
                folders.append(Folder(name=name, display=name))
        return folders or [Folder("INBOX", "收件箱")]

    # ------------------------------------------------------------ 邮件
    def search_new_uids(self, imap: imaplib.IMAP4, since_uid: int,
                        limit: int = 200) -> list[str]:
        """查询 UID > since_uid 的邮件，返回升序 UID 列表（最多 limit 条）。"""
        try:
            imap.select("INBOX", readonly=True)
            if since_uid > 0:
                typ, data = imap.uid("SEARCH", None, f"UID {since_uid + 1}:*")
            else:
                typ, data = imap.uid("SEARCH", None, "ALL")
        except imaplib.IMAP4.error as exc:
            raise ImapError(f"搜索邮件失败：{exc}") from exc
        if typ != "OK" or not data or not data[0]:
            return []
        uids = sorted(int(u) for u in data[0].split())
        uids = [u for u in uids if u > since_uid]
        return [str(u) for u in uids[-limit:]]

    def fetch_raw(self, imap: imaplib.IMAP4, uid: str,
                  headers_only: bool = False) -> bytes:
        """拉取单封邮件原文。headers_only=True 时只取头部。"""
        spec = "(BODY.PEEK[HEADER])" if headers_only else "(BODY.PEEK[])"
        try:
            typ, data = imap.uid("FETCH", uid, spec)
        except imaplib.IMAP4.error as exc:
            raise ImapError(f"拉取邮件 {uid} 失败：{exc}") from exc
        if typ != "OK" or not data:
            raise ImapError(f"拉取邮件 {uid} 失败")
        for item in data:
            if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
                return item[1]
        raise ImapError(f"邮件 {uid} 返回数据为空")

    def fetch_headers(self, imap: imaplib.IMAP4, uid: str,
                      folder: str = "INBOX") -> NormalizedMail:
        raw = self.fetch_raw(imap, uid, headers_only=True)
        return parser.parse_headers_only(raw, uid, folder)

    def fetch_message(self, imap: imaplib.IMAP4, uid: str,
                      folder: str = "INBOX") -> NormalizedMail:
        raw = self.fetch_raw(imap, uid, headers_only=False)
        return parser.parse_message(raw, uid, folder)

    def fetch_attachment(self, imap: imaplib.IMAP4, uid: str,
                         part_index: str) -> bytes:
        """按 part 编号下载附件内容。"""
        try:
            typ, data = imap.uid("FETCH", uid, f"(BODY.PEEK[{part_index}])")
        except imaplib.IMAP4.error as exc:
            raise ImapError(f"下载附件失败：{exc}") from exc
        if typ != "OK" or not data:
            raise ImapError("下载附件失败")
        for item in data:
            if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
                return item[1]
        return b""

    def uid_validity(self, imap: imaplib.IMAP4) -> int | None:
        try:
            typ, data = imap.status("INBOX", "(UIDVALIDITY)")
            if typ == "OK" and data:
                text = data[0].decode() if isinstance(data[0], bytes) else str(data[0])
                if "UIDVALIDITY" in text.upper():
                    return int(text.split()[-1].strip(")"))
        except (imaplib.IMAP4.error, ValueError, IndexError):
            pass
        return None


def make_account_stub(draft) -> Account:
    """从 AccountDraft 构造一个未落库的 Account，用于试连。"""
    cfg = PLATFORMS.get(draft.platform)
    return Account(
        id="__probe__",
        platform=draft.platform,
        email=draft.email,
        display_name=draft.display_name,
        imap_host=draft.imap_host or (cfg.imap_host if cfg else ""),
        imap_port=draft.imap_port or (cfg.imap_port if cfg else 993),
        use_ssl=draft.use_ssl,
        username=draft.username,
        sync_interval=draft.sync_interval,
    )

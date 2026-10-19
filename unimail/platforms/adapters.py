"""各邮箱平台适配器实现。

每个类只需声明 platform 并覆盖可能的差异点（特殊命令、编码、文件夹命名）。
"""
from __future__ import annotations

import imaplib
import logging

from ..config import APP_VERSION
from ..core.models import Account
from .base import ImapAdapter, parse_list_line, utf7_decode

log = logging.getLogger(__name__)


class QQMailAdapter(ImapAdapter):
    """QQ 邮箱。

    差异点：
      - 认证使用授权码（在配置提示中已说明）
      - 文件夹名为中文（如「已发送」），部分场景返回 GBK 编码
    """

    platform = "qq"

    def list_folders(self, imap: imaplib.IMAP4):
        try:
            _typ, data = imap.list()
            folders = []
            for line in data or []:
                if not line:
                    continue
                raw = line if isinstance(line, bytes) else str(line).encode()
                # QQ 部分文件夹名以 modified UTF-7 编码。注意这里用的是
                # base.utf7_decode（协议用的 `+,` 位移），而不是内置 `utf-7`
                # 解码器——后者认的是 `+/`，会把中文名解成乱码。
                if b"&" in raw:
                    text = utf7_decode(raw.decode("ascii", errors="replace"))
                else:
                    text = raw.decode("gb18030", errors="replace")
                parsed = parse_list_line(text)
                if parsed is not None:
                    flags, name = parsed
                    if name:
                        folders.append(self._folder(name, flags))
                    continue
                parts = text.split(' "/" ')
                if len(parts) >= 2:
                    name = parts[-1].strip().strip('"')
                    folders.append(self._folder(name))
            return folders or super().list_folders(imap)
        except imaplib.IMAP4.error:
            return super().list_folders(imap)

    @staticmethod
    def _folder(name: str, flags: frozenset[str] = frozenset()):
        from .base import Folder
        mapping = {
            "INBOX": "收件箱", "Sent Messages": "已发送", "Drafts": "草稿箱",
            "Deleted Messages": "已删除", "Junk": "垃圾邮件",
        }
        return Folder(name=name, display=mapping.get(name, name), flags=flags)


class Net163Adapter(ImapAdapter):
    """网易 163 邮箱。

    差异点：
      - 网易要求客户端在登录后发送 IMAP ID 命令，否则返回
        "Unsafe Login. Please contact kefu@188.com" 错误。
    """

    platform = "163"

    def post_login(self, imap: imaplib.IMAP4) -> None:
        try:
            imap.xatom(
                "ID",
                f'("name" "UniMail" "version" "{APP_VERSION}" '
                '"vendor" "UniMail" "support-email" "unimail@example.com")',
            )
            log.debug("163: 已发送 IMAP ID")
        except (imaplib.IMAP4.error, AttributeError) as exc:
            log.debug("163: 发送 ID 命令失败（可忽略）: %s", exc)


class GmailAdapter(ImapAdapter):
    """Gmail。

    差异点：
      - 使用应用专用密码
      - 支持 X-GM-EXT-1 扩展（可读 Gmail 标签 / 是否已读）
    """

    platform = "gmail"

    def list_folders(self, imap: imaplib.IMAP4):
        folders = super().list_folders(imap)
        mapping = {
            "[Gmail]/All Mail": "所有邮件",
            "[Gmail]/Sent Mail": "已发送",
            "[Gmail]/Drafts": "草稿",
            "[Gmail]/Spam": "垃圾邮件",
            "[Gmail]/Trash": "回收站",
            "[Gmail]/Important": "重要",
            "[Gmail]/Starred": "已加星标",
        }
        from .base import Folder
        out = []
        for f in folders:
            # 保留 LIST 属性（`\Trash` 等）——垃圾箱定位依赖它，
            # 只做显示名替换不该把它丢掉。
            out.append(Folder(f.name, mapping.get(f.name, f.display), f.flags))
        return out


class OutlookAdapter(ImapAdapter):
    """Outlook / Microsoft 365。

    微软已于 2024-09-16 停用个人 Outlook.com 的 IMAP 基础认证（Exchange
    Online 更早），应用密码在这条路上不再被接受——只能走 OAuth2 + XOAUTH2。
    错误提示必须指向「重新授权」，而不是继续引导用户去生成已失效的应用密码。
    """

    platform = "outlook"

    def _login_error_hint(self, exc: Exception,
                          account: Account | None = None) -> str:
        if account is not None and str(
                getattr(account, "auth_type", "")).startswith("oauth2"):
            return (
                f"OAuth2 登录被拒绝：{exc}\n"
                "授权可能已过期、被管理员撤销，或该账号未开启 IMAP。"
                "请删除该账号后重新用「OAuth2 授权」添加。"
            )
        return (
            f"登录被拒绝：{exc}\n"
            "微软已停用 IMAP 基础认证，应用密码不再可用。\n"
            "请用添加账号对话框里的「OAuth2 授权…」登录；"
            "企业租户还需管理员为该账号开启 IMAP。"
        )


class CustomImapAdapter(ImapAdapter):
    """自定义 IMAP 服务器。"""

    platform = "custom"


_ADAPTERS = {
    "qq": QQMailAdapter,
    "163": Net163Adapter,
    "gmail": GmailAdapter,
    "outlook": OutlookAdapter,
    "custom": CustomImapAdapter,
}


def get_adapter(platform: str) -> ImapAdapter:
    """按平台 key 获取适配器实例。未知平台回退到自定义 IMAP。"""
    cls = _ADAPTERS.get(platform, CustomImapAdapter)
    return cls()


def all_platforms() -> list[str]:
    return list(_ADAPTERS.keys())

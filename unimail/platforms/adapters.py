"""各邮箱平台适配器实现。

每个类只需声明 platform 并覆盖可能的差异点（特殊命令、编码、文件夹命名）。
"""
from __future__ import annotations

import imaplib
import logging

from .base import ImapAdapter

from ..config import APP_VERSION

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
            typ, data = imap.list()
            folders = []
            for line in data or []:
                if not line:
                    continue
                raw = line if isinstance(line, bytes) else str(line).encode()
                # QQ 部分文件夹名以 modified UTF-7 编码
                text = raw.decode("utf-7", errors="replace") if b"&" in raw \
                    else raw.decode("gb18030", errors="replace")
                parts = text.split(' "/" ')
                if len(parts) >= 2:
                    name = parts[-1].strip().strip('"')
                    folders.append(self._folder(name))
            return folders or super().list_folders(imap)
        except imaplib.IMAP4.error:
            return super().list_folders(imap)

    @staticmethod
    def _folder(name: str):
        from .base import Folder
        mapping = {
            "INBOX": "收件箱", "Sent Messages": "已发送", "Drafts": "草稿箱",
            "Deleted Messages": "已删除", "Junk": "垃圾邮件",
        }
        return Folder(name=name, display=mapping.get(name, name))


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
            out.append(Folder(f.name, mapping.get(f.name, f.display)))
        return out


class OutlookAdapter(ImapAdapter):
    """Outlook / Microsoft 365。

    差异点：
      - 微软已停用基础认证；如租户仍允许，可配合应用密码使用
      - 完整方案应接入 OAuth2（XOAUTH2）
    """

    platform = "outlook"

    def _login_error_hint(self, exc: Exception) -> str:
        return (
            f"登录被拒绝：{exc}\n"
            "微软已停止基础认证，请确认：\n"
            "  1) 已开启两步验证并生成「应用密码」；\n"
            "  2) 企业租户已由管理员开启 IMAP 访问。"
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

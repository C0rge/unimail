"""平台适配层基类与注册表。

所有平台差异（服务器参数、特殊命令、编码处理）都收敛在 Adapter 内部，
上层只面对统一的 NormalizedMail 与标准 IMAP 操作。
"""
from __future__ import annotations

import contextlib
import imaplib
import logging
import ssl
from dataclasses import dataclass

from ..config import ALLOW_INVALID_TLS_CERT, FETCH_TIMEOUT, PLATFORMS, PlatformConfig
from ..core.models import Account, NormalizedMail
from . import parser

log = logging.getLogger(__name__)

# 大邮件头：imaplib 默认单行上限仅 10 KB，长 References / 长主题会被静默截断。
# `_MAXLINE` 是 CPython 有意暴露的模块级开关，只能直接改模块属性。
imaplib._MAXLINE = 10_000_000  # type: ignore[attr-defined]  # noqa: SLF001


def tls_context(allow_invalid: bool = False) -> ssl.SSLContext:
    """构造 IMAP 的 TLS 上下文。

    默认**强制校验**服务器证书与主机名。若不显式传入上下文，`imaplib.IMAP4_SSL`
    会退回 `ssl._create_stdlib_context()`（`verify_mode=CERT_NONE`），
    等于对任何中间人敞开——授权码可被直接截获。

    allow_invalid=True 仅供自建服务器使用自签证书的极端场景，需显式开启。
    """
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    if allow_invalid:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class ImapError(Exception):
    """IMAP 连接或操作失败（面向用户的可读错误）。"""


@dataclass
class Folder:
    name: str
    display: str


class ImapAdapter:
    """IMAP 平台适配器。

    刻意**不**继承 `abc.ABC`：`probe()` 等方法的默认实现是抛
    `NotImplementedError`，而适配器的调用方只依赖 `connect/fetch_*/search_*`
    这几个通用方法，抽象基类在这里只会造成「子类必须实现全部抽象方法」的
    过度约束（例如仅用于解析单测的轻量子类）。
    """

    platform: str = "custom"

    def __init__(self, config: PlatformConfig | None = None) -> None:
        self.config = config or PLATFORMS.get(self.platform, PLATFORMS["custom"])

    # ------------------------------------------------------------ 连接
    def connect(self, account: Account, password: str) -> imaplib.IMAP4:
        host = account.imap_host or self.config.imap_host
        port = account.imap_port or self.config.imap_port
        if not host:
            raise ImapError("未配置 IMAP 服务器地址")

        # 默认强制校验证书；仅由环境变量显式放行时才允许不校验
        allow_invalid = ALLOW_INVALID_TLS_CERT or bool(
            getattr(account, "allow_invalid_cert", False)
        )
        ctx = tls_context(allow_invalid)

        # 显式标注为基类：IMAP4_SSL 是 IMAP4 的子类，两个分支共用一个变量
        imap: imaplib.IMAP4
        try:
            if account.use_ssl:
                imap = imaplib.IMAP4_SSL(host, port, timeout=FETCH_TIMEOUT,
                                         ssl_context=ctx)
            else:
                imap = imaplib.IMAP4(host, port, timeout=FETCH_TIMEOUT)
                if port == 143:
                    try:
                        imap.starttls(ssl_context=ctx)
                    except ssl.SSLCertVerificationError as exc:
                        raise ImapError(self._cert_error_hint(host, exc)) from exc
                    except (imaplib.IMAP4.error, ssl.SSLError, OSError) as exc:
                        # 不再静默降级为明文：用户配置的是 STARTTLS 端口，
                        # 握手失败说明无法建立可信通道。
                        raise ImapError(
                            f"与 {host}:{port} 的 STARTTLS 握手失败：{exc}\n"
                            "为避免明文传输凭据，已中止连接。若该服务器仅支持明文 IMAP，"
                            "请在账号中改用对应端口并关闭 SSL。"
                        ) from exc
        except ssl.SSLCertVerificationError as exc:
            raise ImapError(self._cert_error_hint(host, exc)) from exc
        except ssl.SSLError as exc:
            raise ImapError(f"与 {host}:{port} 的 TLS 握手失败：{exc}") from exc
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

        # select 失败不构成连接失败：后续操作会各自 select 到需要的文件夹
        with contextlib.suppress(imaplib.IMAP4.error):
            imap.select("INBOX", readonly=True)
        self.post_login(imap)
        return imap

    @staticmethod
    def _cert_error_hint(host: str, exc: Exception) -> str:
        detail = getattr(exc, "verify_message", None) or str(exc)
        return (
            f"无法验证 {host} 的服务器证书，已中止连接。\n"
            f"失败原因：{detail}\n"
            "这通常意味着网络被劫持、存在代理中间设备，或对方使用了自签证书。\n"
            "如确认是企业自建服务器且使用自签证书，可设置环境变量 "
            "UNIMAIL_ALLOW_INVALID_CERT=1 后重启（会失去中间人防护，请谨慎）。"
        )

    def _login_error_hint(self, exc: Exception) -> str:
        return (f"登录被拒绝：{exc}\n提示：{self.config.auth_hint}")

    def post_login(self, imap: imaplib.IMAP4) -> None:
        """登录后的平台特殊处理，默认空实现。"""
        return None

    @staticmethod
    def disconnect(imap: imaplib.IMAP4 | None) -> None:
        """尽力优雅退出：连接可能已断，任何一步失败都不影响调用方。"""
        if imap is None:
            return
        with contextlib.suppress(imaplib.IMAP4.error, OSError):
            imap.close()
        with contextlib.suppress(imaplib.IMAP4.error, OSError):
            imap.logout()

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
            _typ, data = imap.list()
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
        """查询 UID > since_uid 的邮件，返回**升序** UID 列表（最多 limit 条）。

        返回的是**最旧的一批**（UID 最小者优先），而不是最新的一批。
        调用方按页循环推进游标，才能保证「已抓取区间」连续、不丢中间的邮件；
        若返回最新 N 条，游标会被直接推到邮箱末尾，中间的邮件将永久不再拉取。
        """
        try:
            imap.select("INBOX", readonly=True)
            # imaplib 的 uid() 会跳过 None 参数；这里直接给检索式即可
            if since_uid > 0:
                typ, data = imap.uid("SEARCH", f"UID {since_uid + 1}:*")
            else:
                typ, data = imap.uid("SEARCH", "ALL")
        except imaplib.IMAP4.error as exc:
            raise ImapError(f"搜索邮件失败：{exc}") from exc
        if typ != "OK" or not data or not data[0]:
            return []
        uids = sorted(int(u) for u in data[0].split())
        uids = [u for u in uids if u > since_uid]
        return [str(u) for u in uids[:limit]]

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

    def fetch_attachment_meta(self, imap: imaplib.IMAP4, uids: list[str],
                              folder: str = "INBOX") -> dict[str, list]:
        """批量获取多封邮件的附件元数据（BODYSTRUCTURE，**不下载正文**）。

        为什么需要它：列表同步只 FETCH `BODY.PEEK[HEADER]`，拿到的字节里没有
        任何 MIME 部件，因此 `parse_headers_only` 永远解析不出附件——邮件在
        列表里不显示 📎，也永远不会产生可下载的附件记录。BODYSTRUCTURE 由
        服务器直接给出结构（类型/文件名/字节数），一次 FETCH 可覆盖整页 UID。

        典型开销：每页 1 次往返（而不是每封 1 次）。任何失败都返回空字典，
        绝不让「附件信息」这个附加项拖垮整次同步。
        """
        result: dict[str, list] = {}
        if not uids:
            return result
        try:
            imap.select(folder, readonly=True)
            typ, data = imap.uid(
                "FETCH", ",".join(str(u) for u in uids), "(UID BODYSTRUCTURE)"
            )
        except (imaplib.IMAP4.error, OSError) as exc:
            log.debug("获取 BODYSTRUCTURE 失败（将退回无附件信息）：%s", exc)
            return result
        if typ != "OK" or not data:
            return result

        for item in data:
            head = b""
            tail = b""
            if isinstance(item, tuple) and len(item) >= 2:
                head = item[0] if isinstance(item[0], bytes) else b""
                tail = item[1] if isinstance(item[1], bytes) else b""
            elif isinstance(item, bytes):
                head = item
            if not head and not tail:
                continue
            if b"BODYSTRUCTURE" not in head.upper() and tail:
                blob = tail          # 少数服务器把结构体放在第 2 项
            elif tail:
                # 字面量形式的响应：结构体被拆成「前缀 + {n}\r\n<字面量>」两段，
                # 只取 head 会得到括号不配平的残缺文本，必须拼回去。
                blob = head + tail
            else:
                blob = head
            uid, structure = parser.extract_bodystructure_from_fetch(blob)
            if uid is None or structure is None:
                continue
            result[uid] = parser.parse_bodystructure(structure)
        return result

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

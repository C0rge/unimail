"""平台适配层基类与注册表。

所有平台差异（服务器参数、特殊命令、编码处理）都收敛在 Adapter 内部，
上层只面对统一的 NormalizedMail 与标准 IMAP 操作。
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import imaplib
import logging
import re
import ssl
from collections.abc import Iterator
from dataclasses import dataclass, field

from ..config import ALLOW_INVALID_TLS_CERT, FETCH_TIMEOUT, PLATFORMS, PlatformConfig
from ..core.models import Account, NormalizedMail
from . import parser

log = logging.getLogger(__name__)

# 大邮件头：imaplib 默认单行上限仅 10 KB，长 References / 长主题会被静默截断。
# `_MAXLINE` 是 CPython 有意暴露的模块级开关，只能直接改模块属性。
imaplib._MAXLINE = 10_000_000  # type: ignore[attr-defined]  # noqa: SLF001

# LIST 响应形如 `(\HasNoChildren \Trash) "/" "Deleted Messages"`。
# 分隔符可能是 `NIL` 或 `.`，文件夹名可能带引号，也可能是 163 那种中文名，
# 因此不能沿用 `split(' "/" ')`（该写法在 `[Gmail]/Trash` 与中文名上都不稳）。
_LIST_LINE_RE = re.compile(
    r'^\((?P<flags>[^)]*)\)\s+(?P<delim>"(?:[^"\\]|\\.)*"|NIL)\s+(?P<name>.+)$'
)

# RFC 3501 ATOM-CHAR 排除的字符：括号、花括号、空格、CTL、
# 列表通配符（% *）、引号类（" \）、响应特殊字符（]）。
# 含这些字符的邮箱名必须写成带引号的字符串形式。
_ATOM_UNSAFE = set('(){"\\]%*') | {chr(c) for c in range(0x21)} | {chr(0x7F)}

# `UID FETCH` 响应前缀里的 UID，形如 `1 (UID 123 BODY[HEADER] {456}`。
# 只在**前缀**里找，不碰字面量正文——正文里出现 "UID 999" 是邮件内容，不是应答。
_FETCH_UID_RE = re.compile(rb"UID\s+(\d+)", re.IGNORECASE)


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


def utf7_encode(name: str) -> str:
    r"""把文件夹名编成 **IMAP 修改版 UTF-7**（RFC 3501 §5.1.3）。

    为什么不能直接用 `str.encode("utf-7")`：Python 内置的 `utf-7` 编解码器
    用 `+/` 表示 Base64 位移，而 IMAP 的修改版规定用 `+,` 且省略补位的 `=`。
    两者**不兼容**——把内置编解码器的结果发给服务器，163 / QQ 的中文文件夹名
    会直接报 `NO Invalid mailbox name`。

    两个易错点：位移字符是 `+`（不是 `&`）；字面量 `&` 与 `+` 分别要写成
    `&-` 与 `+-`，否则解码方会把它们当位移序列的起始。
    """
    out: list[str] = []
    buf: list[bytes] = []

    def flush() -> None:
        if buf:
            b64 = base64.b64encode(b"".join(buf)).rstrip(b"=").decode("ascii")
            out.append("+" + b64.replace("/", ",") + "-")
            buf.clear()

    for ch in name:
        if ch == "&":
            flush()
            out.append("&-")
        elif ch == "+":
            flush()
            out.append("+-")
        elif 0x20 <= ord(ch) <= 0x7E:
            flush()
            out.append(ch)
        else:
            buf.append(ch.encode("utf-16-be"))
    flush()
    return "".join(out)


def utf7_decode(name: str) -> str:
    """解码 IMAP 修改版 UTF-7（`utf7_encode` 的逆运算）。

    同样不能用内置的 `utf-7` 解码器：内置版认 `+/`，而协议用 `+,`，
    直接喂给内置解码器会把 QQ / 163 的中文文件夹名解成乱码。
    遇到解不开的片段**原样保留**——猜错编码比留一段怪字符更难排查。
    """
    out: list[str] = []
    index = 0
    while index < len(name):
        char = name[index]
        if char == "&":
            # `&-` 表示字面量 `&`；孤立的 `&`（畸形输入）也按字面量处理。
            out.append("&")
            index += 2 if name.startswith("&-", index) else 1
            continue
        if char != "+":
            out.append(char)
            index += 1
            continue
        end = name.find("-", index + 1)
        if end == -1:
            # 位移序列没有收尾的 `-`：原样保留，不猜。
            out.append(name[index:])
            break
        chunk = name[index + 1:end]
        if not chunk:
            out.append("+")          # `+-` 是字面量 `+`
        else:
            padded = chunk.replace(",", "/")
            padded += "=" * (-len(padded) % 4)
            try:
                out.append(base64.b64decode(padded, validate=True).decode("utf-16-be"))
            except (binascii.Error, UnicodeDecodeError, ValueError):
                out.append(name[index:end + 1])
        index = end + 1
    return "".join(out)


def encode_mailbox(name: str) -> str:
    """把文件夹名编成可**直接拼进 IMAP 命令**的形式。

    含非 ASCII（163 / QQ 的中文文件夹名）或含 `]`（`[Gmail]/Trash`）时，
    必须先转修改版 UTF-7 或退化为带引号的字符串，否则命令要么编码出错、
    要么被服务器理解成列表通配符。
    """
    encoded = utf7_encode(name)
    if encoded and all(ord(c) > 0x20 and ord(c) != 0x7F and c not in _ATOM_UNSAFE
                       for c in encoded):
        return encoded
    return '"' + encoded.replace("\\", "\\\\").replace('"', '\\"') + '"'


class ImapError(Exception):
    """IMAP 连接或操作失败（面向用户的可读错误）。"""


@dataclass
class Folder:
    name: str
    display: str
    # LIST 响应里的属性，如 `\Trash` / `\Sent` / `\Noselect`（大写，含反斜杠）。
    # 只有带 `\Trash` 的文件夹才能被安全地当作删除目标：靠名字猜是不可靠的
    # （同一家邮箱的中文版 / 英文版界面给出的名字不同）。
    flags: frozenset[str] = field(default_factory=frozenset)

    def has_flag(self, flag: str) -> bool:
        return flag.upper() in self.flags


def parse_list_line(text: str) -> tuple[frozenset[str], str] | None:
    """解析一行 LIST / LSUB 响应，返回 `(属性集合, 文件夹名)`。

    返回 `None` 表示这行不符合标准形式，调用方应回退到宽松解析，
    以免某个服务器的畸形响应让整个文件夹列表变成空的。
    """
    match = _LIST_LINE_RE.match(text)
    if match is None:
        return None
    flags = frozenset(
        token.upper() for token in match.group("flags").split() if token.startswith("\\")
    )
    name = match.group("name").strip()
    if len(name) >= 2 and name.startswith('"') and name.endswith('"'):
        name = name[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return flags, name


def _iter_fetch_literals(data) -> Iterator[tuple[str, bytes]]:
    r"""从 `UID FETCH` 的响应里逐个取出 `(uid, 字面量字节)`。

    imaplib 的返回形状随服务器而异：带字面量时每项是 `(前缀, 内容)` 二元组
    （前缀形如 `b'1 (UID 123 BODY[HEADER] {456}'`）；没有字面量时只给一段
    bytes——那种情况下拿不到正文，直接跳过。请求是 `BODY.PEEK[HEADER]`，
    按 `HEADER` 关键字匹配，避免把 `BODYSTRUCTURE` 之类的响应也当成头部。
    """
    for item in data:
        head = b""
        body = b""
        if isinstance(item, tuple) and len(item) >= 2:
            head = item[0] if isinstance(item[0], bytes) else b""
            body = item[1] if isinstance(item[1], bytes) else b""
        if not body:
            continue
        match = _FETCH_UID_RE.search(head)
        if match is None:
            # 服务器没在应答里回带 UID（少数实现如此）：无法定位归属，
            # 交由调用方回退逐封取。
            continue
        yield match.group(1).decode("ascii"), body


class ImapAdapter:
    """IMAP 平台适配器。

    刻意**不**继承 `abc.ABC`：`probe()` 等方法的默认实现是抛
    `NotImplementedError`，而适配器的调用方只依赖 `connect/fetch_*/search_*`
    这几个通用方法，抽象基类在这里只会造成「子类必须实现全部抽象方法」的
    过度约束（例如仅用于解析单测的轻量子类）。
    """

    platform: str = "custom"

    # 一次批量 `UID FETCH` 覆盖多少个 UID。每封头部通常几 KB，50 封约
    # 100–250 KB —— 在「往返次数越少越好」与「单次响应别撞上服务器上限」
    # 之间取平衡。
    HEADER_FETCH_CHUNK = 50

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
            parsed = parse_list_line(text)
            if parsed is not None:
                flags, name = parsed
                if name:
                    folders.append(Folder(name=name, display=name, flags=flags))
                continue
            # 回退：老式宽松解析，兼容不含属性组的畸形响应
            # 形如: (\HasNoChildren) "/" "INBOX"
            parts = text.split(' "/" ')
            if len(parts) >= 2:
                name = parts[-1].strip().strip('"')
                folders.append(Folder(name=name, display=name))
        return folders or [Folder("INBOX", "收件箱")]

    def capabilities(self, imap: imaplib.IMAP4) -> set[str]:
        """查询服务器能力（`CAPABILITY`），返回大写集合。

        每次现查而不是缓存：登录前后能力集可能变化（例如登录后才宣告
        `UIDPLUS`），而删除是低频操作，多一次往返无所谓。
        查询失败返回空集——调用方应按「不具备该能力」处理，宁可拒绝执行。
        """
        try:
            typ, data = imap.capability()
        except (imaplib.IMAP4.error, AttributeError, OSError):
            return set()
        if typ != "OK":
            return set()
        caps: set[str] = set()
        for item in data or []:
            text = item.decode("ascii", errors="replace") if isinstance(item, bytes) else str(item)
            caps |= {token.upper() for token in text.split()}
        return caps

    def find_trash_folder(self, imap: imaplib.IMAP4) -> str | None:
        """定位垃圾箱文件夹，找不到返回 None。

        优先用 `\\Trash` 特殊用途属性（RFC 6154）——这是唯一可靠的方式，
        网易 / Gmail 的中文版与英文版给出的文件夹名并不一致。只有在服务器
        不宣告该属性时，才退回按平台常见名匹配。
        """
        try:
            folders = self.list_folders(imap)
        except (ImapError, imaplib.IMAP4.error, OSError):
            folders = []
        usable = [f for f in folders if not f.has_flag("\\Noselect")]
        for folder in usable:
            if folder.has_flag("\\Trash"):
                return folder.name
        candidates = {name.casefold() for name in (self.config.trash_candidates or ())}
        if candidates:
            for folder in usable:
                if folder.name.casefold() in candidates:
                    return folder.name
        return None

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

    def fetch_headers_many(self, imap: imaplib.IMAP4, uids: list[str],
                           folder: str = "INBOX") -> dict[str, NormalizedMail]:
        r"""批量拉取多封邮件的头部，返回 `{uid: NormalizedMail}`。

        为什么要批量：`fetch_headers()` 是**单 UID** 的 `UID FETCH`，一页 200 封
        就是 200 次串行往返（首同步 1 万封 = 1 万次往返）。IMAP 本来就允许把
        UID 写成逗号集合一次取回 —— 本文件里的 `fetch_attachment_meta()`
        早就这么做了，只是邮件头这条路径当初漏掉。

        健壮性：批量没拿到的 UID 会**逐封回退重试**，所以返回结果的下限等于
        「全部逐封取」，不会因为某台服务器不支持批量（或应答里不回带 UID）
        而把邮件取丢。真正取不到的 UID 不出现在返回值里，调用方据此停止推进
        游标（保持「单封失败不越过」的既有语义）。
        """
        result: dict[str, NormalizedMail] = {}
        wanted = [str(u) for u in uids]
        if not wanted:
            return result
        # 只读 select 一次供整批使用；被服务器拒绝也无妨（多数服务器登录后
        # 已默认选中 INBOX，且 FETCH 本来就能对已选中的文件夹生效）
        with contextlib.suppress(imaplib.IMAP4.error, OSError):
            imap.select(folder, readonly=True)
        for start in range(0, len(wanted), self.HEADER_FETCH_CHUNK):
            chunk = wanted[start:start + self.HEADER_FETCH_CHUNK]
            chunk_set = set(chunk)
            try:
                typ, data = imap.uid(
                    "FETCH", ",".join(chunk), "(UID BODY.PEEK[HEADER])"
                )
            except (imaplib.IMAP4.error, OSError) as exc:
                log.debug("批量拉取邮件头失败（本片改为逐封）：%s", exc)
                continue
            if typ != "OK" or not data:
                continue
            for uid_text, raw in _iter_fetch_literals(data):
                if uid_text in chunk_set and uid_text not in result:
                    result[uid_text] = parser.parse_headers_only(raw, uid_text, folder)
        # 逐封回退：只补批量没拿到的（一切正常时这里是空循环）
        for uid_text in [u for u in wanted if u not in result]:
            try:
                result[uid_text] = self.fetch_headers(imap, uid_text, folder)
            except ImapError as exc:
                log.debug("邮件头 %s 取不到：%s", uid_text, exc)
        return result

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

    # ------------------------------------------------------------ 标记回写
    FLAG_SEEN = "\\Seen"
    FLAG_FLAGGED = "\\Flagged"

    def store_flags(self, imap: imaplib.IMAP4, uid: str, folder: str = "INBOX",
                    add: list[str] | tuple[str, ...] = (),
                    remove: list[str] | tuple[str, ...] = ()) -> None:
        r"""把「已读 / 星标」写回服务器（`UID STORE ±FLAGS.SILENT`）。

        `.SILENT` 表示不需要服务器回传新的 FLAGS 列表——我们只关心是否写成功，
        回传只会多一次解析。不需要增删任何标志时直接返回，不产生任何往返。

        只改 `\Seen` / `\Flagged` 这两个「用户可见状态」标志，**不动**
        `\Deleted`：把「标为已读」和「删除邮件」混在同一条通路里，
        一次标志位转义错误就可能变成删邮件。真正的删除走 `move_to_trash()`，
        且必须由用户显式触发。
        """
        allowed = {self.FLAG_SEEN, self.FLAG_FLAGGED}
        add_set = sorted(set(add) & allowed)
        remove_set = sorted(set(remove) & allowed)
        if not add_set and not remove_set:
            return
        with contextlib.suppress(imaplib.IMAP4.error, OSError):
            imap.select(folder or "INBOX", readonly=False)
        try:
            if add_set:
                imap.uid("STORE", str(uid), "+FLAGS.SILENT",
                         "(" + " ".join(add_set) + ")")
            if remove_set:
                imap.uid("STORE", str(uid), "-FLAGS.SILENT",
                         "(" + " ".join(remove_set) + ")")
        except imaplib.IMAP4.error as exc:
            raise ImapError(f"同步标记到服务器失败（uid={uid}）：{exc}") from exc

    # ------------------------------------------------------------ 服务端删除
    def move_to_trash(self, imap: imaplib.IMAP4, uid: str, folder: str = "INBOX",
                      *, trash: str | None = None) -> str:
        r"""把一封邮件移入垃圾箱（**可在垃圾箱里恢复**），返回垃圾箱名。

        刻意只做「移动到垃圾箱」而**不提供永久删除**，理由有两层：

        1. 可逆。误删的邮件还躺在垃圾箱里，这与「永久删除」是两种不同后果的
           操作，前者不该被一次误点触发。
        2. 不变通 `EXPUNGE`。`UID EXPUNGE`（RFC 4315）精确到单个 UID，而普通的
           `EXPUNGE` 会清掉该文件夹里**所有**被标记 `\Deleted` 的邮件——包括
           手机端 / 网页版标记的、用户根本没打算删的那些。因此这里要求服务器
           宣告 `UIDPLUS`，否则宁可拒绝执行并说明原因。

        调用方需保证 `uid` 确实属于 `folder`；本方法会自行 `select`（非只读）。
        """
        caps = self.capabilities(imap)
        if "UIDPLUS" not in caps:
            raise ImapError(
                "该服务器未宣告 UIDPLUS（RFC 4315），无法安全地删除单封邮件。\n"
                "没有 UIDPLUS 就只能用整文件夹 EXPUNGE，而那会把其它客户端"
                "（手机、网页版）标记为删除的邮件一并清掉，因此本程序拒绝执行。"
            )

        target = trash or self.find_trash_folder(imap)
        if not target:
            raise ImapError(
                "未能在这个账号里找到垃圾箱文件夹，已中止操作（不做不可恢复的删除）。\n"
                "若该邮箱确实没有垃圾箱，请改用「删除本地副本」。"
            )

        try:
            typ, _data = imap.select(folder or "INBOX", readonly=False)
            if typ != "OK":
                raise ImapError(f"无法以可写方式打开文件夹「{folder}」")
            typ, _data = imap.uid("COPY", str(uid), encode_mailbox(target))
            if typ != "OK":
                raise ImapError(f"复制邮件到「{target}」失败")
            typ, _data = imap.uid("STORE", str(uid), "+FLAGS.SILENT", "(\\Deleted)")
            if typ != "OK":
                raise ImapError("标记邮件为已删除失败（邮件可能已复制到垃圾箱）")
            typ, _data = imap.uid("EXPUNGE", str(uid))
            if typ != "OK":
                raise ImapError(
                    f"从「{folder}」移除邮件失败；邮件可能同时存在于原文件夹与垃圾箱"
                )
        except ImapError:
            raise
        except imaplib.IMAP4.error as exc:
            raise ImapError(f"移动到垃圾箱失败：{exc}") from exc
        return target



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

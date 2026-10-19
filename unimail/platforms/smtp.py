"""SMTP 发信适配器：把「能收」补成「能发」。

为什么这是 P0
-----------
审查报告里三个硬伤之一：只收不发。用户读到一封邮件后必须切到网页版或手机
去回复——留存的核心动作断裂，这是与竞品差距最大的一项（Foxmail、
Thunderbird、Spark 全都把「写邮件」当作第一公民）。

认证矩阵（与 IMAP 侧完全对齐）
-----------------------------
| 平台 | SMTP 认证 | 说明 |
|---|---|---|
| QQ / 163 | `LOGIN` + 授权码 | 与 IMAP 用同一枚授权码 |
| Gmail | `LOGIN` + 应用专用密码 | 或 OAuth2 XOAUTH2（需 client_id） |
| Outlook / M365 | **必须 XOAUTH2** | 微软已停用 SMTP 基础认证 |
| 自定义 IMAP | `LOGIN` + 密码 | 服务器配什么用什么 |

**刻意不引入 `aiosmtplib` / 不自己写投递队列**：SMTP 投递是一次短连接
（认证 → `DATA` → `QUIT`，通常几百毫秒到几秒），直接同步调用再丢给后台
线程池即可；引入异步库会让「取消发送」「失败重试」这些真问题全部重新实现
一遍。失败重发的语义放在 `core/services.py` 的 `ComposeService` 里，
由 outbox 表承载——那才是「哪封没发出去」的持久事实。

安全约束（与 IMAP 侧同一套，不另起炉灶）
--------------------------------------
1. **默认强制 TLS**：465 用 `SMTP_SSL`，587 走 `STARTTLS`。明文 25 端口
   只在账号显式关闭 SSL 时才用，并且拒绝明文发送凭据（见 `_login`）。
2. **走代理不放宽校验**：与 IMAP 一致——覆写 `_get_socket` 让流量经
   `platforms/proxy.py` 的隧道，TLS 的 SNI 与主机名校验仍按真实服务器做。
   代理只搬字节，没有机会冒充服务器。
3. **OAuth2 账号的凭据栏是 refresh_token**，access_token 在内存里换出来即用，
   不落盘。与 IMAP 侧同一份 `TokenSet` 语义。
"""
from __future__ import annotations

import contextlib
import email.message
import logging
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from ..config import ALLOW_INVALID_TLS_CERT, FETCH_TIMEOUT
from ..core.models import Account
from .base import tls_context
from .oauth import OAuthError, xoauth2_string
from .proxy import (
    ProxyConfig,
    ProxyError,
    describe_active_proxy,
    open_proxy_tunnel,
    resolve_proxy,
)

log = logging.getLogger(__name__)

# STARTTLS 前的握手阶段：smtplib 默认对 EHLO 响应较宽松，这里取与 IMAP
# 一致的 FETCH_TIMEOUT，避免「连上了但服务器不应答」时无限期挂住。
_CONNECT_TIMEOUT = FETCH_TIMEOUT

# 标准端口：用于「账号没填 SMTP 端口」时按 use_ssl 推断。
_PORT_SSL = 465
_PORT_STARTTLS = 587
_PORT_PLAIN = 25


class SmtpError(RuntimeError):
    """发信失败。消息面向用户，说清「哪一步、为什么、能怎么办」。"""


@dataclass(frozen=True)
class SmtpConfig:
    """一次发信所需的连接参数。

    从 `Account` 派生（`from_account`），不单独持久化——SMTP 服务器地址
    多数与 IMAP 同域（`imap.qq.com` ↔ `smtp.qq.com`），账号里只存一个
    `smtp_host` 覆盖值即可，没有第二个事实源要同步。
    """
    host: str
    port: int
    use_ssl: bool               # True=465 隐式 TLS；False=587 STARTTLS 或 25 明文
    username: str
    # 密码或 access_token（OAuth2 账号）。**只在内存里存在**，不落盘。
    password: str
    oauth2: bool = False
    # 平台键（qq/163/gmail/outlook/custom）：只用于把认证失败映射成
    # 该平台的可操作提示，不参与连接与协议。
    platform: str = ""

    @classmethod
    def from_account(cls, account: Account, password: str,
                     host: str = "", port: int = 0) -> SmtpConfig:
        oauth2 = str(getattr(account, "auth_type", "")).startswith("oauth2")
        return cls(
            host=host or _derive_smtp_host(account),
            port=port or _derive_smtp_port(account),
            use_ssl=bool(account.use_ssl),
            username=account.username or account.email,
            password=password,
            oauth2=oauth2,
            platform=getattr(account, "platform", "") or "",
        )


def _derive_smtp_host(account: Account) -> str:
    """从 IMAP 主机推断 SMTP 主机：`imap.qq.com` → `smtp.qq.com`。

    覆盖不到的情况由账号的 `smtp_host` 显式指定（自定义 IMAP 尤其需要：
    自建服务器的 SMTP 地址与 IMAP 没有必然关系）。
    """
    explicit = str(getattr(account, "smtp_host", "") or "").strip()
    if explicit:
        return explicit
    host = (account.imap_host or "").strip()
    for prefix in ("imap.", "imap4."):
        if host.startswith(prefix):
            return "smtp." + host[len(prefix):]
    if host:
        # 没有 imap. 前缀时不猜：把 imap 主机原样当 SMTP 用，大概率是错的，
        # 但至少错误信息里会出现那个主机名，用户知道该去改哪里。
        log.warning("账号 %s 的 IMAP 主机 %s 不含 imap. 前缀，SMTP 地址按同名推断",
                    account.email, host)
    return host


def _derive_smtp_port(account: Account) -> int:
    explicit = int(getattr(account, "smtp_port", 0) or 0)
    if explicit:
        return explicit
    # 与 IMAP 的 use_ssl 保持一致：账号开的是 SSL，SMTP 就走隐式 TLS 端口。
    return _PORT_SSL if account.use_ssl else _PORT_STARTTLS


class _ProxiedSMTP(smtplib.SMTP_SSL):
    """经代理隧道的 SMTP_SSL。

    与 `platforms/base.py` 里 `_ProxiedIMAP4SSL` 是同一手法：`smtplib` 只做
    直连，因此覆写它取 socket 的那一个方法（`_get_socket`），让流量先过
    `proxy.py` 的隧道，再在隧道上做 TLS。

    `server_hostname` 传**真实 SMTP 主机**而非代理地址，所以 SNI 与证书
    主机名校验完全不受代理影响——「走代理不放宽校验」是机制保证，
    不依赖调用方自觉。测试里用自签证书 + 主机名不匹配实测会被拒绝。
    """

    def __init__(self, host: str, port: int, *, ssl_context: ssl.SSLContext,
                 timeout: float, proxy: ProxyConfig | None = None) -> None:
        self.proxy = proxy
        super().__init__(host, port, timeout=timeout, context=ssl_context)

    def _get_socket(self, host, port, timeout):  # type: ignore[no-untyped-def]
        if self.proxy is None:
            # typeshed 未在 SMTP/SMTP_SSL 上声明 `_get_socket`，运行期它一定在。
            # 与 platforms/base.py 的 `_create_socket` 同一处理。
            return super()._get_socket(host, port, timeout)  # type: ignore[misc]
        sock = open_proxy_tunnel(self.proxy, host, port, timeout)
        return self.context.wrap_socket(sock, server_hostname=host)


class _ProxiedSMTPStartTLS(smtplib.SMTP):
    """经代理隧道 + STARTTLS 升级的 SMTP（587 端口）。

    STARTTLS 的顺序很重要：先明文 `EHLO`（SMTP 协议要求），再
    `STARTTLS` 升级，**升级之后才允许发凭据**。`smtplib.starttls()`
    内部会重新取一次 socket，所以同样只需覆写 `_get_socket`。
    """

    def __init__(self, host: str, port: int, *, ssl_context: ssl.SSLContext,
                 timeout: float, proxy: ProxyConfig | None = None) -> None:
        self.proxy = proxy
        self._tls_context = ssl_context
        super().__init__(host, port, timeout=timeout)

    def _get_socket(self, host, port, timeout):  # type: ignore[no-untyped-def]
        if self.proxy is None:
            return super()._get_socket(host, port, timeout)  # type: ignore[misc]
        return open_proxy_tunnel(self.proxy, host, port, timeout)

    def starttls(self, *, context: ssl.SSLContext | None = None):  # type: ignore[override]
        # 显式传入自己的上下文：不传时 smtplib 会用 `ssl._create_stdlib_context()`，
        # 那是 `verify_mode=CERT_NONE` 的宽松上下文——与 IMAP 侧同一个坑。
        return super().starttls(context=context or self._tls_context)


def build_message(*, from_addr: str, from_name: str, to: list[str],
                  subject: str, body_text: str, body_html: str = "",
                  cc: list[str] | None = None,
                  in_reply_to: str = "", references: list[str] | None = None,
                  attachments: list[tuple[str, bytes, str]] | None = None) -> EmailMessage:
    """构造一封待发邮件。

    **回复线程的正确性**（这是「回复后对方客户端能正确归并」的唯一依据）：
      * `In-Reply-To` 填被回复邮件的 `Message-ID`；
      * `References` 按 RFC 2822 累积：被回复邮件的 References + 其
        Message-ID，空格分隔。**顺序不能反**——收件方按最后一个元素
        找父邮件，写成「自身 ID 在前」会把线程接到错误的位置。
    缺了这两个头，Gmail / Outlook 会把回复显示成一封独立新邮件，
    而 UniMail 自己的会话视图也会把它并进错误的会话（它靠的正是这两个头）。

    不在这里做 HTML：正文是**纯文本**。理由见 `core/services.py` 里
    `ComposeService` 的说明——本项目对 HTML 的立场是「只清洗接收的，
    不生成发送的」，避免把 XSS 与跟踪像素的防御面扩大到 outgoing。
    """
    msg = EmailMessage()
    msg["From"] = f"{from_name} <{from_addr}>" if from_name else from_addr
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=_domain_of(from_addr))
    msg["MIME-Version"] = "1.0"
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if references:
        chain = [r for r in references if r]
        if in_reply_to and in_reply_to not in chain:
            chain.append(in_reply_to)
        msg["References"] = " ".join(chain)

    if body_html:
        # 双格式并存：不支持 HTML 的客户端（部分企业邮、纯文本转发链）
        # 会回退到 text/plain，不至于看到一堆标签。
        msg.set_content(body_text or "")
        msg.add_alternative(body_html, subtype="html")
    else:
        msg.set_content(body_text or "")

    for filename, data, mime in (attachments or []):
        maintype, _, subtype = mime.partition("/")
        msg.add_attachment(data, maintype=maintype or "application",
                           subtype=subtype or "octet-stream", filename=filename)
    return msg


def _domain_of(addr: str) -> str:
    return addr.split("@", 1)[1] if "@" in addr else "localhost"


def send(cfg: SmtpConfig, message: email.message.Message) -> None:
    """发一封邮件。失败抛 `SmtpError`（消息面向用户）。

    参数类型是 `email.message.Message` 而不是 `EmailMessage`：
    outbox 里存的是 RFC 5322 原文，重放时用 `message_from_string()` 解析，
    它返回的是兼容层 `Message`（没有 `iter_attachments()` 等新 API）。
    `smtplib.send_message()` 本身也只要求 `Message`，因此这里按实际
    接受的范围声明，而不是逼调用方做一次无意义的类型转换。

    端口语义
    --------
    * 465：连接即 TLS（`SMTP_SSL`）；
    * 587：明文连接 → `STARTTLS` 升级 → 认证 → 发送；
    *  25：明文。**拒绝**在此端口上发送凭据——明文 SMTP 会把授权码
      直接暴露给同路径上的任何观察者，与项目「凭据只走加密通道」的立场
      冲突。确实需要用 25 的服务器（极少见）应改配 587。
    """
    if not cfg.host:
        raise SmtpError("未配置 SMTP 服务器地址")
    if not cfg.password and not cfg.oauth2:
        raise SmtpError("缺少 SMTP 认证凭据")

    try:
        proxy = resolve_proxy(cfg.host)
    except ProxyError as exc:
        raise SmtpError(f"{exc}\n（代理来自环境变量 UNIMAIL_PROXY；未设置时一律直连）") from exc

    ctx = tls_context(allow_invalid=ALLOW_INVALID_TLS_CERT)

    # 25 端口一律拒绝，**不取决于** use_ssl。
    #
    # 早先的判据是 `port == 25 and not use_ssl`，那是个漏洞：账号是从 IMAP
    # 派生的（多数平台 use_ssl=True），于是「SMTP 端口被显式改成 25」时
    # 条件不成立，凭据照样明文发出。端口本身就是事实标准——
    # 25 明文、465 隐式 TLS、587 STARTTLS，没有「25 却跑 TLS」的合法配置。
    # 这里按端口判，宁可拒绝一个罕见配置，也不给明文留下任何入口。
    if cfg.port == _PORT_PLAIN:
        raise SmtpError(
            f"拒绝在 {cfg.port} 端口上发送凭据：该端口是明文 SMTP，"
            "授权码/密码会被同路径上的观察者直接拿到。\n"
            "请把账号的 SMTP 端口改为 587（STARTTLS）或 465（SSL）。"
        )

    try:
        if cfg.use_ssl or cfg.port == _PORT_SSL:
            server: smtplib.SMTP = _ProxiedSMTP(
                cfg.host, cfg.port, ssl_context=ctx,
                timeout=_CONNECT_TIMEOUT, proxy=proxy)
        else:
            server = _ProxiedSMTPStartTLS(
                cfg.host, cfg.port, ssl_context=ctx,
                timeout=_CONNECT_TIMEOUT, proxy=proxy)
    except (OSError, ssl.SSLError, smtplib.SMTPException) as exc:
        raise SmtpError(
            f"无法连接 SMTP 服务器 {cfg.host}:{cfg.port} — {exc}\n"
            f"{_proxy_hint(proxy, cfg.host)}"
        ) from exc

    try:
        server.ehlo_or_helo_if_needed()
        if not (cfg.use_ssl or cfg.port == _PORT_SSL):
            if not server.has_extn("starttls"):
                raise SmtpError(
                    f"服务器 {cfg.host}:{cfg.port} 不支持 STARTTLS，"
                    "继续将以明文发送凭据，已中止。\n"
                    "请改用 465 端口的 SSL 连接。"
                )
            server.starttls(context=ctx)
            server.ehlo()

        _login(server, cfg)
        server.send_message(message)
        log.info("已发送邮件：%s → %s", message["From"], message["To"])
    except SmtpError:
        raise
    except ssl.SSLCertVerificationError as exc:
        raise SmtpError(
            f"无法验证 {cfg.host} 的服务器证书，已中止发送。\n"
            f"失败原因：{getattr(exc, 'verify_message', None) or exc}\n"
            + ("当前经代理连接——若代理开启了「HTTPS 解密」，它就会替换服务器证书，"
               "从而必然触发本错误。请关掉解密功能，或改用不解密的 SOCKS5 隧道。"
               if proxy is not None else
               "如确认是企业自建服务器且使用自签证书，可设置环境变量 "
               "UNIMAIL_ALLOW_INVALID_CERT=1 后重启（会失去中间人防护，请谨慎）。")
        ) from exc
    except ssl.SSLError as exc:
        raise SmtpError(f"与 {cfg.host}:{cfg.port} 的 TLS 握手失败：{exc}") from exc
    except smtplib.SMTPAuthenticationError as exc:
        raise SmtpError(
            _auth_hint(cfg, exc)
        ) from exc
    except OAuthError as exc:
        # OAuth2 账号的 access_token 过期/被撤：说清要重新授权，
        # 而不是让用户去查密码（那条路对 OAuth2 账号根本不存在）。
        raise SmtpError(
            f"OAuth2 授权已失效，无法发送：{exc}\n"
            "请在账号管理中重新授权（授权信息过期或被撤销时会出现此提示）。"
        ) from exc
    except smtplib.SMTPRecipientsRefused as exc:
        raise SmtpError(
            f"服务器拒绝了全部收件人：{exc.recipients}\n"
            "常见原因：收件地址不存在、被对方列入黑名单，或该域名拒绝来自本服务器的邮件。"
        ) from exc
    except smtplib.SMTPException as exc:
        raise SmtpError(f"发送失败：{exc}") from exc
    except OSError as exc:
        raise SmtpError(f"发送过程中连接中断：{exc}") from exc
    finally:
        # QUIT 失败不影响发送结论（邮件已经交给服务器），因此吞掉异常。
        # 但连接必须关闭：连接里带着解出的明文凭据，不能留着。
        # 用 contextlib.suppress 而不是 try/except/pass：后者的两个层次
        # 都会被 ruff 记（S110「该记日志」+ SIM105「该用 suppress」），
        # 而这里确实没有任何可做的补救动作，suppress 正是它的语义。
        with contextlib.suppress(Exception):
            server.quit()
        with contextlib.suppress(Exception):
            server.close()


def _login(server: smtplib.SMTP, cfg: SmtpConfig) -> None:
    """认证。OAuth2 走 XOAUTH2，其余走 LOGIN。"""
    if cfg.oauth2:
        # smtplib 与 imaplib 的 SASL 回调**返回类型不同**：imaplib 要 bytes，
        # smtplib 要 str（它会在内部按 command_encoding 再编码）。typeshed
        # 对 SMTP.auth 的回调声明为 `(bytes) -> str`，因此这里不能直接复用
        # `xoauth2_string()` 的 bytes 结果，必须解码成 str。
        payload = xoauth2_string(cfg.username, cfg.password).decode("utf-8")

        def _respond(_challenge: bytes) -> str:
            # 不在 EHLO 阶段预发 initial response：部分服务器（尤其企业邮）
            # 对 `AUTH XOAUTH2 <initial>` 的处理与标准 SASL-IR 不一致，
            # 等服务器发出 334 挑战后再回同样的 payload，兼容性更好。
            return payload

        try:
            server.auth("XOAUTH2", _respond)
        except smtplib.SMTPException as exc:
            raise OAuthError(f"XOAUTH2 认证失败：{exc}") from exc
        return
    try:
        server.login(cfg.username, cfg.password)
    except smtplib.SMTPNotSupportedError as exc:
        # 服务器不支持 LOGIN 而账号是密码型：把「它支持什么」说出来，
        # 比一句「认证失败」有用得多。
        raise SmtpError(
            f"服务器 {cfg.host} 不支持 LOGIN 认证（{exc}）。\n"
            "Outlook / Microsoft 365 必须改用 OAuth2 授权。"
        ) from exc


def _auth_hint(cfg: SmtpConfig, exc: Exception) -> str:
    """认证失败时给出**该平台**的 actionable 提示。

    直接照搬 IMAP 侧的提示会漏掉一件事：授权码在 IMAP 与 SMTP 侧通常是
    同一枚，但部分平台（163 早期、部分企业邮）的 SMTP 服务要单独开。
    """
    base = f"SMTP 认证被拒绝：{exc}"
    hints = {
        "qq": "QQ 邮箱请在「设置 → 账户 → POP3/IMAP/SMTP」中确认已开启 "
              "IMAP/SMTP 服务，并使用 16 位授权码（不是 QQ 密码）。",
        "163": "163 邮箱请在「设置 → POP3/SMTP/IMAP」中确认已开启 SMTP 服务，"
               "并使用授权码。",
        "gmail": "Gmail 请使用「应用专用密码」（需先开启两步验证），"
                 "或改用 OAuth2 授权。",
        "outlook": "Outlook / Microsoft 365 必须使用 OAuth2 授权"
                   "（微软已停用 SMTP 基础认证）。",
    }
    return base + "\n" + hints.get(cfg.platform,
                                   "请确认密码/授权码正确，且服务器已开启 SMTP 服务。")


def _proxy_hint(proxy: ProxyConfig | None, host: str) -> str:
    """连接失败时补一句「这次走没走代理」。

    与 IMAP 侧同一动机：没有这句话，用户会去怀疑密码、服务器、防火墙，
    唯独不会想到「我开的系统代理，本程序没用上」。
    """
    if proxy is not None:
        return (f"当前经代理 {proxy.display} 连接。\n"
                "若代理软件本身正常，请检查它的规则是否允许转发 SMTP 端口"
                "（465 / 587）；部分客户端默认只代理 80/443。")
    hint = [
        "当前为**直连**：本程序不会自动使用系统代理"
        "（系统代理只作用于 HTTP(S)，SMTP 走的是独立端口）。"
    ]
    try:
        detected = describe_active_proxy(host=host)
    except Exception:            # noqa: BLE001 - 探测失败不该影响主流程
        detected = ""
    if detected:
        # 这里刻意不写出具体代理地址：`describe_active_proxy()` 返回的是
        # 供人读的描述串，把它拼进提示会让同一段文案在不同机器上长短不一，
        # 而用户需要的是「怎么配」这个动作，不是「我检测到了什么」。
        hint.append(
            "\n检测到系统里已启用代理。如果你正需要靠它才能访问外网，"
            "可以这样让本程序也走它：\n"
            "    设置环境变量 UNIMAIL_PROXY=<代理地址>\n"
            "或把代理客户端切到「TUN / 增强 / 全局路由」模式。"
        )
    else:
        hint.append("\n若你确实需要使用代理，请查阅 使用说明.md 的「网络与代理」一节。")
    return "\n".join(hint)


__all__ = ["SmtpConfig", "SmtpError", "build_message", "send"]

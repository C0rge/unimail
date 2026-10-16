"""IMAP 代理通道：SOCKS5 与 HTTP CONNECT（含系统代理读取）。

为什么需要单独一个模块
----------------------
`imaplib` 只会**直连**：`IMAP4._create_socket()` 直接
`socket.create_connection((host, port))`。它既不读操作系统的「系统代理」
（Windows 上是注册表 `Internet Settings\\ProxyServer` 那份、macOS 上是
`scutil --proxy`、Linux 上是 GSettings），也不读 `HTTP_PROXY` 之类的
环境变量。于是「我已经开了系统代理」对本程序**毫无影响**：TCP 依旧直连
`imap.gmail.com:993`。在需要代理才能出网（或 Gmail 直连被阻断）的网络里，
这一步会被 RST、被超时、或被中间设备改写证书 —— 用户看到的却是一句
「TLS 握手失败」，和代理没有任何字面关联。这是本项目最容易被误判为
「程序有 bug」的一类问题，因此这里把代理做成**显式可选**的一等能力，
并让失败信息主动把「当前是否走代理」讲出来。

设计取舍
--------
* **默认关闭，且只认专用环境变量。** 环境里存在 `HTTP_PROXY` 不代表用户希望
  邮件客户端也走它：这类变量常被系统 / 工具链（pip、apt、curl）预置，把 IMAP
  「顺手」接到一个只转发 HTTP(S) 的代理上，会把原本能直连的用户直接变成连不上。
  本项目因此**只读 `UNIMAIL_PROXY`**；要复用通用的那几个变量，得显式写成
  `UNIMAIL_PROXY=env`（见 `resolve_proxy`）。这条取舍是实测撞出来的：
  开发环境里预置的 `HTTP_PROXY=http://127.0.0.1:53538` 一度让所有 IMAP 连接
  改道去打一个连不上 993 的端口。
* **不引入新依赖。** SOCKS5 与 HTTP CONNECT 的握手各只有几十行，自己实现
  比多一个 `PySocks` 运行时依赖更划算 —— 本项目已经因为「可选依赖缺失导致
  行为分裂」吃过亏（见 `storage/database.py` 顶部对 SQLCipher 的说明）。
* **一律由代理解析域名**（SOCKS5 用 `ATYP=0x03` 域名形式）。这样
  `socks5` 与 `socks5h` 行为一致，也避免本地 DNS 泄露与「本地解析出的 IP
  与代理侧不一致」造成的连接失败。
* **SNI 与证书校验不受影响**：TLS 仍由 `platforms/base.py` 用
  `server_hostname=<真实 IMAP 主机>` 建立，代理只搬字节，因此
  `check_hostname=True` 依然成立。
"""
from __future__ import annotations

import base64
import contextlib
import logging
import os
import socket
import ssl
import struct
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

log = logging.getLogger(__name__)

# 唯一被隐式读取的变量。见模块顶部「只认专用环境变量」。
PRIMARY_ENV_KEY = "UNIMAIL_PROXY"
# 通用代理变量：仅在 `UNIMAIL_PROXY=env` 时才会被参考。
GENERIC_ENV_KEYS = ("ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy",
                    "HTTP_PROXY", "http_proxy")
# 绕过列表：专用变量始终生效；通用的 `NO_PROXY` 只在 `env` 模式下参考，
# 因为它本来是给通用变量配对用的。
NO_PROXY_ENV_KEYS = ("UNIMAIL_NO_PROXY", "NO_PROXY", "no_proxy")

# `UNIMAIL_PROXY` 的保留取值
AUTO = "auto"          # 去读操作系统的「系统代理」设置
ENV = "env"            # 参考 ALL_PROXY / HTTPS_PROXY / HTTP_PROXY

SOCKS_SCHEMES = ("socks5", "socks5h")
HTTP_SCHEMES = ("http", "https")

# 握手缓冲区上限：HTTP 代理的响应头再长也不会超过这个数，
# 超过就认为对端不是代理（或恶意），直接中止而不是无限读。
_MAX_HANDSHAKE_BYTES = 16 * 1024

_SOCKS_REPLY_TEXT = {
    0x01: "代理返回「通用失败」",
    0x02: "代理规则不允许连接到该地址",
    0x03: "代理无法访问目标网络",
    0x04: "代理无法访问目标主机（域名解析失败或不可达）",
    0x05: "目标主机拒绝连接",
    0x06: "TTL 过期",
    0x07: "代理不支持 CONNECT 命令",
    0x08: "代理不支持该地址类型",
}


class ProxyError(RuntimeError):
    """代理配置错误或代理握手失败。

    调用方（`platforms/base.py`）会把它翻成面向用户的 `ImapError`，
    因此这里的文案要能直接读，别只说「连接失败」。
    """


@dataclass(frozen=True)
class ProxyConfig:
    """一条代理配置。`scheme` ∈ {socks5, socks5h, http, https}。"""

    scheme: str
    host: str
    port: int
    username: str = ""
    password: str = ""

    @property
    def display(self) -> str:
        """用于日志与界面提示的安全形式（**不含密码**）。"""
        auth = f"{self.username}@" if self.username else ""
        return f"{self.scheme}://{auth}{self.host}:{self.port}"

    @property
    def is_socks(self) -> bool:
        return self.scheme in SOCKS_SCHEMES


# ---------------------------------------------------------------- 解析
def parse_proxy(text: str) -> ProxyConfig | None:
    """把一条代理 URL 解析成 `ProxyConfig`；空串返回 None。

    接受的写法::

        socks5://127.0.0.1:7890
        socks5h://user:pass@127.0.0.1:1080
        http://127.0.0.1:7890
        https://user:pass@proxy.example.com:8443
        127.0.0.1:7890            （无 scheme，按 http 处理）
        auto                      （读系统代理设置）
        env                       （读 ALL_PROXY / HTTPS_PROXY / HTTP_PROXY）

    拒绝 `ftp://` 这类无法承载 TCP 隧道的 scheme —— 静默当成 http 会让用户
    以为配置生效了，实际走的是完全不同的协议。
    """
    raw = (text or "").strip()
    if not raw:
        return None
    lowered = raw.lower()
    if lowered == AUTO:
        return system_proxy()
    if lowered == ENV:
        # `env` 不是地址，是模式；单独解析它没有意义（调用方应先展开）
        raise ProxyError("`env` 只能作为 UNIMAIL_PROXY 的取值，不能直接当代理地址。")
    if "://" not in raw:
        raw = "http://" + raw

    scheme, _, rest = raw.partition("://")
    scheme = scheme.strip().lower()
    if scheme not in SOCKS_SCHEMES + HTTP_SCHEMES:
        raise ProxyError(
            f"不支持的代理协议：{scheme}://\n"
            "本程序只能通过 SOCKS5 或 HTTP CONNECT 隧道转发 IMAP 流量，"
            "请改用 socks5:// 或 http:// 开头的地址。"
        )

    rest, _, _path = rest.partition("/")     # 忽略路径与查询串
    username = password = ""
    if "@" in rest:
        cred, _, rest = rest.rpartition("@")
        username, sep, password = cred.partition(":")
        if not sep:
            username, password = cred, ""
    if rest.startswith("["):                 # IPv6 字面量
        host, _, port_text = rest.partition("]")
        host = host[1:]
        port_text = port_text.lstrip(":")
    else:
        host, _, port_text = rest.rpartition(":")
    host = host.strip()
    if not host:
        raise ProxyError(f"代理地址缺少主机名：{text}")
    try:
        port = int(port_text or "0")
    except ValueError as exc:
        raise ProxyError(f"代理端口不是数字：{port_text}") from exc
    if not (0 < port < 65536):
        default = 1080 if scheme in SOCKS_SCHEMES else 8080
        log.warning("代理 %s 未给出有效端口，按默认 %d 处理", text, default)
        port = default

    return ProxyConfig(scheme=scheme, host=host, port=port,
                       username=unquote(username), password=unquote(password))


def host_in_no_proxy(host: str, spec: str) -> bool:
    """`NO_PROXY` 通配匹配：`*`、精确主机、`.suffix` 后缀、裸 `suffix`。"""
    host = (host or "").strip().lower()
    if not host:
        return False
    for item in (spec or "").replace(";", ",").split(","):
        pattern = item.strip().lower()
        if not pattern:
            continue
        if pattern == "*":
            return True
        if pattern.startswith("."):
            if host.endswith(pattern) or host == pattern[1:]:
                return True
        elif host == pattern or host.endswith("." + pattern):
            return True
    return False


def no_proxy_spec(env: Mapping[str, str] | None = None, *, generic: bool = False) -> str:
    """绕过列表：先看 `UNIMAIL_NO_PROXY`；`generic=True` 时再看通用的 `NO_PROXY`。"""
    env = os.environ if env is None else env
    keys = NO_PROXY_ENV_KEYS if generic else NO_PROXY_ENV_KEYS[:1]
    for key in keys:
        value = (env.get(key) or "").strip()
        if value:
            return value
    return ""


def resolve_proxy(host: str, env: Mapping[str, str] | None = None) -> ProxyConfig | None:
    """解析出「这个目标主机该用哪条代理」。未配置（或命中绕过列表）返回 None。

    取值来源**只有** `UNIMAIL_PROXY`：

        UNIMAIL_PROXY=socks5://127.0.0.1:7890     显式地址
        UNIMAIL_PROXY=auto                        读操作系统「系统代理」
        UNIMAIL_PROXY=env                         读 ALL_PROXY/HTTPS_PROXY/HTTP_PROXY
        未设置                                     直连（默认，与历史行为一致）

    刻意**不**隐式参考 `HTTP_PROXY` 一族：这些变量常被开发环境或工具链预置，
    而一个只转发 HTTP(S) 的代理接不住 IMAP 的 993 端口，结果是「本来能直连的
    用户反而连不上」。要复用它们就得显式写 `env`，这是有意多出来的一步。
    """
    env = os.environ if env is None else env
    raw = (env.get(PRIMARY_ENV_KEY) or "").strip()
    if not raw:
        return None

    mode = raw.lower()
    generic = mode == ENV
    if generic:
        for key in GENERIC_ENV_KEYS:
            value = (env.get(key) or "").strip()
            if value:
                raw = value
                break
        else:
            log.debug("UNIMAIL_PROXY=env 但环境中没有任何通用代理变量，直连")
            return None

    if mode != AUTO and host_in_no_proxy(host, no_proxy_spec(env, generic=generic)):
        log.info("目标 %s 命中 NO_PROXY，将直连", host)
        return None
    return parse_proxy(raw)


# ---------------------------------------------------------------- 系统代理
_SYSTEM_PROXY_CACHE: list = [0.0, None]
_SYSTEM_PROXY_TTL = 10.0


def system_proxy(use_cache: bool = True) -> ProxyConfig | None:
    """读取操作系统的「系统代理」设置；读不到返回 None。

    只在 `UNIMAIL_PROXY=auto` 时才会被调用 —— 见模块顶部关于「为什么不默认
    接管」的说明。结果缓存 10 秒：每次建连都读一遍注册表既慢又没必要，
    但用户刚改了代理设置时也不该等到重启才生效。
    """
    now = time.monotonic()
    if use_cache and now - _SYSTEM_PROXY_CACHE[0] < _SYSTEM_PROXY_TTL:
        return _SYSTEM_PROXY_CACHE[1]
    value = _read_system_proxy()
    _SYSTEM_PROXY_CACHE[0] = now
    _SYSTEM_PROXY_CACHE[1] = value
    if value is not None:
        log.info("已读取系统代理：%s", value.display)
    return value


def _read_system_proxy() -> ProxyConfig | None:
    try:
        if sys.platform == "win32":
            return _read_windows_proxy()
        if sys.platform == "darwin":
            return _read_macos_proxy()
        return _read_gnome_proxy()
    except Exception as exc:      # noqa: BLE001 - 读系统设置失败不该影响连接
        log.debug("读取系统代理失败：%s", exc)
        return None


def _windows_registry() -> Any:
    """取 `winreg` 模块。返回 `Any` 而不是模块类型，理由如下。

    typeshed **只在 Windows 上**声明 winreg 的属性：在 Linux / macOS 上它是一个
    **空模块**，于是 `winreg.OpenKey(...)`、`winreg.HKEY_CURRENT_USER` 这类访问
    在 ubuntu 上（也就是本仓库 CI 的类型检查环境）会被判成 `attr-defined`，而这段
    代码在那两个平台上根本不会被执行——调用方 `system_proxy()` 先判了 `sys.platform`。

    与其在每一行挂 `# type: ignore`，不如在这唯一的入口处收敛成 `Any`：
    类型检查在这个薄封装上让一步，换掉四条平台相关的噪音，并且让
    **Windows 与 Linux 上的 mypy 结论一致**（否则本地过、CI 红，只有推到远端
    才会发现）。
    """
    import winreg

    return winreg


def _read_windows_proxy() -> ProxyConfig | None:
    """Windows：`HKCU\\...\\Internet Settings`。

    `ProxyServer` 既可能是裸 `host:port`，也可能是
    `http=h:p;https=h:p;socks=h:p` 这种分段形式。优先取 `socks=`（它天然支持
    任意端口，不会在 993 上被拒），其次 `https=`/`http=` —— 后者要求代理允许
    CONNECT 到非 443 端口，Clash / V2Ray 这类客户端默认允许。
    """
    reg = _windows_registry()
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with reg.OpenKey(reg.HKEY_CURRENT_USER, path) as key:
        enabled = _reg_int(reg, key, "ProxyEnable")
        if not enabled:
            return None
        server = _reg_str(reg, key, "ProxyServer")
    if not server:
        return None
    segmented: dict[str, str] = {}
    for part in server.split(";"):
        name, sep, value = part.partition("=")
        if sep:
            segmented[name.strip().lower()] = value.strip()
    scheme = "http"
    raw = server if not segmented else ""
    for name, candidate in (("socks", "socks5"), ("https", "http"), ("http", "http")):
        if segmented.get(name):
            raw, scheme = segmented[name], candidate
            break
    if not raw:
        return None
    return parse_proxy(f"{scheme}://{raw}")


def _reg_int(reg: Any, key: Any, name: str) -> int:
    try:
        return int(reg.QueryValueEx(key, name)[0])
    except (FileNotFoundError, ValueError, OSError):
        return 0


def _reg_str(reg: Any, key: Any, name: str) -> str:
    try:
        return str(reg.QueryValueEx(key, name)[0] or "").strip()
    except (FileNotFoundError, ValueError, OSError):
        return ""


def _read_macos_proxy() -> ProxyConfig | None:
    """macOS：解析 `scutil --proxy` 的输出。

    不引入 PyObjC：`scutil` 是系统自带工具，输出格式几十年没变，
    比多一个可选依赖稳。
    """
    import re
    # 参数全是常量，没有外部输入参与；`scutil` 靠 PATH 解析是刻意的
    # （它就在 /usr/sbin，写死绝对路径反而在非常规系统上会失败）。
    out = subprocess.run(("scutil", "--proxy"),  # noqa: S607
                         capture_output=True,
                         text=True, timeout=5, check=False).stdout or ""

    def num(pattern: str) -> int:
        found = re.search(pattern, out)
        return int(found.group(1)) if found else 0

    def host(pattern: str) -> str:
        found = re.search(pattern, out)
        return (found.group(1) if found else "").strip()

    if num(r"SOCKSEnable\s*:\s*(\d+)"):
        addr, port = host(r"SOCKSProxy\s*:\s*(\S+)"), num(r"SOCKSPort\s*:\s*(\d+)")
        if addr and port:
            return ProxyConfig("socks5", addr, port)
    for prefix in ("HTTPS", "HTTP"):
        if num(rf"{prefix}Enable\s*:\s*(\d+)"):
            addr = host(rf"{prefix}Proxy\s*:\s*(\S+)")
            port = num(rf"{prefix}Port\s*:\s*(\d+)")
            if addr and port:
                return ProxyConfig("http", addr, port)
    return None


def _read_gnome_proxy() -> ProxyConfig | None:
    """Linux 桌面：GNOME 的代理设置（失败即返回 None）。"""
    def get(schema: str, key: str) -> str:
        try:
            # schema / key 只来自本函数下方那几个字面量，不经过任何外部输入，
            # 因此不存在「执行不可信输入」的问题（S603）。
            out = subprocess.run(("gsettings", "get", schema, key),  # noqa: S603, S607
                                 capture_output=True, text=True, timeout=5,
                                 check=False).stdout
        except (OSError, subprocess.SubprocessError):
            return ""
        return (out or "").strip().strip("'")

    if get("org.gnome.system.proxy", "mode") != "manual":
        return None
    for schema, scheme in (("org.gnome.system.proxy.socks", "socks5"),
                           ("org.gnome.system.proxy.http", "http")):
        addr = get(schema, "host")
        port = get(schema, "port")
        if addr and port.isdigit() and int(port):
            return ProxyConfig(scheme, addr, int(port))
    return None


# ---------------------------------------------------------------- 隧道
def open_proxy_tunnel(cfg: ProxyConfig, host: str, port: int,
                      timeout: float | int | None = None) -> socket.socket:
    """经代理建立到 `(host, port)` 的 TCP 隧道，返回**已就绪**的裸 socket。

    调用方随后自行完成 TLS（`ssl_context.wrap_socket(..., server_hostname=host)`），
    因此证书校验与 SNI 完全不受代理影响。
    """
    try:
        sock: socket.socket = socket.create_connection((cfg.host, cfg.port), timeout)
    except OSError as exc:
        raise ProxyError(
            f"无法连接代理 {cfg.host}:{cfg.port} — {exc}\n"
            "请确认代理软件正在运行、监听端口与配置一致。"
        ) from exc
    if timeout:
        sock.settimeout(timeout)
    try:
        if cfg.scheme == "https":
            # `https://` 代理：先与代理本体建立 TLS，再在其上发 CONNECT
            try:
                sock = _PROXY_TLS_CONTEXT.wrap_socket(sock, server_hostname=cfg.host)
            except ssl.SSLError as exc:
                raise ProxyError(
                    f"与 HTTPS 代理 {cfg.host}:{cfg.port} 的 TLS 握手失败：{exc}"
                ) from exc
        if cfg.is_socks:
            _socks5_handshake(sock, cfg, host, port)
        else:
            _http_connect_handshake(sock, cfg, host, port)
    except BaseException:
        with contextlib.suppress(OSError):
            sock.close()
        raise
    if timeout:
        sock.settimeout(timeout)
    return sock


_PROXY_TLS_CONTEXT = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)


def _socks5_handshake(sock: socket.socket, cfg: ProxyConfig,
                      host: str, port: int) -> None:
    """SOCKS5（RFC 1928）+ 用户名/密码认证（RFC 1929）。"""
    greeting = b"\x05\x02\x00\x02" if cfg.username else b"\x05\x01\x00"
    sock.sendall(greeting)
    ver, method = _recv_exact(sock, 2)
    if ver != 0x05:
        raise ProxyError(
            f"代理返回了非 SOCKS5 的响应（版本字节 0x{ver:02x}）—— "
            "它可能是 HTTP 代理，请把地址改成 http:// 开头。")
    if method == 0x02:
        if not cfg.username:
            raise ProxyError("代理要求用户名/密码认证，但配置里没有凭据。\n"
                             "请写成 socks5://用户名:密码@主机:端口。")
        user = cfg.username.encode("utf-8")[:255]
        password = cfg.password.encode("utf-8")[:255]
        sock.sendall(b"\x01" + bytes([len(user)]) + user
                     + bytes([len(password)]) + password)
        _ver, status = _recv_exact(sock, 2)
        if status != 0x00:
            raise ProxyError("SOCKS5 代理拒绝了用户名/密码（认证失败）。")
    elif method != 0x00:
        raise ProxyError(f"代理不接受免密连接（方法字节 0x{method:02x}）；"
                         "如果它需要认证，请在代理地址里带上用户名与密码。")

    # 域名形式（ATYP=0x03）：由代理解析，避免本地 DNS 泄露与解析结果不一致
    try:
        name = host.encode("idna")
    except (UnicodeEncodeError, UnicodeError):
        raise ProxyError(f"无法把主机名编码成 DNS 形式：{host}") from None
    if len(name) > 255:
        raise ProxyError(f"目标主机名过长：{host}")
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name
                 + struct.pack("!H", port))
    ver, rep, _rsv, atyp = _recv_exact(sock, 4)
    if ver != 0x05:
        raise ProxyError(f"SOCKS5 响应版本异常：0x{ver:02x}")
    _skip_socks_address(sock, atyp)
    _recv_exact(sock, 2)                      # BND.PORT
    if rep != 0x00:
        raise ProxyError(
            f"代理拒绝了连接到 {host}:{port} —— "
            f"{_SOCKS_REPLY_TEXT.get(rep, f'未知错误码 {rep}')}。\n"
            "常见原因：代理规则把该域名/端口排除在转发之外，"
            "或代理只允许特定端口。"
        )


def _skip_socks_address(sock: socket.socket, atyp: int) -> None:
    if atyp == 0x01:
        _recv_exact(sock, 4)
    elif atyp == 0x04:
        _recv_exact(sock, 16)
    elif atyp == 0x03:
        _recv_exact(sock, _recv_exact(sock, 1)[0])
    else:
        raise ProxyError(f"SOCKS5 返回了未知的地址类型：0x{atyp:02x}")


def _http_connect_handshake(sock: socket.socket, cfg: ProxyConfig,
                            host: str, port: int) -> None:
    """HTTP 代理的 CONNECT 隧道（RFC 9110 §9.3.6）。"""
    target = f"{host}:{port}"
    lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}",
             "Proxy-Connection: keep-alive"]
    if cfg.username:
        # RFC 7617 规定 Basic 的口令按 UTF-8 编码后 base64；`.encode()` 的
        # 默认编码就是 UTF-8，无需显式传参。
        token = base64.b64encode(
            f"{cfg.username}:{cfg.password}".encode()).decode("ascii")
        lines.append(f"Proxy-Authorization: Basic {token}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))

    buf = b""
    deadline = time.monotonic() + 30.0
    while b"\r\n\r\n" not in buf:
        if len(buf) > _MAX_HANDSHAKE_BYTES:
            raise ProxyError("代理返回的响应头异常冗长，已中止（它可能不是 HTTP 代理）。")
        if time.monotonic() > deadline:
            raise ProxyError("等待代理响应超时（30 秒）。")
        chunk = sock.recv(4096)
        if not chunk:
            raise ProxyError(
                "代理在接受 CONNECT 之后立刻关闭了连接。\n"
                "如果是 HTTP 代理，它可能只允许 CONNECT 到 443 端口 —— "
                "IMAP 的 993/143 需要代理规则放行；"
                "若你的客户端同时支持 SOCKS5，改用 socks5:// 更稳。")
        buf += chunk

    head = buf.split(b"\r\n\r\n", 1)[0]
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    parts = status_line.split()
    code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    if code != 200:
        extra = ""
        if code in (401, 407):
            extra = "\n（代理要求认证，请在代理地址里带上 用户名:密码）"
        elif code in (403, 405, 501):
            extra = ("\n（代理拒绝 CONNECT 到该端口。请确认它的规则允许 993/143，"
                     "或改用 SOCKS5。）")
        raise ProxyError(f"代理拒绝了 CONNECT {target}：{status_line}{extra}")


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    """读满 `count` 字节；对端提前关闭则报出可读错误。"""
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ProxyError("代理在握手过程中关闭了连接（响应不完整）。")
        data += chunk
    return data


def describe_active_proxy(env: Mapping[str, str] | None = None, host: str = "") -> str:
    """给错误提示用的一句话：当前这条连接到底走不走代理。

    失败信息里带上它，用户立刻能分清「代理没配对」与「服务器真的连不上」。
    """
    try:
        cfg = resolve_proxy(host, env)
    except ProxyError as exc:
        return f"代理配置有误：{exc}"
    if cfg is None:
        return "当前为直连（未配置代理）"
    return f"当前经代理 {cfg.display} 连接"


__all__ = [
    "AUTO",
    "ENV",
    "ProxyConfig",
    "ProxyError",
    "describe_active_proxy",
    "host_in_no_proxy",
    "no_proxy_spec",
    "open_proxy_tunnel",
    "parse_proxy",
    "resolve_proxy",
    "system_proxy",
]

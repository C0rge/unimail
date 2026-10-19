"""OAuth2 / XOAUTH2：让 Outlook（Microsoft 365）重新可用，并给 Gmail 一条不再
依赖应用专用密码的路径。

为什么必须做
------------
微软已于 2024-09-16 停用个人 Outlook.com 的 IMAP/POP/SMTP **基础认证**，
Exchange Online 更早；应用密码在这些协议上不再被接受。也就是说，
「用户名 + 密码/应用密码」这条路对 Outlook 已经彻底失效——不是配置技巧问题，
而是服务端不再提供该认证方式。唯一的出路是 OAuth2 + `AUTHENTICATE XOAUTH2`。

为什么不引入 msal / google-auth
-------------------------------
两者都是可用的库，但对本项目而言代价不成比例：
  * 桌面客户端只需 **Device Code Flow**（RFC 8628）这一个流程——两次 POST，
    轮询一次 token 端点，总共不到 150 行；
  * 引入 msal 会带来一条独立的依赖链与它自己的 token 缓存目录（多一份需要
    加密/清理的落盘数据），而项目一直在「零新依赖」上保持一致；
  * 本项目只需要 `access_token` 与 `refresh_token` 两个字段，不需要图 API、
    不需要静默续期、不需要多租户缓存。
因此这里用标准库 `urllib` 手写，和 `platforms/proxy.py` 手写 SOCKS5 是同一取舍。

client_id 从哪来
----------------
OAuth 要求每个应用有自己的 `client_id`（公开客户端，不需要 client secret）。
本仓库不内置任何 client_id —— 内置的公共 client_id 会被滥用、随时可能被
提供方吊销，把它写进代码是给别人埋雷。请自行注册后通过环境变量提供：

    UNIMAIL_OAUTH_CLIENT_ID_OUTLOOK   Azure 门户 → 应用注册 → 移动和桌面应用
    UNIMAIL_OAUTH_CLIENT_ID_GMAIL     Google Cloud → OAuth 客户端 → 桌面应用

未配置时 `provider_for()` 抛 `OAuthError` 并给出注册指引，而不是让用户对着
一个「invalid_client」的英文报错猜。
"""
from __future__ import annotations

import base64
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

# 轮询与网络超时（秒）。token 端点的 POST 很轻，10 秒足够。
_HTTP_TIMEOUT = 15.0
# 刷新提前量：access_token 通常 1 小时，提前 2 分钟换，避免「刚好过期」的惊群。
_REFRESH_SKEW = 120


class OAuthError(RuntimeError):
    """OAuth 流程失败（网络、协议、授权被拒、client_id 缺失）。"""


@dataclass(frozen=True)
class _Spec:
    key: str
    display_name: str
    device_url: str
    token_url: str
    scope: str
    client_env: str
    register_hint: str


_SPECS: dict[str, _Spec] = {
    "outlook": _Spec(
        key="outlook",
        display_name="Outlook / Microsoft 365",
        device_url="https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
        token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",  # noqa: S106
        # offline_access 才会下发 refresh_token；IMAP 权限是独立的作用域，
        # 只申请 mail.read 不够——XOAUTH2 要的是 IMAP.AccessAsUser.All。
        scope="https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
        client_env="UNIMAIL_OAUTH_CLIENT_ID_OUTLOOK",
        register_hint=(
            "请在 Azure 门户「应用注册」中新建应用：账户类型选「任何组织目录中的"
            "账户和个人 Microsoft 账户」，平台选「移动和桌面应用程序」，"
            "启用「允许公共客户端流」；然后把应用（客户端）ID 填进环境变量 "
            "UNIMAIL_OAUTH_CLIENT_ID_OUTLOOK。"
        ),
    ),
    "gmail": _Spec(
        key="gmail",
        display_name="Gmail",
        device_url="https://oauth2.googleapis.com/device/code",
        token_url="https://oauth2.googleapis.com/token",  # noqa: S106
        # https://mail.google.com/ 覆盖 IMAP 全部权限（含 XOAUTH2）
        scope="https://mail.google.com/",
        client_env="UNIMAIL_OAUTH_CLIENT_ID_GMAIL",
        register_hint=(
            "请在 Google Cloud Console 创建项目 → 启用 Gmail API → "
            "「OAuth 同意屏幕」选外部并添加测试用户 → 创建「桌面应用」类型的"
            "OAuth 客户端；把客户端 ID 填进环境变量 "
            "UNIMAIL_OAUTH_CLIENT_ID_GMAIL。"
        ),
    ),
}


@dataclass(frozen=True)
class OAuthProvider:
    """一个已配置好 client_id 的 OAuth 服务方。"""

    spec: _Spec
    client_id: str

    @property
    def key(self) -> str:
        return self.spec.key

    @property
    def display_name(self) -> str:
        return self.spec.display_name


@dataclass
class DeviceCode:
    """设备授权流程第一步的返回。"""

    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int
    interval: int = 5
    message: str = ""


@dataclass
class TokenSet:
    """一次授权/刷新得到的令牌集合。

    `refresh_token` 在按 refresh_token 续期时**可能为空**（服务方不一定每次
    都下发新的），调用方必须沿用旧值，不能覆盖成空串。
    """

    access_token: str
    refresh_token: str = ""
    expires_at: float = 0.0
    token_type: str = "Bearer"  # noqa: S105
    scope: str = ""
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    def expired(self, *, skew: float = _REFRESH_SKEW, now: float | None = None) -> bool:
        if not self.expires_at:
            return False
        return (now or time.time()) >= self.expires_at - skew


def provider_for(platform: str) -> OAuthProvider:
    """按平台取 provider；client_id 未配置时给出注册指引而不是空指针。"""
    spec = _SPECS.get(platform)
    if spec is None:
        raise OAuthError(f"平台 {platform} 不使用 OAuth2")
    client_id = (os.environ.get(spec.client_env) or "").strip()
    if not client_id:
        raise OAuthError(
            f"{spec.display_name} 需要 OAuth2 授权，但本机还没有配置应用 ID。\n"
            f"{spec.register_hint}"
        )
    return OAuthProvider(spec=spec, client_id=client_id)


def oauth_supported(platform: str) -> bool:
    """该平台是否具备 OAuth2 能力（与「是否已配置 client_id」无关）。"""
    return platform in _SPECS


def client_configured(platform: str) -> bool:
    spec = _SPECS.get(platform)
    if spec is None:
        return False
    return bool((os.environ.get(spec.client_env) or "").strip())


def xoauth2_string(username: str, access_token: str) -> bytes:
    """构造 SASL XOAUTH2 的初始响应（RFC 7628 的 IMAP 用法）。

    格式固定为 `user=<邮箱>^Aauth=Bearer <token>^A^A`，其中 `^A` 是 \\x01。
    `imaplib.authenticate()` 会负责 base64，这里返回原始字节。
    """
    if not username or not access_token:
        raise OAuthError("XOAUTH2 需要邮箱地址与 access_token")
    return f"user={username}\x01auth=Bearer {access_token}\x01\x01".encode()


# ---------------------------------------------------------------- HTTP
def _post_form(url: str, data: dict[str, str]) -> dict[str, Any]:
    """向 OAuth 端点 POST 一个 form；把 HTTP 错误翻译成人话。

    token 端点在失败时会返回 JSON（`error` / `error_description`），
    直接抛 `HTTPError` 只会得到「HTTP Error 400: Bad Request」，
    对排查没有任何帮助。
    """
    body = urllib.parse.urlencode(data).encode("utf-8")
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme != "https":
        # 令牌只能走 HTTPS。这里显式拒绝而不是依赖调用方自觉：
        # 一旦某个 provider 的 URL 被改错，凭据就会明文上网。
        raise OAuthError(f"拒绝向非 HTTPS 地址发送授权请求：{scheme or '(空)'}")
    # scheme 已在上面限定为 https，这里的 S310 是误报
    req = urllib.request.Request(  # noqa: S310
        url, data=body, method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            # 部分网关会拒绝没有 UA 的请求
            "User-Agent": "UniMail/1.6",
        },
    )
    try:
        # scheme 已在上面限定为 https
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            payload = json.loads(exc.read().decode("utf-8", "replace"))
            detail = payload.get("error_description") or payload.get("error") or ""
        except (ValueError, TypeError):
            detail = ""
        if exc.code == 400 and detail:
            raise OAuthError(f"授权被拒绝：{detail}") from exc
        raise OAuthError(f"向 {urllib.parse.urlsplit(url).netloc} 请求失败：HTTP {exc.code}"
                         + (f"（{detail}）" if detail else "")) from exc
    except urllib.error.URLError as exc:
        raise OAuthError(
            f"无法连接授权服务器 {urllib.parse.urlsplit(url).netloc}：{exc.reason}\n"
            "若本机通过代理上网，OAuth 走的是 HTTPS —— 请确认 HTTPS_PROXY "
            "已设置且代理允许访问该域名。"
        ) from exc
    except (TimeoutError, OSError) as exc:
        raise OAuthError(f"连接授权服务器超时：{exc}") from exc


def request_device_code(provider: OAuthProvider) -> DeviceCode:
    """设备授权流程第 1 步：拿到 user_code 与验证地址。"""
    payload = _post_form(provider.spec.device_url, {
        "client_id": provider.client_id,
        "scope": provider.spec.scope,
    })
    device_code = payload.get("device_code") or ""
    user_code = payload.get("user_code") or ""
    uri = (payload.get("verification_uri")
           or payload.get("verification_url") or "")
    if not (device_code and user_code and uri):
        raise OAuthError("授权服务器返回的设备码不完整，请稍后重试")
    return DeviceCode(
        device_code=device_code,
        user_code=user_code,
        verification_uri=uri,
        expires_in=int(payload.get("expires_in") or 900),
        interval=max(1, int(payload.get("interval") or 5)),
        message=str(payload.get("message") or ""),
    )


def poll_token(provider: OAuthProvider, code: DeviceCode, *,
               cancel=None) -> TokenSet:
    """设备授权流程第 2 步：轮询直到用户完成授权或超时。

    `cancel` 是可选的 `threading.Event`：调用方（UI）取消时必须能停下来，
    否则关闭对话框后仍有一条线程在后台每 5 秒打一次 token 端点。
    """
    deadline = time.monotonic() + max(1, code.expires_in)
    interval = code.interval
    while time.monotonic() < deadline:
        if cancel is not None and cancel.is_set():
            raise OAuthError("已取消授权")
        payload = _post_form(provider.spec.token_url, {
            "client_id": provider.client_id,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": code.device_code,
        })
        error = payload.get("error")
        if not error:
            return _to_token_set(payload)
        if error == "authorization_pending":
            pass                       # 用户还没点完，继续等
        elif error == "slow_down":
            interval += 5              # 服务方要求降速，别再按原间隔打
        elif error == "expired_token":
            raise OAuthError("授权码已过期，请重新发起登录")
        elif error == "access_denied":
            raise OAuthError("用户拒绝了授权请求")
        else:
            raise OAuthError(
                f"授权失败：{payload.get('error_description') or error}")
        # 分段等待，保证取消能在 1 秒内生效
        end = time.monotonic() + interval
        while time.monotonic() < end:
            if cancel is not None and cancel.is_set():
                raise OAuthError("已取消授权")
            time.sleep(min(0.5, end - time.monotonic()))
    raise OAuthError("授权超时，请重新发起登录")


def refresh_access_token(provider: OAuthProvider,
                        refresh_token: str) -> TokenSet:
    """用 refresh_token 换新的 access_token。"""
    if not refresh_token:
        raise OAuthError("缺少 refresh_token，请重新授权")
    payload = _post_form(provider.spec.token_url, {
        "client_id": provider.client_id,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": provider.spec.scope,
    })
    if payload.get("error"):
        desc = payload.get("error_description") or payload["error"]
        # invalid_grant = refresh_token 已被吊销/过期/改密，只能重新走设备授权
        raise OAuthError(f"刷新令牌失败：{desc}")
    return _to_token_set(payload)


def _to_token_set(payload: dict[str, Any]) -> TokenSet:
    access = payload.get("access_token") or ""
    if not access:
        raise OAuthError("授权服务器没有返回 access_token")
    expires_in = int(payload.get("expires_in") or 0)
    return TokenSet(
        access_token=access,
        # 刷新时服务方可能不下发新的 refresh_token，保持空串由调用方沿用旧值
        refresh_token=str(payload.get("refresh_token") or ""),
        expires_at=time.time() + expires_in if expires_in else 0.0,
        token_type=str(payload.get("token_type") or "Bearer"),
        scope=str(payload.get("scope") or ""),
        raw=payload,
    )


def describe(platform: str) -> str:
    """给 UI 用的一句话状态（是否已配置应用 ID）。"""
    spec = _SPECS.get(platform)
    if spec is None:
        return "该平台不使用 OAuth2"
    if client_configured(platform):
        return f"已配置 {spec.display_name} 的 OAuth 客户端"
    return f"未配置 {spec.display_name} 的应用 ID（需设置 {spec.client_env}）"


def b64_xoauth2(username: str, access_token: str) -> str:
    """调试用：返回 base64 后的 XOAUTH2 串（测试断言握手载荷时使用）。"""
    return base64.b64encode(xoauth2_string(username, access_token)).decode("ascii")

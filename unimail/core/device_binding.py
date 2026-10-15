"""设备绑定免密解锁：用操作系统级的用户密钥保护主密钥。

威胁模型（必须先说清楚）
------------------------
「免密解锁」意味着**本机上任何能运行代码的、以当前用户身份登录的进程**
都能拿到主密钥——这包括用户自己误运行的程序。因此它换来的是便利，
付出的是「本机沦陷即邮件全量泄露」这一风险档次的提升。

基于这一点，本项目对它的定位是：

* **默认关闭**。必须由用户在设置里显式打开，并且打开时会看到这段风险说明。
* **只在有真实 OS 级保护的平台上提供**：Windows 用 DPAPI
  （绑定「当前用户 + 本机」，密文复制到别的机器上无法解开），
  macOS 用 Keychain（登录钥匙串）。其它平台 `available()` 返回 False，
  界面直接不显示这个开关，而不是退化成「把密钥明文存文件里」。
* **可以随时解绑**，解绑会删除保存的密文。

为什么不用 DPAPI 直接保护主密码
-------------------------------
直觉方案是把主密码存起来，解锁时替用户「输入」。但那样主密码会以明文
出现在进程内存里更长时间，而且一旦用户改了主密码，保存值就失效。
改为保存**主密钥**（`SecurityService.master_key_copy()`）后配合
`restore_from_master_key()` 恢复会话，路径更短：不需要重新跑
Argon2（64 MiB / 3 轮，实测约 0.4 s），也让「改主密码后自动解绑」
成为一个自然的失效点。
"""
from __future__ import annotations

import base64
import contextlib
import ctypes
import json
import logging
import os
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

from ..config import DATA_DIR

log = logging.getLogger(__name__)

BINDING_PATH = DATA_DIR / "device.key"
KEYCHAIN_SERVICE = "UniMail"
KEYCHAIN_ACCOUNT = "master-key"


# ---------------------------------------------------------------- Windows
class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> _DataBlob:
    buf = ctypes.create_string_buffer(data, len(data))
    return _DataBlob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def _blob_bytes(blob: _DataBlob) -> bytes:
    return ctypes.string_at(blob.pbData, blob.cbData)


def _dpapi_protect(data: bytes, entropy: bytes = b"") -> bytes:
    """调用 DPAPI 加密（`crypt32.dll`）。

    用 ctypes 直接调系统库而不是引入 `pywin32`：后者是个几十 MB 的依赖，
    而这里只需要两个函数。多一个重量级依赖会同时抬高打包体积与
    「某个平台装不上」的风险。
    """
    crypt32 = ctypes.windll.crypt32  # type: ignore[attr-defined]  # 仅 Windows 存在；Linux 上的 mypy 看不到
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]  # 仅 Windows 存在；Linux 上的 mypy 看不到

    in_blob = _blob(data)
    ent_blob = _blob(entropy) if entropy else None
    out_blob = _DataBlob()
    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "UniMail 设备绑定",
        ctypes.byref(ent_blob) if ent_blob else None,
        None,
        None,
        0x1,                      # CRYPTPROTECT_UI_FORBIDDEN：不弹任何系统框
        ctypes.byref(out_blob),
    )
    if not ok:
        raise OSError(f"CryptProtectData 失败（错误码 {ctypes.GetLastError()}）")  # type: ignore[attr-defined]
    try:
        return _blob_bytes(out_blob)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _dpapi_unprotect(data: bytes, entropy: bytes = b"") -> bytes:
    crypt32 = ctypes.windll.crypt32  # type: ignore[attr-defined]  # 仅 Windows 存在；Linux 上的 mypy 看不到
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]  # 仅 Windows 存在；Linux 上的 mypy 看不到

    in_blob = _blob(data)
    ent_blob = _blob(entropy) if entropy else None
    out_blob = _DataBlob()
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(ent_blob) if ent_blob else None,
        None,
        None,
        0x1,
        ctypes.byref(out_blob),
    )
    if not ok:
        # 换机器、换用户、或密文被改过都会走到这里——这不是「异常」，
        # 而是设计内的失效路径，调用方据此退回密码解锁。
        raise OSError(f"CryptUnprotectData 失败（错误码 {ctypes.GetLastError()}）")  # type: ignore[attr-defined]
    try:
        return _blob_bytes(out_blob)
    finally:
        kernel32.LocalFree(out_blob.pbData)


# ---------------------------------------------------------------- 平台适配
def _entropy(account_hint: str) -> bytes:
    """附加熵：把「数据目录」拌进去。

    这样即使用户把整个数据目录（含 device.key）复制到另一个账户下，
    DPAPI 本身已经拒绝了；再叠一层熵可以让「同一用户、不同数据目录」
    的两套库不会互相解开对方的绑定。
    """
    return str(DATA_DIR).encode("utf-8")


class DeviceBinding:
    """设备绑定状态的读写。

    不做任何 UI 判断——是否显示开关由设置对话框按 `available()` 决定。
    """

    def __init__(self, path: Path | None = None, platform: str | None = None) -> None:
        self.path = Path(path) if path else BINDING_PATH
        self.platform = platform or sys.platform
        self.last_error = ""

    # ------------------------------------------------------------ 能力
    @property
    def backend(self) -> str:
        if self.platform == "win32":
            return "dpapi"
        if self.platform == "darwin":
            return "keychain"
        return ""

    def available(self) -> bool:
        """当前平台是否提供可用的 OS 级保护。"""
        if self.backend == "dpapi":
            try:
                ctypes.windll.crypt32       # type: ignore[attr-defined]  # noqa: B018
                return True
            except (AttributeError, OSError):
                return False
        if self.backend == "keychain":
            return _which("security") is not None
        return False

    def describe(self) -> str:
        return {
            "dpapi": "Windows DPAPI（绑定当前用户与本机）",
            "keychain": "macOS 钥匙串（登录钥匙串）",
        }.get(self.backend, "当前系统不提供可用的设备绑定后端")

    # ------------------------------------------------------------ 状态
    def is_bound(self) -> bool:
        if not self.available():
            return False
        if self.backend == "keychain":
            return self._keychain_read() is not None
        return self.path.is_file()

    def bound_at(self) -> str:
        meta = self._read_meta()
        return str(meta.get("created_at") or "")

    # ------------------------------------------------------------ 写
    def bind(self, master_key: bytes, label: str = "") -> None:
        """把主密钥交给操作系统保护后落盘。"""
        if not self.available():
            raise RuntimeError(self.describe())
        import hashlib
        from datetime import datetime, timezone

        # 附一个主密钥的 SHA-256 作为**损坏检测**（不是防篡改）：
        # DPAPI 在某些配置下不会在解密时校验完整性，密文被同步盘/杀软
        # 改坏后会安静地解出一段错误的密钥。带上摘要就能当场失败，
        # 而不是让错误密钥一路流到「数据库打不开」。
        # 这不构成额外风险：文件与主密钥在同一台机器上，能读到它的人
        # 本来就能直接调用 DPAPI 取出主密钥。而 256 位随机密钥的
        # 哈希不存在字典攻击面。
        digest = hashlib.sha256(master_key).hexdigest()
        entropy = _entropy(label)
        if self.backend == "dpapi":
            blob = _dpapi_protect(master_key, entropy)
            payload = {
                "format": "unimail-device-binding",
                "version": 1,
                "backend": "dpapi",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "label": label,
                "digest": digest,
                "blob": base64.b64encode(blob).decode("ascii"),
            }
            self._atomic_write(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            # 钥匙串自己就是密文库：存 base64 只是为了放进命令行参数
            secret = base64.b64encode(master_key).decode("ascii")
            self._keychain_write(secret)
            self._atomic_write(json.dumps({
                "format": "unimail-device-binding",
                "version": 1,
                "backend": "keychain",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "label": label,
                "digest": digest,
            }, ensure_ascii=False, indent=2))

    def unbind(self) -> None:
        try:
            self.path.unlink(missing_ok=True)
        except OSError as exc:
            log.warning("删除设备绑定文件失败：%s", exc)
        if self.backend == "keychain":
            self._keychain_delete()

    # ------------------------------------------------------------ 读
    def recall(self) -> bytes | None:
        """取出主密钥；任何失败都返回 None（调用方退回密码解锁）。"""
        self.last_error = ""
        if not self.available():
            return None
        try:
            import hashlib
            payload = self._read_meta()
            if self.backend == "keychain":
                raw = self._keychain_read()
                if not raw:
                    return None
                key = base64.b64decode(raw)
            else:
                blob = base64.b64decode(payload["blob"])
                key = _dpapi_unprotect(blob, _entropy(payload.get("label") or ""))

            expect = payload.get("digest")
            if expect and hashlib.sha256(key).hexdigest() != expect:
                # 密文被改坏/被同步盘截断：宁可失败，也不要把错误的密钥
                # 交给上层（那会表现为「数据库打不开」，远比一句提示难排查）。
                self.last_error = "绑定数据完整性校验失败"
                log.warning("设备绑定数据已损坏，已忽略")
                return None
            return key
        except (OSError, KeyError, ValueError, TypeError) as exc:
            self.last_error = str(exc)
            log.info("设备绑定解密失败，将退回密码解锁：%s", exc)
            return None

    # ------------------------------------------------------------ 内部
    def _read_meta(self) -> dict:
        try:
            data = json.loads(self.path.read_text("utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError, TypeError):
            return {}

    def _atomic_write(self, text: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, self.path)
        # Windows 上 chmod 只影响只读位，语义有限；失败可容忍
        with contextlib.suppress(OSError):
            os.chmod(self.path, 0o600)

    # ------------------------------------------------------------ Keychain
    def _keychain_write(self, secret: str) -> None:
        self._keychain_delete()
        _run(["security", "add-generic-password",
              "-a", KEYCHAIN_ACCOUNT, "-s", KEYCHAIN_SERVICE,
              "-w", secret, "-U"])

    def _keychain_read(self) -> str | None:
        out = _run(["security", "find-generic-password",
                    "-a", KEYCHAIN_ACCOUNT, "-s", KEYCHAIN_SERVICE, "-w"],
                   check=False)
        return out.strip() if out else None

    def _keychain_delete(self) -> None:
        _run(["security", "delete-generic-password",
              "-a", KEYCHAIN_ACCOUNT, "-s", KEYCHAIN_SERVICE], check=False)


def _which(name: str) -> str | None:
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(folder) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def _run(args: list[str], check: bool = True) -> str:
    # 参数全部是本模块里写死的字面量（`security` 子命令），没有外部输入
    proc = subprocess.run(args, capture_output=True, text=True, timeout=10,  # noqa: S603
                          check=False)
    if check and proc.returncode != 0:
        raise OSError(proc.stderr.strip() or f"{args[0]} 返回 {proc.returncode}")
    return proc.stdout


__all__ = ["BINDING_PATH", "KEYCHAIN_ACCOUNT", "KEYCHAIN_SERVICE", "DeviceBinding"]

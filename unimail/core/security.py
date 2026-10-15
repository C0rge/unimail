"""安全服务：主密码派生、凭据加解密、登录校验、解锁退避。

三层加密模型：
    主密码 --KDF--> 主密钥 MK --HKDF--> 数据库密钥 / 凭据密钥 CK
设计原则：主密码与明文密钥只在内存中短暂存在，绝不落盘、绝不写日志。

KDF 选择（v1.3.0）：
    默认 **Argon2id**（memory-hard）。PBKDF2-HMAC-SHA256 是纯计算型 KDF，
    在 GPU 上比 CPU 快 2–3 个数量级；实测 600k 次派生仅 0.069 s、单核
    约 14 次/秒，配合「6 位密码」的现实下限，离线爆破门槛过低。
    参数写入 sidecar，因此**旧库仍以 PBKDF2 校验**，验证成功后再借
    改密码/升级流程渐进迁移到 Argon2id（见 KdfParams.algorithm）。
"""
from __future__ import annotations

import base64
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..config import (
    ARGON2_HASH_LEN,
    ARGON2_MEMORY_COST_KIB,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    KDF_ALGORITHM,
    KDF_ITERATIONS,
    KDF_SALT_BYTES,
    PASSWORD_MIN_LENGTH,
    UNLOCK_BACKOFF_BASE,
    UNLOCK_BACKOFF_MAX,
    guard_path,
)

log = logging.getLogger(__name__)

SUPPORTED_KDF = ("argon2id", "pbkdf2")

# Argon2id 需要 cryptography >= 44。旧版本下用不了它，但**不能因此让应用起不来**：
# 这里把名字标注为 Any 并按可用性赋值，调用点只需看 _ARGON2_AVAILABLE。
Argon2id: Any = None
_ARGON2_AVAILABLE = False
try:  # pragma: no cover - 依赖 cryptography 版本
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id as _Argon2id

    Argon2id = _Argon2id
    _ARGON2_AVAILABLE = True
except ImportError:  # pragma: no cover
    pass


class SecurityError(Exception):
    """安全相关错误（主密码错误、库损坏等）。"""


@dataclass
class KdfParams:
    """密钥派生参数。`algorithm` 决定用哪种 KDF，其余字段按算法解释。"""
    salt: bytes
    iterations: int                       # PBKDF2 迭代次数 / Argon2id time_cost
    algorithm: str = "pbkdf2"
    memory_cost: int = ARGON2_MEMORY_COST_KIB    # KiB，仅 Argon2id
    parallelism: int = ARGON2_PARALLELISM        # 仅 Argon2id
    hash_len: int = ARGON2_HASH_LEN

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "salt": base64.b64encode(self.salt).decode(),
            "iterations": self.iterations,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
            "hash_len": self.hash_len,
        }

    @classmethod
    def from_dict(cls, data: dict) -> KdfParams:
        try:
            salt = base64.b64decode(data["salt"])
        except (KeyError, ValueError, TypeError) as exc:
            raise SecurityError("安全元数据缺少可用的 salt 字段") from exc
        algorithm = str(data.get("algorithm") or "pbkdf2").lower()
        if algorithm not in SUPPORTED_KDF:
            # 不认识的算法绝不能「猜一种试试」——猜错会把「密码错误」
            # 和「算法不支持」混为一谈，用户会以为自己记错了密码。
            raise SecurityError(
                f"安全元数据使用了本版本不支持的密钥派生算法：{algorithm}。\n"
                "请使用较新版本的 UniMail 打开该数据目录。"
            )
        return cls(
            salt=salt,
            iterations=int(data.get("iterations") or KDF_ITERATIONS),
            algorithm=algorithm,
            memory_cost=int(data.get("memory_cost") or ARGON2_MEMORY_COST_KIB),
            parallelism=int(data.get("parallelism") or ARGON2_PARALLELISM),
            hash_len=int(data.get("hash_len") or ARGON2_HASH_LEN),
        )

    @property
    def display(self) -> str:
        if self.algorithm == "argon2id":
            return (f"Argon2id(m={self.memory_cost // 1024}MiB, "
                    f"t={self.iterations}, p={self.parallelism})")
        return f"PBKDF2-HMAC-SHA256({self.iterations} 次)"


def _derive_pbkdf2(password: str, salt: bytes, iterations: int, length: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=max(int(iterations), 1),
    )
    return kdf.derive(password.encode("utf-8"))


def derive_master_key(password: str, params: KdfParams) -> bytes:
    """按 params.algorithm 派生主密钥（唯一入口）。"""
    if params.algorithm == "argon2id":
        if not _ARGON2_AVAILABLE:
            raise SecurityError(
                "该数据目录使用 Argon2id 派生密钥，但当前 cryptography 版本过旧。\n"
                "请升级依赖后重试：pip install -U \"cryptography>=44\""
            )
        kdf = Argon2id(
            salt=params.salt,
            length=params.hash_len,
            iterations=max(int(params.iterations), 1),
            lanes=max(int(params.parallelism), 1),
            memory_cost=max(int(params.memory_cost), 8),
        )
        return kdf.derive(password.encode("utf-8"))
    return _derive_pbkdf2(password, params.salt, params.iterations, params.hash_len)


def password_policy_error(password: str) -> str | None:
    """返回不符合策略的原因；符合则返回 None。"""
    if len(password or "") < PASSWORD_MIN_LENGTH:
        return f"主密码至少 {PASSWORD_MIN_LENGTH} 位"
    return None


def password_strength(password: str) -> tuple[int, str]:
    """粗略强度评分 (0–4, 文案)，用于给用户即时反馈。"""
    pwd = password or ""
    kinds = sum([
        any(c.islower() for c in pwd),
        any(c.isupper() for c in pwd),
        any(c.isdigit() for c in pwd),
        any(not c.isalnum() for c in pwd),
    ])
    score = 0
    if len(pwd) >= PASSWORD_MIN_LENGTH:
        score += 1
    if len(pwd) >= 16:
        score += 1
    if kinds >= 3:
        score += 1
    if kinds >= 4 and len(pwd) >= PASSWORD_MIN_LENGTH:
        score += 1
    labels = [
        "太弱", "偏弱", "一般", "较强", "很强",
    ]
    if len(pwd) < PASSWORD_MIN_LENGTH:
        return 0, f"太短（至少 {PASSWORD_MIN_LENGTH} 位）"
    return score, labels[min(score, 4)]


class UnlockGuard:
    """解锁失败的持久化退避。

    失败 1 次等 1 s、2 次等 2 s、3 次等 4 s…上限 30 s。
    状态写入独立的小文件（只有计数与时间戳，无密钥），
    因此**重开程序不会把计数清零**——否则 3 次上限形同虚设。
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else guard_path()
        self._failures = 0
        self._next_allowed = 0.0
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text("utf-8"))
            self._failures = int(data.get("failures") or 0)
            self._next_allowed = float(data.get("next_allowed") or 0.0)
        except (OSError, ValueError, TypeError):
            self._failures = 0
            self._next_allowed = 0.0

    def _save(self) -> None:
        payload = json.dumps({
            "failures": self._failures,
            "next_allowed": self._next_allowed,
        })
        try:
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(payload, "utf-8")
            os.replace(tmp, self.path)
        except OSError as exc:  # 退避文件写不进去也不能阻止用户使用
            log.warning("写入解锁退避状态失败：%s", exc)

    @property
    def failures(self) -> int:
        return self._failures

    def remaining_wait(self) -> float:
        return max(0.0, self._next_allowed - time.monotonic())

    def check(self) -> None:
        wait = self.remaining_wait()
        if wait > 0:
            raise SecurityError(f"尝试过于频繁，请等待 {wait:.0f} 秒后重试")

    def record_failure(self) -> float:
        self._failures += 1
        delay = min(UNLOCK_BACKOFF_BASE * (2 ** (self._failures - 1)),
                    UNLOCK_BACKOFF_MAX)
        self._next_allowed = time.monotonic() + delay
        self._save()
        return delay

    def reset(self) -> None:
        self._failures = 0
        self._next_allowed = 0.0
        self._save()


def _derive_subkey(master_key: bytes, info: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
    return hkdf.derive(master_key)


class SecurityService:
    """持有会话级密钥，提供加解密能力。

    生命周期：
        - setup()  首次使用，生成 salt 并派生密钥
        - unlock() 后续启动，用主密码校验并派生密钥（返回 DB 密钥）
        - lock()   清空内存中的所有密钥
    """

    def __init__(self) -> None:
        self._master_key: bytes | None = None
        self._cred_key: bytes | None = None
        self._fernet: Fernet | None = None
        self._unlocked_at: float = 0.0

    # ------------------------------------------------------------ 状态
    @property
    def is_unlocked(self) -> bool:
        return self._master_key is not None

    def touch(self) -> None:
        """更新活跃时间，用于空闲自动锁定。"""
        self._unlocked_at = time.monotonic()

    def idle_seconds(self) -> float:
        if not self._unlocked_at:
            return 0.0
        return time.monotonic() - self._unlocked_at

    def lock(self) -> None:
        """清空所有驻留密钥。"""
        self._master_key = None
        self._cred_key = None
        self._fernet = None
        self._unlocked_at = 0.0

    # ------------------------------------------------------------ 初始化
    @staticmethod
    def new_kdf_params(algorithm: str | None = None) -> KdfParams:
        """生成一套新的 KDF 参数（默认跟随 config.KDF_ALGORITHM）。"""
        algo = (algorithm or KDF_ALGORITHM or "pbkdf2").lower()
        if algo == "argon2id" and not _ARGON2_AVAILABLE:
            log.warning("cryptography 版本不支持 Argon2id，回退为 PBKDF2")
            algo = "pbkdf2"
        if algo not in SUPPORTED_KDF:
            algo = "pbkdf2"
        if algo == "argon2id":
            return KdfParams(
                salt=os.urandom(KDF_SALT_BYTES),
                iterations=ARGON2_TIME_COST,
                algorithm="argon2id",
                memory_cost=ARGON2_MEMORY_COST_KIB,
                parallelism=ARGON2_PARALLELISM,
                hash_len=ARGON2_HASH_LEN,
            )
        return KdfParams(
            salt=os.urandom(KDF_SALT_BYTES),
            iterations=KDF_ITERATIONS,
            algorithm="pbkdf2",
            hash_len=32,
        )

    @staticmethod
    def needs_upgrade(params: KdfParams) -> bool:
        """旧库的 KDF 参数是否弱于当前默认（用于提示/渐进升级）。"""
        if params.algorithm != KDF_ALGORITHM:
            return True
        if params.algorithm == "pbkdf2":
            return params.iterations < KDF_ITERATIONS
        return (params.memory_cost < ARGON2_MEMORY_COST_KIB
                or params.iterations < ARGON2_TIME_COST)

    @staticmethod
    def make_verifier(master_key: bytes) -> str:
        """生成一条可校验主密码的密文（明文固定，仅用于校验）。"""
        f = Fernet(base64.urlsafe_b64encode(_derive_subkey(master_key, b"verifier")))
        return f.encrypt(b"unimail-verifier").decode("ascii")

    def setup(self, password: str, params: KdfParams) -> bytes:
        """首次设置主密码，返回数据库密钥。"""
        mk = derive_master_key(password, params)
        self._install_keys(mk)
        return self.db_key()

    def unlock(self, password: str, params: KdfParams, verifier: str) -> bytes:
        """用主密码解锁，校验失败抛 SecurityError。"""
        mk = derive_master_key(password, params)
        f = Fernet(base64.urlsafe_b64encode(_derive_subkey(mk, b"verifier")))
        try:
            plain = f.decrypt(verifier.encode("ascii"))
        except (InvalidToken, ValueError) as exc:
            # from None：把「解密失败」压成一句用户能看懂的话，
            # 不把 Fernet 的底层异常链暴露到 UI。
            raise SecurityError("主密码错误") from exc
        if not hmac.compare_digest(plain, b"unimail-verifier"):
            raise SecurityError("主密码错误")
        self._install_keys(mk)
        return self.db_key()

    def verify_password(self, password: str, params: KdfParams, verifier: str) -> bool:
        """只校验主密码是否正确，**不改动当前会话密钥**。

        用途：应用内锁屏后的重新认证（A.9）。不能复用 `unlock()`——
        那会重新派生密钥并覆盖当前会话；若用户输入的是某个旧密码而库刚被改过，
        覆盖失败或成功都会让内存里的会话与实际数据不一致。

        返回 False 表示密码不对（或参数/校验块不可用），不抛异常：
        调用方就是「错了就再让用户试一次」，异常在这里没有额外信息量。
        """
        try:
            mk = derive_master_key(password, params)
            f = Fernet(base64.urlsafe_b64encode(_derive_subkey(mk, b"verifier")))
            plain = f.decrypt(verifier.encode("ascii"))
        except (SecurityError, InvalidToken, ValueError, TypeError):
            return False
        return hmac.compare_digest(plain, b"unimail-verifier")

    def _install_keys(self, master_key: bytes) -> None:
        self._master_key = master_key
        self._cred_key = _derive_subkey(master_key, b"credentials")
        self._fernet = Fernet(base64.urlsafe_b64encode(self._cred_key))
        self.touch()

    def master_key_copy(self) -> bytes:
        """返回主密钥副本（供**显式开启**的设备绑定快速解锁使用）。

        刻意做成显式命名、且不在文档中当「常用接口」宣传：主密钥等价于主密码，
        任何拿到它的代码都能解开全部数据。除 `DeviceKeyStore` 外不应有调用方。
        """
        if self._master_key is None:
            raise SecurityError("安全服务未解锁")
        return self._master_key

    def restore_from_master_key(self, master_key: bytes) -> None:
        """用已保存的主密钥直接恢复会话（设备绑定免密解锁路径）。

        与 `unlock()` 的差别：不做 verifier 校验——调用方拿到的密钥要么来自
        操作系统凭据保护（Windows DPAPI / macOS Keychain），要么就是空。
        校验由 `DeviceKeyStore` 在更外层完成。
        """
        if not isinstance(master_key, (bytes, bytearray)) or len(master_key) < 16:
            raise SecurityError("设备绑定的密钥无效")
        self._install_keys(bytes(master_key))

    def change_password(self, old_password: str, params: KdfParams,
                        verifier: str, new_password: str) -> tuple[bytes, KdfParams, str]:
        """修改主密码：返回 (新DB密钥, 新KdfParams, 新verifier)。

        顺带把 KDF 升级到当前默认算法——改密码是唯一能安全更换 salt 的时机，
        因此旧 PBKDF2 库会在这一步自动升级为 Argon2id。
        注意：DB 重加密由调用方（Database.rekey）负责，本方法只派生新密钥。
        """
        # 先校验旧密码（按旧参数派生，兼容 PBKDF2 老库）
        mk_old = derive_master_key(old_password, params)
        f = Fernet(base64.urlsafe_b64encode(_derive_subkey(mk_old, b"verifier")))
        try:
            f.decrypt(verifier.encode("ascii"))
        except (InvalidToken, ValueError) as exc:
            raise SecurityError("原主密码错误") from exc

        new_params = self.new_kdf_params()
        mk_new = derive_master_key(new_password, new_params)
        self._install_keys(mk_new)
        return self.db_key(), new_params, self.make_verifier(mk_new)

    # ------------------------------------------------------------ 密钥
    def db_key(self) -> bytes:
        if self._master_key is None:
            raise SecurityError("安全服务未解锁")
        return _derive_subkey(self._master_key, b"database")

    # ------------------------------------------------------------ 凭据
    def encrypt_secret(self, plaintext: str) -> bytes:
        if self._fernet is None:
            raise SecurityError("安全服务未解锁")
        return self._fernet.encrypt(plaintext.encode("utf-8"))

    def decrypt_secret(self, ciphertext: bytes) -> str:
        if self._fernet is None:
            raise SecurityError("安全服务未解锁")
        try:
            return self._fernet.decrypt(ciphertext).decode("utf-8")
        except InvalidToken as exc:
            raise SecurityError("凭据解密失败（密钥不匹配）") from exc

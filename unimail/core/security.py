"""安全服务：主密码派生、凭据加解密、登录校验。

三层加密模型：
    主密码 --PBKDF2--> 主密钥 MK --HKDF--> 数据库密钥 / 凭据密钥 CK
设计原则：主密码与明文密钥只在内存中短暂存在，绝不落盘、绝不写日志。
"""
from __future__ import annotations

import base64
import hmac
import os
import time
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..config import KDF_ITERATIONS, KDF_SALT_BYTES


class SecurityError(Exception):
    """安全相关错误（主密码错误、库损坏等）。"""


@dataclass
class KdfParams:
    salt: bytes
    iterations: int


def _derive_master_key(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


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
    def new_kdf_params() -> KdfParams:
        return KdfParams(salt=os.urandom(KDF_SALT_BYTES), iterations=KDF_ITERATIONS)

    @staticmethod
    def make_verifier(master_key: bytes) -> str:
        """生成一条可校验主密码的密文（明文固定，仅用于校验）。"""
        f = Fernet(base64.urlsafe_b64encode(_derive_subkey(master_key, b"verifier")))
        return f.encrypt(b"unimail-verifier").decode("ascii")

    def setup(self, password: str, params: KdfParams) -> bytes:
        """首次设置主密码，返回数据库密钥。"""
        mk = _derive_master_key(password, params.salt, params.iterations)
        self._install_keys(mk)
        return self.db_key()

    def unlock(self, password: str, params: KdfParams, verifier: str) -> bytes:
        """用主密码解锁，校验失败抛 SecurityError。"""
        mk = _derive_master_key(password, params.salt, params.iterations)
        f = Fernet(base64.urlsafe_b64encode(_derive_subkey(mk, b"verifier")))
        try:
            plain = f.decrypt(verifier.encode("ascii"))
        except (InvalidToken, ValueError):
            raise SecurityError("主密码错误")
        if not hmac.compare_digest(plain, b"unimail-verifier"):
            raise SecurityError("主密码错误")
        self._install_keys(mk)
        return self.db_key()

    def _install_keys(self, master_key: bytes) -> None:
        self._master_key = master_key
        self._cred_key = _derive_subkey(master_key, b"credentials")
        self._fernet = Fernet(base64.urlsafe_b64encode(self._cred_key))
        self.touch()

    def change_password(self, old_password: str, params: KdfParams,
                        verifier: str, new_password: str) -> tuple[bytes, KdfParams, str]:
        """修改主密码：返回 (新DB密钥, 新KdfParams, 新verifier)。

        注意：DB 重加密由调用方（Database.rekey）负责，本方法只派生新密钥。
        """
        # 先校验旧密码
        mk_old = _derive_master_key(old_password, params.salt, params.iterations)
        f = Fernet(base64.urlsafe_b64encode(_derive_subkey(mk_old, b"verifier")))
        try:
            f.decrypt(verifier.encode("ascii"))
        except (InvalidToken, ValueError):
            raise SecurityError("原主密码错误")

        new_params = self.new_kdf_params()
        mk_new = _derive_master_key(new_password, new_params.salt, new_params.iterations)
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

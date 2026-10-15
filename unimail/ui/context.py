"""应用上下文：组装所有服务，管理数据库生命周期。"""
from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass

from ..config import DB_PATH
from ..core.events import EventBus
from ..core.security import KdfParams, SecurityError, SecurityService
from ..core.services import AccountService, MailService
from ..storage import (
    AccountRepository,
    AttachmentRepository,
    CursorRepository,
    Database,
    MailRepository,
)
from ..sync import BodyFetchPool, Scheduler, WorkerPool

log = logging.getLogger(__name__)


@dataclass
class ChangePasswordResult:
    """修改主密码的结果，用于向用户如实说明实际发生了什么。"""
    credentials_rotated: int = 0     # 成功重新加密的账号凭据数
    database_rekeyed: bool = False   # 数据库是否真的做了整库重加密


class AppContext:
    """持有全局单例服务，负责初始化与关闭。"""

    def __init__(self) -> None:
        self.db: Database | None = None
        self.security = SecurityService()
        self.bus = EventBus()
        self.accounts: AccountService | None = None
        self.mails: MailService | None = None
        self.scheduler: Scheduler | None = None
        self.pool: WorkerPool | None = None
        self.body_pool: BodyFetchPool | None = None
        self.is_first_run = not DB_PATH.exists()

    # ------------------------------------------------------------ 元数据
    @property
    def _sidecar(self):
        return DB_PATH.with_suffix(".meta.json")

    def _read_security_meta(self) -> tuple[KdfParams, str]:
        """读取 KDF 参数与校验块。

        salt 与迭代次数本身不是秘密（秘密是主密码），verifier 是密文，
        因此可安全地存放在明文 sidecar 中——这样在解锁前就能拿到派生参数。
        """
        if not self._sidecar.exists():
            raise SecurityError("找不到安全元数据文件，数据库可能已损坏")
        try:
            data = json.loads(self._sidecar.read_text("utf-8"))
            params = KdfParams(
                salt=base64.b64decode(data["salt"]),
                iterations=int(data["iterations"]),
            )
            return params, str(data["verifier"])
        except (KeyError, ValueError) as exc:
            raise SecurityError("安全元数据格式错误") from exc

    def _write_security_meta(self, params: KdfParams, verifier: str) -> None:
        self._sidecar.write_text(json.dumps({
            "salt": base64.b64encode(params.salt).decode(),
            "iterations": params.iterations,
            "verifier": verifier,
        }, indent=2), "utf-8")

    # ------------------------------------------------------------ 生命周期
    def bootstrap_new(self, password: str) -> None:
        """首次运行：生成 salt、设置主密码、建库。"""
        params = SecurityService.new_kdf_params()
        db_key = self.security.setup(password, params)
        self.db = Database(DB_PATH, db_key)
        verifier = SecurityService.make_verifier(self.security._master_key)  # noqa: SLF001
        self._write_security_meta(params, verifier)
        self._wire()
        log.info("已初始化新数据库，加密等级：%s", self.db.encryption_level)

    def unlock(self, password: str) -> None:
        """后续启动：校验主密码并解锁。"""
        params, verifier = self._read_security_meta()
        db_key = self.security.unlock(password, params, verifier)
        self.db = Database(DB_PATH, db_key)
        self._wire()
        log.info("数据库已解锁，加密等级：%s", self.db.encryption_level)

    def change_password(self, old: str, new: str) -> ChangePasswordResult:
        """修改主密码：重加密数据库 + 用新密钥重新加密所有邮箱凭据。

        关键顺序（顺序错误会导致凭据永久不可解）：
            1. 用**旧**密钥取出所有账号的明文密码（此时旧密钥仍有效）
            2. 换主密码，派生新密钥
            3. 重加密数据库整库（SQLCipher）
            4. 用**新**密钥重新加密全部凭据并写回
            5. 最后写入新的 KDF 元数据

        任一步失败都会回滚到旧密码状态，避免出现"库能用但凭据全废"的中间态。
        """
        if self.db is None or self.accounts is None:
            raise SecurityError("应用尚未初始化")

        params, verifier = self._read_security_meta()

        # ---- 步骤 1：先用旧密钥把明文凭据全部取出（内存中暂存）
        # 先校验旧密码，避免把明文凭据取出来之后才发现密码错
        plain_secrets: dict[str, str] = {}
        for account in self.accounts.list():
            try:
                plain_secrets[account.id] = self.accounts.reload_password(account)
            except SecurityError as exc:
                raise SecurityError(
                    f"账号 {account.email} 的凭据无法解密，已中止修改主密码"
                    f"（原密码可能不正确）：{exc}"
                ) from exc

        # ---- 步骤 2：校验旧密码并派生新密钥
        old_db_key = self.security.db_key()
        new_key, new_params, new_verifier = self.security.change_password(
            old, params, verifier, new
        )

        # ---- 步骤 3：重加密数据库
        new_key = self._rekey_database(old_db_key, new_key)

        # ---- 步骤 4：用新凭据密钥重新加密并写回
        rotated = len(plain_secrets)
        try:
            for account_id, plain in plain_secrets.items():
                self.accounts.accounts.put_credential(
                    account_id, self.security.encrypt_secret(plain)
                )
        except Exception as exc:  # noqa: BLE001
            # 凭据写回失败：回滚数据库密钥，保证状态一致
            log.exception("凭据重新加密失败，正在回滚")
            try:
                if self.db.rekey_supported:
                    self.db.rekey(old_db_key)
            except Exception:  # noqa: BLE001
                log.exception("回滚数据库密钥失败，可能需要从备份恢复")
            self.security.lock()
            raise SecurityError(f"凭据重新加密失败，主密码未变更：{exc}") from exc
        finally:
            # 明文凭据用完立即从内存清除
            plain_secrets.clear()

        # ---- 步骤 5：写入新元数据
        self._write_security_meta(new_params, new_verifier)
        log.info("主密码已更新，%d 个账号凭据已重新加密", rotated)

        return ChangePasswordResult(
            credentials_rotated=rotated,
            database_rekeyed=self.db.rekey_supported,
        )

    def _rekey_database(self, old_key: bytes, new_key: bytes) -> bytes:
        """重加密数据库。

        降级模式（无 SQLCipher）下数据库本身未加密，无需也不应调用 rekey；
        此时直接返回新密钥即可，由上层提示用户当前加密等级。
        """
        assert self.db is not None
        if not self.db.rekey_supported:
            log.warning("当前为降级模式（无 SQLCipher），数据库未整库加密，跳过 rekey")
            return new_key
        try:
            self.db.rekey(new_key)
            log.info("数据库已重新加密")
            return new_key
        except Exception as exc:  # noqa: BLE001
            # rekey 失败：把数据库密钥改回旧值，保持与旧主密码一致
            log.exception("数据库 rekey 失败，回滚到旧密钥")
            try:
                self.db.rekey(old_key)
            except Exception:  # noqa: BLE001
                log.exception("回滚数据库密钥同样失败，数据库可能需要从备份恢复")
            self.security.lock()
            raise SecurityError(
                f"数据库重新加密失败，主密码未变更：{exc}"
            ) from exc

    # ------------------------------------------------------------ 装配
    def _wire(self) -> None:
        assert self.db is not None
        account_repo = AccountRepository(self.db)
        mail_repo = MailRepository(self.db)
        attach_repo = AttachmentRepository(self.db)
        cursor_repo = CursorRepository(self.db)

        self.accounts = AccountService(account_repo, cursor_repo, self.security, self.bus)
        self.mails = MailService(mail_repo, attach_repo, account_repo,
                                 self.security, self.bus)
        self.pool = WorkerPool(self.accounts, mail_repo, cursor_repo,
                               self.security, self.bus)
        self.body_pool = BodyFetchPool(self.accounts, mail_repo, self.bus)
        self.scheduler = Scheduler(self.accounts, self.pool, self.bus)

    def shutdown(self) -> None:
        if self.scheduler:
            self.scheduler.stop()
        if self.pool:
            self.pool.stop_all()
        if self.body_pool:
            self.body_pool.stop_all()
        if self.db:
            self.db.close()
        self.security.lock()
        log.info("应用已安全关闭")

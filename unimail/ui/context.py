"""应用上下文：组装所有服务，管理数据库生命周期。"""
from __future__ import annotations

import base64
import json
import logging

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
from ..sync import Scheduler, WorkerPool

log = logging.getLogger(__name__)


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

    def change_password(self, old: str, new: str) -> None:
        """修改主密码并重加密数据库。"""
        params, verifier = self._read_security_meta()
        new_key, new_params, new_verifier = self.security.change_password(
            old, params, verifier, new
        )
        if self.db:
            self.db.rekey(new_key)
        self._write_security_meta(new_params, new_verifier)
        log.info("主密码已更新")

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
        self.scheduler = Scheduler(self.accounts, self.pool, self.bus)

    def shutdown(self) -> None:
        if self.scheduler:
            self.scheduler.stop()
        if self.pool:
            self.pool.stop_all()
        if self.db:
            self.db.close()
        self.security.lock()
        log.info("应用已安全关闭")

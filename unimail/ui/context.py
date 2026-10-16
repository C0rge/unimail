"""应用上下文：组装所有服务，管理数据库生命周期。"""
from __future__ import annotations

import json
import logging
import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..config import APP_VERSION, DB_PATH, KDF_ALGORITHM, sidecar_path
from ..core.device_binding import DeviceBinding
from ..core.events import EventBus
from ..core.security import (
    KdfParams,
    SecurityError,
    SecurityService,
    UnlockGuard,
    password_policy_error,
)
from ..core.services import AccountService, MailService
from ..storage import (
    AccountRepository,
    AttachmentRepository,
    CursorRepository,
    Database,
    DatabaseError,
    MailRepository,
    PendingFlagRepository,
    sqlcipher_available,
)
from ..sync import BodyFetchPool, Scheduler, SessionPool, WorkerPool

log = logging.getLogger(__name__)


def _fsync_file(path: Path) -> None:
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_write_json(path: Path, payload: dict) -> None:
    """原子写 JSON：临时文件 fsync → 旧文件备份为 .bak → `os.replace` 原子替换。

    侧车文件一旦半截损坏，salt 即丢失、加密数据库**永久无法解密**。
    因此绝不允许直接 `write_text` 覆盖。

    失败时（写入/fsync/replace 任一步抛错）必须清掉 `.tmp`：否则中断一次就
    在数据目录里留下一个残骸，反复失败会不断堆积。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())

        if path.exists():
            backup = path.with_name(path.name + ".bak")
            try:
                shutil.copy2(path, backup)
                _fsync_file(backup)
            except OSError:
                log.warning("安全元数据备份失败（继续写入主文件）", exc_info=True)

        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    _fsync_file(path)


@dataclass
class ChangePasswordResult:
    """修改主密码的结果，用于向用户如实说明实际发生了什么。"""
    credentials_rotated: int = 0     # 成功重新加密的账号凭据数
    database_rekeyed: bool = False   # 数据库是否真的做了整库重加密
    kdf: str = ""                    # 更新后实际使用的 KDF 参数描述


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
        # IMAP 保活会话池：每账号一条连接，避免「看附件就握手一次」。
        # 这里创建（而不是在 _wire 里）是为了让它在数据库重开时也保持不变，
        # 从而让「锁定/解锁」不会打断正在进行的同步。
        self.sessions = SessionPool()
        self.device_binding = DeviceBinding()
        self.is_first_run = not DB_PATH.exists()
        self.kdf_upgrade_pending = False      # 现有库的 KDF 参数是否弱于当前默认
        self._quiesced = False                # 「改密码 / 迁移加密」期间暂停后台 IO
        self._closed = False                  # 让 shutdown() 可重复调用

    @property
    def quiesced(self) -> bool:
        """是否正处于「排空后台写入」的维护窗口。

        改主密码 / 迁移数据库加密时，旧密钥建立的连接与半截事务都不能再产生。
        这个标志让 UI 层的新后台 IO（附件下载、导出、服务端删除）在此窗口内
        被直接拒绝——否则一个恰好在此时提交的 IMAP 往返可能在 rekey 之后才
        落盘，写出用旧密钥加密的行。
        """
        return self._quiesced

    # ------------------------------------------------------------ 元数据
    @property
    def _sidecar(self) -> Path:
        return sidecar_path(DB_PATH)

    def _read_security_meta(self) -> tuple[KdfParams, str, str | None]:
        """读取 KDF 参数、校验块与创建该库的驱动。

        salt 与迭代次数本身不是秘密（秘密是主密码），verifier 是密文，
        因此可安全地存放在明文 sidecar 中——这样在解锁前就能拿到派生参数。
        主文件不可用时自动回退到 `.bak`，并尝试自愈。
        """
        primary = self._sidecar
        backup = primary.with_name(primary.name + ".bak")
        failed: list[str] = []

        for path in (primary, backup):
            if not path.exists():
                failed.append(f"{path.name}（不存在）")
                continue
            try:
                data = json.loads(path.read_text("utf-8"))
                params = KdfParams.from_dict(data)
                verifier = str(data["verifier"])
                if not verifier:
                    raise ValueError("verifier 为空")
            except (KeyError, ValueError, TypeError, OSError, SecurityError) as exc:
                failed.append(f"{path.name}（{exc}）")
                log.error("安全元数据 %s 不可用：%s", path.name, exc)
                continue

            if path is not backup:
                return params, verifier, (data.get("driver") or None)

            # 主文件损坏 → 用备份自愈，避免下次启动又走一遍回退
            log.warning("主安全元数据不可用，已回退到备份 %s", backup.name)
            try:
                atomic_write_json(primary, data)
            except OSError:
                log.warning("备份自愈失败（不影响本次解锁）", exc_info=True)
            return params, verifier, (data.get("driver") or None)

        raise SecurityError(
            "无法读取安全元数据（salt / 校验块），主文件与备份均不可用。\n"
            f"目录：{primary.parent}\n"
            f"已尝试：{'; '.join(failed) or '未找到任何侧车文件'}\n"
            "如果你导出过「恢复包」，可将其中的 salt 与 iterations 手工写回 "
            f"{primary.name} 后重试。请勿删除数据库文件。"
        )

    def _write_security_meta(self, params: KdfParams, verifier: str,
                             driver: str | None = None) -> None:
        payload = params.to_dict()
        payload.update({
            "verifier": verifier,
            "driver": driver or (self.db.driver_name if self.db else ""),
            "app_version": APP_VERSION,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        atomic_write_json(self._sidecar, payload)

    def export_recovery_bundle(self, target: str | Path | None = None) -> Path:
        """导出恢复包：salt / KDF 参数 / 驱动，**不含任何密文**。

        侧车文件损坏时，用恢复包里的参数即可重新派生数据库密钥，
        避免「换块硬盘就与数据永久失联」。参数必须来自**实际读取到的那一份**，
        不能照抄当前默认值——旧库是 PBKDF2，照抄会导致恢复时派生不出同一密钥。
        """
        params, _verifier, driver = self._read_security_meta()
        dest = Path(target) if target else DB_PATH.with_name("unimail-recovery.json")
        kdf = params.to_dict()
        kdf.pop("hash_len", None)
        atomic_write_json(dest, {
            "format": "unimail-recovery-bundle",
            "version": 1,
            "app_version": APP_VERSION,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "kdf": kdf,
            "driver": driver or (self.db.driver_name if self.db else "unknown"),
            "database_file": DB_PATH.name,
            "note": "本文件不含密码或任何密文。恢复时把 kdf.salt / kdf.iterations "
                    "填回 *.meta.json 即可重新派生密钥。",
        })
        log.info("恢复包已导出：%s", dest)
        return dest

    # ------------------------------------------------------------ 生命周期
    def bootstrap_new(self, password: str) -> None:
        """首次运行：生成 salt、设置主密码、建库。

        密码策略在这里**再次**收口（UI 层已提示过一次）。原因是主密码是
        「整库明文邮件」的唯一屏障：只要有一个入口能设成 6 位口令，
        Argon2id 的参数再好也挡不住字典攻击。策略必须落在服务层，
        而不是只依赖某个对话框的实现。
        """
        policy_error = password_policy_error(password)
        if policy_error:
            raise SecurityError(policy_error)
        params = SecurityService.new_kdf_params()
        db_key = self.security.setup(password, params)
        # 环境具备 SQLCipher 时，首次建库就直接建成整库加密（确定性行为）
        self.db = Database(DB_PATH, db_key, encrypted=sqlcipher_available())
        verifier = SecurityService.make_verifier(self.security._master_key)  # noqa: SLF001
        self._write_security_meta(params, verifier, driver=self.db.driver_name)
        UnlockGuard().reset()          # 新建库不该继承上一个库的失败计数
        self.kdf_upgrade_pending = False
        self._wire()
        log.info("已初始化新数据库，加密等级：%s，KDF：%s",
                 self.db.encryption_level, params.display)

    def unlock(self, password: str) -> None:
        """后续启动：校验主密码并解锁。

        失败按次退避且**跨进程持久化**——否则「关掉重开」就能把尝试次数清零，
        3 次上限形同虚设。
        """
        guard = UnlockGuard()
        guard.check()
        params, verifier, driver = self._read_security_meta()
        try:
            db_key = self.security.unlock(password, params, verifier)
        except SecurityError:
            delay = guard.record_failure()
            log.warning("主密码校验失败（累计 %d 次），下次可尝试需等待 %.0f 秒",
                        guard.failures, delay)
            raise
        guard.reset()
        self.db = self._open_database(db_key, driver)
        # 驱动记录缺失或与实际情况不符时自愈，避免每次启动都要回退探测
        self._write_security_meta(params, verifier, driver=self.db.driver_name)
        self.kdf_upgrade_pending = SecurityService.needs_upgrade(params)
        if self.kdf_upgrade_pending:
            log.info("现有数据库使用较弱的 KDF 参数（%s），建议修改主密码以升级到 %s",
                     params.display, KDF_ALGORITHM)
        self._wire()
        log.info("数据库已解锁，加密等级：%s，KDF：%s",
                 self.db.encryption_level, params.display)

    def _open_database(self, db_key: bytes, driver: str | None) -> Database:
        """按 sidecar 记录的驱动打开数据库；记录缺失时双向回退探测。

        这是「降级/升级路径打通」的核心：明文库绝不能被当成加密库打开，
        否则 `PRAGMA key` 会让整个库报 `file is not a database`。
        """
        if driver == "sqlcipher":
            return Database(DB_PATH, db_key, encrypted=True)
        if driver == "sqlite3":
            return Database(DB_PATH, db_key, encrypted=False)

        # 旧版 sidecar 没有 driver 字段：先按当前环境能用的模式试一次，失败再试另一种
        log.warning("安全元数据缺少 driver 字段，正在自动探测数据库加密模式")
        errors: list[str] = []
        first = sqlcipher_available()
        for encrypted in (first, not first):
            try:
                db = Database(DB_PATH, db_key, encrypted=encrypted)
            except DatabaseError as exc:
                mode = "加密" if encrypted else "明文"
                log.warning("以 %s 模式打开失败：%s", mode, exc)
                errors.append(f"· 按{mode}模式打开：{exc.splitlines()[0]}")
                continue
            log.info("已探测到数据库实际模式：%s", db.driver_name)
            return db
        raise SecurityError(
            "数据库既无法以明文方式也无法以加密方式打开。\n"
            + "\n".join(errors) + "\n"
            "若其中提示缺少 sqlcipher3，请安装依赖后重试；"
            "请勿删除数据库文件，可先备份数据目录。"
        )

    def migrate_encryption(self, target: str) -> str:
        """在「明文」与「整库加密」之间迁移数据库，返回迁移后的驱动标识。"""
        if self.db is None:
            raise SecurityError("应用尚未初始化")
        if target not in ("encrypted", "plaintext"):
            raise ValueError(f"未知的迁移目标：{target}")
        if (target == "encrypted") == self.db.encrypted:
            return self.db.driver_name

        resume = self._quiesce()
        try:
            key = self.security.db_key()
            if target == "encrypted":
                self.db.migrate_to_encrypted(key)
            else:
                self.db.migrate_to_plaintext()
        finally:
            self._resume(resume)

        params, verifier, _driver = self._read_security_meta()
        self._write_security_meta(params, verifier, driver=self.db.driver_name)
        log.info("数据库加密模式已切换为：%s", self.db.encryption_level)
        return self.db.driver_name

    def _quiesce(self) -> bool:
        """迁移/改密码前停止后台同步并排空线程，避免旧连接中途写入。

        返回「调度器原本是否在运行」，供 `_resume()` 恢复。
        """
        resume = bool(self.scheduler and self.scheduler.enabled)
        # 先关门再排空：反过来的话，排空过程中新提交的任务会被栅栏「漏过去」，
        # 落在 rekey 之后才写库。
        self._quiesced = True
        if self.scheduler:
            self.scheduler.stop()
        if self.pool:
            self.pool.stop_all(timeout_ms=4000)
        if self.body_pool:
            # 用 cancel_running 而不是 stop_all：后者会 shutdown 线程池并永久
            # 置 _closed=True，而这条路径结束后应用还要继续运行 —— 那会让之后
            # 点开任何「无正文」邮件静默失效。
            self.body_pool.cancel_running(timeout=4.0)
        # 保活连接里带着**用旧主密码解出来的明文凭据**，必须一并丢弃：
        # 否则改完密码后这些连接仍能以旧凭据继续访问邮箱。
        # `close_all()` 是**同步摘除 + 异步断开**：一旦摘除，旧凭据就不可能再被
        # 任何 `borrow()` 取到（安全目标已达成），而带着网络往返的 `LOGOUT`
        # 交给后台线程，避免在这里再冻住主线程一次。
        self.sessions.close_all()
        return resume

    def _resume(self, resume: bool) -> None:
        # 兜底：正常路径下 cancel_running 不会关闭线程池，restart() 是空操作；
        # 但若某条路径确实把它关掉了，这里必须能恢复，否则正文补拉会静默失效。
        if self.body_pool:
            self.body_pool.restart()
        self._quiesced = False
        if resume and self.scheduler:
            self.scheduler.start()

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
        policy_error = password_policy_error(new)
        if policy_error:
            raise SecurityError(policy_error)

        params, verifier, _driver = self._read_security_meta()

        # ---- 步骤 0：暂停后台同步，避免旧密钥建立的连接与 rekey 竞态
        # 调度器必须在步骤 5 之后才恢复：否则 worker 会拿着还没重新加密的凭据去登录。
        resume = self._quiesce()
        succeeded = False
        try:
            result = self._change_password_locked(old, new, params, verifier)
            succeeded = True
            return result
        finally:
            # 成功、或失败但会话仍解锁（例如原密码输错）时恢复调度；
            # 若失败已导致 security.lock()，则保持停止，避免刷出一堆解密失败。
            if succeeded or self.security.is_unlocked:
                self._resume(resume)

    def _change_password_locked(self, old: str, new: str, params: KdfParams,
                                verifier: str) -> ChangePasswordResult:
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
        except Exception as exc:
            # 凭据写回失败：回滚数据库密钥，保证状态一致
            log.exception("凭据重新加密失败，正在回滚")
            try:
                if self.db.rekey_supported:
                    self.db.rekey(old_db_key)
            except Exception:
                log.exception("回滚数据库密钥失败，可能需要从备份恢复")
            self.security.lock()
            raise SecurityError(f"凭据重新加密失败，主密码未变更：{exc}") from exc
        finally:
            # 明文凭据用完立即从内存清除
            plain_secrets.clear()

        # ---- 步骤 5：写入新元数据
        self._write_security_meta(new_params, new_verifier, driver=self.db.driver_name)
        UnlockGuard().reset()
        self.kdf_upgrade_pending = False
        # 设备绑定保存的是**旧主密钥**，改密码后它必然失效。
        # 与其留着一个每次解锁都会失败的绑定，不如主动解绑并告知用户。
        if self.device_binding.is_bound():
            self.device_binding.unbind()
            log.info("主密码已变更，设备绑定已自动解除")
        log.info("主密码已更新，%d 个账号凭据已重新加密，KDF 现为 %s",
                 rotated, new_params.display)

        return ChangePasswordResult(
            credentials_rotated=rotated,
            database_rekeyed=self.db.rekey_supported,
            kdf=new_params.display,
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
        except Exception as exc:
            # rekey 失败：把数据库密钥改回旧值，保持与旧主密码一致
            log.exception("数据库 rekey 失败，回滚到旧密钥")
            try:
                self.db.rekey(old_key)
            except Exception:
                log.exception("回滚数据库密钥同样失败，数据库可能需要从备份恢复")
            self.security.lock()
            raise SecurityError(
                f"数据库重新加密失败，主密码未变更：{exc}"
            ) from exc

    # ------------------------------------------------------------ 装配
    def _wire(self) -> None:
        assert self.db is not None
        # 重新装配即意味着「维护窗口结束」：解锁 / 新建库都会走到这里，
        # 哪怕上一次改密码中途失败把 _quiesced 留在了 True。
        self._quiesced = False
        account_repo = AccountRepository(self.db)
        mail_repo = MailRepository(self.db)
        attach_repo = AttachmentRepository(self.db)
        cursor_repo = CursorRepository(self.db)
        pending_repo = PendingFlagRepository(self.db)

        self.accounts = AccountService(account_repo, cursor_repo, self.security,
                                       self.bus, pending_repo)
        self.mails = MailService(mail_repo, attach_repo, account_repo,
                                 self.security, self.bus, pending_repo)
        # core 层不能反向依赖 sync 层（会形成 import 循环），
        # 因此会话池由这里注入。
        self.mails.sessions = self.sessions
        self.pool = WorkerPool(self.accounts, mail_repo, cursor_repo,
                               self.security, self.bus, sessions=self.sessions)
        self.body_pool = BodyFetchPool(self.accounts, mail_repo, self.bus,
                                       sessions=self.sessions)
        self.scheduler = Scheduler(self.accounts, self.pool, self.bus,
                                   session_pool=self.sessions)

        # 清理孤儿附件文件：历史版本删邮件时只删数据库行，磁盘明文副本会残留
        try:
            self.mails.cleanup_orphan_attachments()
        except Exception:
            log.warning("清理孤儿附件失败", exc_info=True)

    def shutdown(self, *, stop_timeout_ms: int = 8000) -> list[str]:
        """停止后台工作 → 关闭连接 → 关闭数据库 → 清空密钥。

        返回「超时未能退出」的账号列表。调用方应据此如实提示用户，
        而不是假装干净退出——那些线程可能正持有半截事务。

        幂等：走托盘退出时 `MainWindow.quit_app()` 会调一次，进程收尾
        还会再兜一次底。第二次必须是无害的空操作，否则「关闭已关闭的
        数据库」会在退出路径上抛异常，把一次正常退出变成崩溃报告。
        """
        if self._closed:
            return []
        self._closed = True
        if self.scheduler:
            self.scheduler.stop()
        stragglers: list[str] = []
        if self.pool:
            stragglers = self.pool.stop_all(timeout_ms=stop_timeout_ms)
        if self.body_pool:
            self.body_pool.shutdown(timeout=stop_timeout_ms / 1000.0)
        # 断开连接可能会等 `LOGOUT` 的应答（死连接要等到 socket 超时），
        # 这里愿意等一小会儿，但**必须有上界** —— 否则一条连接就能把退出拖住。
        self.sessions.close_all(wait=True, timeout=3.0)
        if self.db:
            self.db.close()
        self.security.lock()
        log.info("应用已安全关闭")
        return stragglers

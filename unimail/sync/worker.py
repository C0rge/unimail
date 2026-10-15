"""邮件同步工作线程：单账号一次增量同步（在 QThread 中执行）。"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from PySide6.QtCore import QObject, QThread, Signal

from ..core.events import EventBus
from ..core.models import Account, AccountStatus
from ..core.security import SecurityError, SecurityService
from ..core.services import AccountService
from ..platforms import ImapError, get_adapter
from ..storage import CursorRepository, MailRepository

log = logging.getLogger(__name__)


class SyncWorker(QThread):
    """在后台线程中执行一次账号同步。

    流程：
        1. 取明文凭据（内存）
        2. 连接 IMAP
        3. 读增量游标，搜索新邮件 UID
        4. 拉取头部入库（快速填充列表）
        5. 拉取正文补齐（可选，逐封）
        6. 更新游标
    """

    progress = Signal(str, int)       # account_id, fetched
    finished_ok = Signal(str, int)    # account_id, new_count
    failed = Signal(str, str)         # account_id, error

    def __init__(self, account: Account, account_service: AccountService,
                 mails: MailRepository, cursors: CursorRepository,
                 security: SecurityService, bus: EventBus,
                 fetch_body_limit: int = 20, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.account = account
        self.account_service = account_service
        self.mails = mails
        self.cursors = cursors
        self.security = security
        self.bus = bus
        self.fetch_body_limit = fetch_body_limit
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    # ------------------------------------------------------------ 主流程
    def run(self) -> None:  # noqa: C901 - 线性流程，保持可读
        account = self.account
        adapter = get_adapter(account.platform)
        imap = None
        self.bus.sync_started.emit(account.id)
        self.account_service.set_status(account.id, AccountStatus.SYNCING)

        try:
            password = self.account_service.reload_password(account)
        except SecurityError as exc:
            self._fail(str(exc))
            return

        try:
            imap = adapter.connect(account, password)
            uid_validity = adapter.uid_validity(imap)
            last_uid, old_validity = self.cursors.get(account.id, "INBOX")

            # UIDVALIDITY 变化说明服务器端邮件序号已重置，需重新同步
            if old_validity and uid_validity and old_validity != uid_validity:
                log.warning("账号 %s UIDVALIDITY 变化，重置游标", account.email)
                last_uid = 0
            max_uid = last_uid
            new_count = 0

            uids = adapter.search_new_uids(imap, last_uid, limit=200)
            log.info("账号 %s 发现 %d 封新邮件", account.email, len(uids))

            # 第一阶段：拉头部，快速填充列表
            header_batch: list[tuple[str, object]] = []
            for uid in uids:
                if self._cancelled:
                    break
                try:
                    mail = adapter.fetch_headers(imap, uid, "INBOX")
                except ImapError as exc:
                    log.warning("拉取邮件头 %s 失败：%s", uid, exc)
                    continue
                mail_id = self.mails.insert_mail(account.id, account.platform, mail)
                if mail_id:
                    new_count += 1
                    header_batch.append((uid, mail))
                    max_uid = max(max_uid, int(uid))
                    self.progress.emit(account.id, new_count)

            # 第二阶段：为最新若干封补齐正文
            for uid, _ in header_batch[-self.fetch_body_limit:]:
                if self._cancelled:
                    break
                try:
                    full = adapter.fetch_message(imap, uid, "INBOX")
                    row = self.mails.db.query_one(
                        "SELECT id FROM mails WHERE account_id = ? AND folder = 'INBOX' AND uid = ?",
                        (account.id, str(uid)),
                    )
                    if row:
                        self.mails.update_body(row["id"], full.body_text, full.body_html)
                except ImapError as exc:
                    log.warning("拉取正文 %s 失败：%s", uid, exc)

            if max_uid > last_uid:
                self.cursors.upsert(account.id, "INBOX", max_uid, uid_validity)

            self.account_service.accounts.set_last_synced(account.id)
            self.account_service.set_status(account.id, AccountStatus.OK)
            self.finished_ok.emit(account.id, new_count)
            self.bus.sync_finished.emit(account.id, new_count)

        except ImapError as exc:
            self._fail(str(exc))
        except Exception as exc:  # noqa: BLE001
            log.exception("同步账号 %s 时发生未预期错误", account.email)
            self._fail(f"同步异常：{exc}")
        finally:
            if imap is not None:
                adapter.disconnect(imap)

    def _fail(self, message: str) -> None:
        self.account_service.set_status(self.account.id, AccountStatus.ERROR)
        self.failed.emit(self.account.id, message)
        self.bus.sync_error.emit(self.account.id, message)


class WorkerPool(QObject):
    """管理多个账号的同步线程，保证同一账号不并发同步。"""

    def __init__(self, account_service: AccountService, mails: MailRepository,
                 cursors: CursorRepository, security: SecurityService, bus: EventBus) -> None:
        super().__init__()
        self.account_service = account_service
        self.mails = mails
        self.cursors = cursors
        self.security = security
        self.bus = bus
        self._workers: dict[str, SyncWorker] = {}
        self._failures: dict[str, tuple[int, float]] = {}  # account_id -> (次数, 下次重试时间)

    def is_running(self, account_id: str) -> bool:
        w = self._workers.get(account_id)
        return w is not None and w.isRunning()

    def running_count(self) -> int:
        return sum(1 for w in self._workers.values() if w.isRunning())

    def dispatch(self, account: Account) -> bool:
        if self.is_running(account.id):
            return False

        # 指数退避：连续失败则推迟重试
        n_fail, next_at = self._failures.get(account.id, (0, 0.0))
        if n_fail > 0 and time.time() < next_at:
            return False

        worker = SyncWorker(account, self.account_service, self.mails,
                            self.cursors, self.security, self.bus)
        worker.finished_ok.connect(lambda aid, cnt: self._on_success(aid))
        worker.failed.connect(lambda aid, msg: self._on_failure(aid))
        worker.finished.connect(lambda aid=account.id: self._on_thread_done(aid))
        self._workers[account.id] = worker
        worker.start()
        return True

    def stop_all(self) -> None:
        for worker in list(self._workers.values()):
            worker.cancel()
        for worker in list(self._workers.values()):
            if worker.isRunning():
                worker.wait(3000)

    def _on_success(self, account_id: str) -> None:
        self._failures.pop(account_id, None)

    def _on_failure(self, account_id: str) -> None:
        n_fail, _ = self._failures.get(account_id, (0, 0.0))
        n_fail += 1
        delay = min(30 * (2 ** (n_fail - 1)), 1800)  # 30s → 30min 封顶
        self._failures[account_id] = (n_fail, time.time() + delay)

    def _on_thread_done(self, account_id: str) -> None:
        worker = self._workers.get(account_id)
        if worker is not None:
            worker.deleteLater()
        self._workers.pop(account_id, None)

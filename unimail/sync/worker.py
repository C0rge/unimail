"""邮件同步工作线程：单账号一次增量同步（在 QThread 中执行）。"""
from __future__ import annotations

import logging
import time

from PySide6.QtCore import QObject, QThread, Signal

from ..config import INITIAL_FETCH_LIMIT, MAX_FETCH_PER_RUN, SYNC_PAGE_SIZE
from ..core.events import EventBus
from ..core.models import Account, AccountStatus
from ..core.security import SecurityError, SecurityService
from ..core.services import AccountService
from ..platforms import ImapError, get_adapter
from ..storage import CursorRepository, MailRepository

log = logging.getLogger(__name__)

FOLDER = "INBOX"


class SyncWorker(QThread):
    """在后台线程中执行一次账号同步。

    流程：
        1. 取明文凭据（内存）
        2. 连接 IMAP
        3. 读增量游标并提供 UIDVALIDITY 失效检测
        4. 分页拉取头部入库（游标只推进到「连续已抓取区间」的最大 UID）
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
            server_validity = adapter.uid_validity(imap)
            last_uid, cursor_validity = self.cursors.get(account.id, FOLDER)

            # ---- UIDVALIDITY 语义修正
            # 服务器端邮箱被重建时 UID 会复用。此时本地副本全部失效：
            # 若不清理，新邮件会因唯一键 (account_id, folder, uid) 冲突被静默丢弃。
            # 判定依据取「本地邮件的 uid_validity」而不是只看游标，这样即使
            # 游标表丢失也不会漏判。
            stored_validities = self.mails.folder_uid_validities(account.id, FOLDER)
            invalidated = (
                bool(stored_validities) and server_validity is not None
                and server_validity not in stored_validities
            ) or (
                cursor_validity is not None and server_validity is not None
                and cursor_validity != server_validity and last_uid > 0
            )
            if invalidated:
                removed = self.mails.purge_folder(account.id, FOLDER)
                log.warning(
                    "账号 %s 的 UIDVALIDITY 已变化（本地=%s 服务端=%s），"
                    "已清理 %d 封过期本地副本并重置游标",
                    account.email, sorted(stored_validities) or cursor_validity,
                    server_validity, removed,
                )
                last_uid = 0

            new_count = 0
            new_pairs: list[tuple[str, str]] = []   # (uid, mail_id)，供第二阶段补正文
            cursor_uid = last_uid
            first_sync = last_uid <= 0
            page_size = max(int(INITIAL_FETCH_LIMIT), 1) if first_sync \
                else max(int(SYNC_PAGE_SIZE), 1)
            budget = MAX_FETCH_PER_RUN if first_sync else 0     # 0 = 不限
            fetched_this_run = 0

            # 分页循环：始终取「最旧的一批」并推进游标，直到追平服务端。
            # 这样既不会丢中间的邮件，也不会因单页上限而永远追不上。
            while not self._cancelled:
                uids = adapter.search_new_uids(imap, cursor_uid, limit=page_size)
                if not uids:
                    break
                log.info("账号 %s 本页发现 %d 封新邮件（游标 %s）",
                         account.email, len(uids), cursor_uid)

                page_continuous = True
                for uid in uids:
                    if self._cancelled:
                        page_continuous = False
                        break
                    try:
                        mail = adapter.fetch_headers(imap, uid, FOLDER)
                    except ImapError as exc:
                        # 单封失败即停止推进游标，下次同步从这里重试，
                        # 避免「跳过失败邮件后游标越过它」造成永久丢失。
                        log.warning("拉取邮件头 %s 失败，游标停在该封之前：%s", uid, exc)
                        page_continuous = False
                        break
                    mail_id = self.mails.insert_mail(
                        account.id, account.platform, mail, uid_validity=server_validity
                    )
                    cursor_uid = int(uid)      # 已入库（或已存在）→ 可安全推进
                    fetched_this_run += 1
                    if mail_id:
                        new_count += 1
                        new_pairs.append((uid, mail_id))
                        self.progress.emit(account.id, new_count)

                # 游标只推进到「连续已抓取区间」的最大 UID
                if cursor_uid > last_uid:
                    self.cursors.upsert(account.id, FOLDER, cursor_uid, server_validity)
                    last_uid = cursor_uid

                if not page_continuous or len(uids) < page_size:
                    break
                if budget and fetched_this_run >= budget:
                    log.info("账号 %s 首次同步达到单次上限 %d 封，其余邮件将在下次同步继续",
                             account.email, budget)
                    break

            # 第二阶段：为最新若干封补齐正文
            for uid, mail_id in new_pairs[-self.fetch_body_limit:]:
                if self._cancelled:
                    break
                try:
                    full = adapter.fetch_message(imap, uid, FOLDER)
                    self.mails.update_body(mail_id, full.body_text, full.body_html)
                except ImapError as exc:
                    log.warning("拉取正文 %s 失败：%s", uid, exc)

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

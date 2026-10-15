"""邮件同步工作线程：单账号一次增量同步（在 QThread 中执行）。"""
from __future__ import annotations

import logging
import time

from PySide6.QtCore import QObject, QThread, Signal

from ..config import INITIAL_FETCH_LIMIT, MAX_FETCH_PER_RUN, SYNC_PAGE_SIZE
from ..core.events import EventBus
from ..core.models import Account, AccountStatus, NormalizedMail
from ..core.security import SecurityError, SecurityService
from ..core.services import AccountService, unlink_attachment_file
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
    def run(self) -> None:
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
                removed, stale = self.mails.purge_folder(account.id, FOLDER)
                for path in stale:
                    unlink_attachment_file(path)
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

            # 每页一次性取回已入库 UID 集合，用于内存去重（避免逐封 exists()）
            known_uids = self.mails.existing_uids(
                account.id, FOLDER, uid_validity=server_validity
            )

            # 分页循环：始终取「最旧的一批」并推进游标，直到追平服务端。
            # 这样既不会丢中间的邮件，也不会因单页上限而永远追不上。
            while not self._cancelled:
                uids = adapter.search_new_uids(imap, cursor_uid, limit=page_size)
                if not uids:
                    break
                log.info("账号 %s 本页发现 %d 封新邮件（游标 %s）",
                         account.email, len(uids), cursor_uid)

                # ---- 阶段一：整页一次性拉头部（内存）后批量入库 ----
                page_continuous = True
                page: list[NormalizedMail] = []
                for uid in uids:
                    if self._cancelled:
                        page_continuous = False
                        break
                    try:
                        page.append(adapter.fetch_headers(imap, uid, FOLDER))
                    except ImapError as exc:
                        # 单封失败即停止推进游标，下次同步从这里重试，
                        # 避免「跳过失败邮件后游标越过它」造成永久丢失。
                        log.warning("拉取邮件头 %s 失败，游标停在该封之前：%s", uid, exc)
                        page_continuous = False
                        break
                    cursor_uid = int(uid)      # 已抓取 → 可安全推进游标
                    fetched_this_run += 1

                if page:
                    # 单事务 + executemany：实测 659–824 封/秒 → 11 800 封/秒
                    outcome = self.mails.insert_mails_batch(
                        account.id, account.platform, page,
                        uid_validity=server_validity, known_uids=known_uids,
                    )
                    new_count += outcome.new_count
                    new_pairs.extend(outcome.inserted)
                    if outcome.new_count:
                        self.progress.emit(account.id, new_count)
                    if outcome.conflicts:
                        # 「UID 被其它 UIDVALIDITY 占用」是数据异常，不能静默吞掉
                        log.warning(
                            "账号 %s 本页有 %d 封邮件因唯一键冲突被跳过"
                            "（本地 UIDVALIDITY 与服务端可能已不一致）",
                            account.email, outcome.conflicts,
                        )

                    # 阶段一补：BODYSTRUCTURE 一次拿到整页的附件元数据
                    # （只取邮件头是拿不到部件信息的，否则列表永远不会显示 📎）
                    self._attach_meta_for_page(
                        adapter, imap, account.id, [uid for uid, _ in outcome.inserted]
                    )

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

            # 第二阶段：为最新若干封补齐正文（整批一次 executemany）
            body_rows: list[tuple[str, str, str]] = []
            for uid, mail_id in new_pairs[-self.fetch_body_limit:]:
                if self._cancelled:
                    break
                try:
                    full = adapter.fetch_message(imap, uid, FOLDER)
                except ImapError as exc:
                    log.warning("拉取正文 %s 失败：%s", uid, exc)
                    continue
                body_rows.append((mail_id, full.body_text, full.body_html))
                # 全文解析顺带带来更完整的附件信息（含 content_id），按 part 号对齐回填
                if full.attachments:
                    for path in self.mails.replace_attachments(mail_id, full.attachments):
                        unlink_attachment_file(path)
            self.mails.update_bodies_batch(body_rows)

            self.account_service.accounts.set_last_synced(account.id)
            self.account_service.set_status(account.id, AccountStatus.OK)
            self.finished_ok.emit(account.id, new_count)
            self.bus.sync_finished.emit(account.id, new_count)

        except ImapError as exc:
            self._fail(str(exc))
        except Exception as exc:
            log.exception("同步账号 %s 时发生未预期错误", account.email)
            self._fail(f"同步异常：{exc}")
        finally:
            if imap is not None:
                adapter.disconnect(imap)

    def _attach_meta_for_page(self, adapter, imap, account_id: str,
                              uids: list[str]) -> None:
        """用 BODYSTRUCTURE 为整页新入库的邮件补上附件元数据。

        这是「列表里能看到 📎、点开能下载」的前提：只取 `BODY.PEEK[HEADER]`
        的同步路径拿不到任何部件信息，此前附件信息**永远为空**。
        开销是每页 1 次往返（不是每封 1 次）；失败只记日志，不影响同步结果。
        """
        if not uids:
            return
        try:
            metas_by_uid = adapter.fetch_attachment_meta(imap, uids, FOLDER)
        except Exception as exc:  # noqa: BLE001 - 附加信息，不拖垮同步
            log.debug("获取附件元数据失败：%s", exc)
            return
        if not metas_by_uid:
            return
        mail_ids = self.mails.ids_by_uid(account_id, FOLDER, list(metas_by_uid))
        for uid, metas in metas_by_uid.items():
            mail_id = mail_ids.get(str(uid))
            if not mail_id:
                continue
            for path in self.mails.replace_attachments(mail_id, metas):
                unlink_attachment_file(path)

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

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
from .session import SessionPool

log = logging.getLogger(__name__)

FOLDER = "INBOX"


def sync_task_id(account_id: str) -> str:
    """任务面板用的稳定 id：同一账号的多次同步归并成一条。"""
    return f"sync:{account_id}"


class SyncWorker(QThread):
    """在后台线程中执行一次账号同步。

    流程：
        1. 取明文凭据（内存）
        2. 取用该账号的保活会话（无会话池时新建一次性连接）
        3. 读增量游标并提供 UIDVALIDITY 失效检测
        4. 分页拉取头部入库（游标只推进到「连续已抓取区间」的最大 UID）
        5. 拉取正文补齐（可选，逐封）
        6. 更新游标

    取消语义（P11）：`cancel()` 会把标志位置真并**关掉底层 socket**。
    只置标志是不够的——线程可能正阻塞在一次网络读上，要等到 TCP 超时
    （最长 30 s）才会看到标志位，退出流程会一直卡住。
    """

    progress = Signal(str, int)       # account_id, fetched
    finished_ok = Signal(str, int)    # account_id, new_count
    failed = Signal(str, str)         # account_id, error

    def __init__(self, account: Account, account_service: AccountService,
                 mails: MailRepository, cursors: CursorRepository,
                 security: SecurityService, bus: EventBus,
                 fetch_body_limit: int = 20, parent: QObject | None = None,
                 sessions: SessionPool | None = None) -> None:
        super().__init__(parent)
        self.account = account
        self.account_service = account_service
        self.mails = mails
        self.cursors = cursors
        self.security = security
        self.bus = bus
        self.fetch_body_limit = fetch_body_limit
        self.sessions = sessions
        self._cancelled = False
        self._interrupted = False

    # ------------------------------------------------------------ 取消
    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def cancel(self) -> None:
        """请求取消：置标志 + 打断阻塞中的连接。"""
        self._cancelled = True
        self._interrupt_connection()

    def _interrupt_connection(self) -> None:
        self._interrupted = True
        if self.sessions is not None:
            self.sessions.interrupt_account(self.account.id)

    # ------------------------------------------------------------ 主流程
    def run(self) -> None:
        account = self.account
        adapter = get_adapter(account.platform)
        task = sync_task_id(account.id)
        self.bus.sync_started.emit(account.id)
        self.bus.task_started.emit(task, f"同步 {account.email}")
        self.account_service.set_status(account.id, AccountStatus.SYNCING)

        try:
            password = self.account_service.reload_password(account)
        except SecurityError as exc:
            self._fail(str(exc))
            return

        try:
            if self.sessions is not None:
                # 保活会话：一次握手服务多次同步/下载
                with self.sessions.borrow(account, password) as imap:
                    self._sync(adapter, imap)
            else:
                imap = adapter.connect(account, password)
                try:
                    self._sync(adapter, imap)
                finally:
                    adapter.disconnect(imap)
        except ImapError as exc:
            self._fail(self._cancel_message(str(exc)))
        except Exception as exc:
            log.exception("同步账号 %s 时发生未预期错误", account.email)
            self._fail(self._cancel_message(f"同步异常：{exc}"))

    def _cancel_message(self, message: str) -> str:
        if self._cancelled:
            return "已被用户取消"
        return message

    def _sync(self, adapter, imap) -> None:
        account = self.account
        # 任务 id 与 `run()` 里发 `task_started` 用的是同一个值。`_sync` 会被
        # 会话池分支和一次性连接分支共用，因此在这里重新取一次而不是靠参数传递。
        task = sync_task_id(account.id)

        # ---- 先把离线期间攒下的服务端标记动作补齐（只读/星标双向同步）
        self._flush_pending_flags(adapter, imap)

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
        inserted_total = 0

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
                inserted_total += outcome.new_count
                if outcome.new_count:
                    self.progress.emit(account.id, new_count)
                    self.bus.sync_progress.emit(account.id, new_count)
                    self.bus.task_progress.emit(task, new_count, -1)
                    # 带负载事件：UI 可直接增量插入，不必整表重查
                    self.bus.mails_inserted.emit(
                        account.id, [mail_id for _uid, mail_id in outcome.inserted]
                    )
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
        self.bus.task_finished.emit(
            sync_task_id(account.id), True,
            f"新增 {new_count} 封" if new_count else "已是最新",
        )

    # ------------------------------------------------------------ 服务端标记
    def _flush_pending_flags(self, adapter, imap) -> None:
        """把离线期间攒下的「标已读 / 星标」动作推回服务器。

        失败不阻塞同步：留在队列里下次再试（网络抖动是常态，
        本地状态已经在用户点击时生效，没必要让同步因此失败）。
        """
        store = getattr(self.account_service, "pending_flags", None)
        if store is None:
            return
        try:
            pending = store.list_for_account(self.account.id)
        except Exception:
            log.debug("读取待同步标记失败", exc_info=True)
            return
        for item in pending:
            if self._cancelled:
                return
            try:
                adapter.store_flags(imap, str(item["uid"]), folder=item["folder"],
                                    add=item["add_flags"], remove=item["remove_flags"])
            except (ImapError, AttributeError, NotImplementedError) as exc:
                log.debug("推送标记失败，保留待下次同步：%s", exc)
                return
            except Exception as exc:  # noqa: BLE001
                log.debug("推送标记异常，保留待下次同步：%s", exc)
                return
            store.remove(item["id"])
        if pending:
            log.info("已向服务器同步 %d 条标记变更", len(pending))

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
        self.bus.task_finished.emit(sync_task_id(self.account.id), False, message)


class WorkerPool(QObject):
    """管理多个账号的同步线程，保证同一账号不并发同步。"""

    def __init__(self, account_service: AccountService, mails: MailRepository,
                 cursors: CursorRepository, security: SecurityService, bus: EventBus,
                 sessions: SessionPool | None = None) -> None:
        super().__init__()
        self.account_service = account_service
        self.mails = mails
        self.cursors = cursors
        self.security = security
        self.bus = bus
        self.sessions = sessions
        self._workers: dict[str, SyncWorker] = {}
        self._failures: dict[str, tuple[int, float]] = {}  # account_id -> (次数, 下次重试时间)

    def is_running(self, account_id: str) -> bool:
        w = self._workers.get(account_id)
        return w is not None and w.isRunning()

    def running_count(self) -> int:
        return sum(1 for w in self._workers.values() if w.isRunning())

    def running_accounts(self) -> list[str]:
        return [aid for aid, w in self._workers.items() if w.isRunning()]

    def dispatch(self, account: Account) -> bool:
        if self.is_running(account.id):
            return False

        # 指数退避：连续失败则推迟重试
        n_fail, next_at = self._failures.get(account.id, (0, 0.0))
        if n_fail > 0 and time.time() < next_at:
            return False

        worker = SyncWorker(account, self.account_service, self.mails,
                            self.cursors, self.security, self.bus,
                            sessions=self.sessions)
        worker.finished_ok.connect(lambda aid, cnt: self._on_success(aid))
        worker.failed.connect(lambda aid, msg: self._on_failure(aid))
        worker.finished.connect(lambda aid=account.id: self._on_thread_done(aid))
        self._workers[account.id] = worker
        worker.start()
        return True

    def cancel_account(self, account_id: str) -> bool:
        """取消指定账号正在进行的同步（任务面板的「取消」按钮）。"""
        worker = self._workers.get(account_id)
        if worker is None or not worker.isRunning():
            return False
        worker.cancel()
        return True

    def stop_all(self, timeout_ms: int = 8000) -> list[str]:
        """取消全部任务并等待线程退出；返回超时未退出的账号 id。

        等待是必须的：任务线程正在写数据库，进程退出时硬杀会留下半截事务。
        返回值让调用方可以如实告知用户「还有任务没结束」，而不是假装干净退出。
        """
        workers = list(self._workers.values())
        for worker in workers:
            worker.cancel()
        deadline = time.monotonic() + max(0.0, timeout_ms / 1000.0)
        stragglers: list[str] = []
        for worker in workers:
            left_ms = int((deadline - time.monotonic()) * 1000)
            if left_ms <= 0 or not worker.isRunning():
                if worker.isRunning():
                    stragglers.append(worker.account.id)
                continue
            if not worker.wait(left_ms):
                stragglers.append(worker.account.id)
        if stragglers:
            log.warning("以下账号的同步任务未能在超时内结束：%s", stragglers)
        return stragglers

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

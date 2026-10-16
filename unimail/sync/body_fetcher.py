"""按需/预取邮件正文：有界并发的后台补拉。

改造要点（v1.5.0，P9）
----------------------
此前每次补拉都新建一条 `QThread` 并各自完成「TCP + TLS + LOGIN」：
并发打开 10 封邮件就是 10 次握手、10 条连接，账号多时既慢又容易被
服务端判定为异常登录。现在改为：

* 复用 `SessionPool` 的保活会话（同账号串行、跨账号并行）；
* 用 `ThreadPoolExecutor` 限制总并发（`max_workers = min(4, CPU)`）；
* 提供 `prefetch()` 后台预取可见行，点开即显，不再出现「正在拉取正文…」。

这个线程池同时也是**全应用的后台 IO 池**（v1.5.0，P1）：附件下载/预览、内嵌图
下载、`.eml` / `.mbox` 导出、「移入服务器垃圾箱」的批量删除都通过
`submit_generic()` 提交进来。它们和正文补拉本质上是同一类东西——一次或多次
网络往返 + 落盘，都要在后台跑，也都希望共享同一套限流、取消与关停语义。
"""
from __future__ import annotations

import contextlib
import logging
import os
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any

from ..core.events import EventBus
from ..core.security import SecurityError
from ..core.services import AccountService, unlink_attachment_file
from ..platforms import ImapError, get_adapter
from ..storage import MailRepository
from .session import SessionPool

log = logging.getLogger(__name__)


def default_workers() -> int:
    """并发上限：4 或 CPU 数，取小者。

    再大没有收益——瓶颈是单条 IMAP 连接的往返延迟，而不是本地计算。
    """
    return max(1, min(4, os.cpu_count() or 2))


class BodyFetchPool:
    """管理正文补拉任务：去重、限流、可取消。

    同时充当全应用的后台 IO 池（见 `submit_generic()`）：两者共用同一个
    `ThreadPoolExecutor`、同一套生命周期钩子。
    """

    def __init__(self, account_service: AccountService, mails: MailRepository,
                 bus: EventBus, sessions: SessionPool | None = None,
                 max_workers: int | None = None) -> None:
        self.account_service = account_service
        self.mails = mails
        self.bus = bus
        self.sessions = sessions
        self._max_workers = max_workers or default_workers()
        self._executor = self._new_executor()
        # `_futures` / `_requested` 会被两条线程同时改：主线程在
        # `request/prefetch/stop_all` 里写，executor 线程在 `_finalize`
        # （`add_done_callback` 的回调，在**完成该 future 的线程**执行）里写。
        # 没有这把锁时会抛 `RuntimeError: set/dict changed size during iteration`，
        # 或者 `_requested` 计数错乱导致同一封被重复提交、或永远显示「拉取中」。
        self._lock = threading.Lock()
        self._futures: dict[str, Future] = {}
        self._requested: set[str] = set()
        self._closed = False

    def _new_executor(self) -> ThreadPoolExecutor:
        return ThreadPoolExecutor(
            max_workers=self._max_workers,
            thread_name_prefix="unimail-body",
        )

    # ------------------------------------------------------------ 查询
    def is_pending(self, mail_id: str) -> bool:
        with self._lock:
            return mail_id in self._requested

    def pending_count(self) -> int:
        with self._lock:
            return len(self._requested)

    # ------------------------------------------------------------ 提交
    def request(self, mail_id: str) -> bool:
        """补拉一封正文；已在队列中则返回 False。"""
        row = self.mails.body_fetch_info(mail_id)
        if row is None:
            return False
        # 已经有正文就不用再拉（点开已缓存邮件不该触发网络请求）
        if row.get("has_body"):
            return False
        return self._submit(mail_id, dict(row), task_id=f"body:{mail_id}",
                            label="拉取正文")

    def prefetch(self, mail_ids: list[str], limit: int = 12) -> int:
        """后台预取一批邮件的正文（列表可见行）。

        只预取「还没有正文」的，且每批不超过 `limit` 封——预取是锦上添花，
        不能挤占用户真正要等的那个请求。
        """
        n = 0
        for mail_id in mail_ids:
            if n >= limit:
                break
            with self._lock:
                if mail_id in self._requested:
                    continue
            if self.request(mail_id):
                n += 1
        if n:
            log.debug("已提交 %d 封邮件的正文预取", n)
        return n

    def _submit(self, mail_id: str, row: dict, task_id: str, label: str) -> bool:
        with self._lock:
            if self._closed or mail_id in self._requested:
                return False
            self._requested.add(mail_id)
            try:
                fut = self._executor.submit(self._work, mail_id, row)
            except RuntimeError:
                # 线程池已关闭（与 shutdown 的竞态）：撤回登记，别让这封
                # 永远停在「拉取中」
                self._requested.discard(mail_id)
                return False
            self._futures[mail_id] = fut
        self.bus.task_started.emit(task_id, f"{label} {mail_id[:8]}")

        def _done(f: Future, mid: str = mail_id) -> None:
            self._finalize(mid, f)

        fut.add_done_callback(_done)
        return True

    # ------------------------------------------------------------ 通用 IO
    def submit_generic(self, fn: Callable[[], Any]) -> Future:
        """把一段阻塞式代码提交到**同一个**线程池执行，返回其 `Future`。

        附件下载/预览、内嵌图下载、`.eml` / `.mbox` 导出、服务端批量删除都走
        这里。刻意不另起第二个线程池：第二个池等于第二套「关停 / 取消 / 重启」
        语义，而 C3、C6 已经说明这类竞态是本项目最容易出错的地方。

        调用方负责把异常与结果带回主线程（UI 层用 `IoTaskRunner`）。
        `RuntimeError` 表示池已关闭（退出流程中的竞态），调用方需自行处理。
        """
        with self._lock:
            if self._closed:
                raise RuntimeError("后台 IO 线程池已关闭")
        return self._executor.submit(fn)

    # ------------------------------------------------------------ 执行
    def _work(self, mail_id: str, row: dict) -> tuple[str, str]:
        account = self.account_service.get(row["account_id"])
        if account is None:
            raise LookupError("账号不存在")
        platform = row.get("platform") or account.platform
        adapter = get_adapter(platform)
        folder = row.get("folder") or "INBOX"
        uid = str(row["uid"])

        password = self.account_service.reload_password(account)

        def _fetch(imap):
            # 只读 select 被拒绝不影响后续 FETCH（连接时通常已默认选中 INBOX）
            with contextlib.suppress(Exception):
                imap.select(folder, readonly=True)
            return adapter.fetch_message(imap, uid, folder)

        if self.sessions is not None:
            with self.sessions.borrow(account, password) as imap:
                full = _fetch(imap)
        else:
            imap = adapter.connect(account, password)
            try:
                full = _fetch(imap)
            finally:
                adapter.disconnect(imap)

        self.mails.update_body(mail_id, full.body_text, full.body_html)
        # 全文解析能给出最完整的附件信息（含 content_id / 精确文件名），
        # 按 part 编号对齐回填；此前这里只写正文，附件元数据被直接丢弃，
        # 导致「点开邮件也看不到附件列表」。
        if full.attachments:
            for path in self.mails.replace_attachments(mail_id, full.attachments):
                unlink_attachment_file(path)
        return mail_id, ""

    def _finalize(self, mail_id: str, fut: Future) -> None:
        with self._lock:
            self._futures.pop(mail_id, None)
            self._requested.discard(mail_id)
        task_id = f"body:{mail_id}"
        try:
            fut.result()
        except (ImapError, SecurityError, LookupError) as exc:
            log.warning("正文补拉失败 mail=%s: %s", mail_id[:8], exc)
            self.bus.task_finished.emit(task_id, False, str(exc))
            return
        except Exception as exc:
            log.exception("补拉正文异常")
            self.bus.task_finished.emit(task_id, False, f"补拉正文异常：{exc}")
            return
        self.bus.mail_updated.emit(mail_id)
        self.bus.task_finished.emit(task_id, True, "正文已加载")

    # ------------------------------------------------------------ 生命周期
    def cancel_running(self, timeout: float = 4.0) -> None:
        """取消并等待当前在跑的任务，但**保留线程池**，之后仍可继续提交。

        用于「改主密码 / 迁移数据库加密」这类需要排空后台写入、而应用还要继续
        运行的场景。此前这里直接调 `stop_all()`，它会 `shutdown()` 线程池并永久
        置 `_closed=True`；而 `AppContext._resume()` 只重启调度器、不重建正文池，
        于是之后点开任何「无正文」邮件都静默失效（`_submit` 直接 return False），
        用户看到的是列表有邮件、点开永远空白。
        """
        with self._lock:
            futures = list(self._futures.values())
        for fut in futures:
            fut.cancel()
        # 用一个排在队尾的「栅栏」任务等到真正在跑的那些结束：ThreadPoolExecutor
        # 没有 join，但它保证任务按提交顺序取用，所以栅栏跑完 = 前面的都跑完了。
        try:
            barrier = self._executor.submit(_noop)
        except RuntimeError:
            return                      # 池已关闭
        with contextlib.suppress(Exception):
            barrier.result(timeout=max(0.0, timeout))
        with self._lock:
            self._futures.clear()
            self._requested.clear()

    def shutdown(self, timeout: float = 5.0) -> None:
        """停止接受新任务并关闭线程池（退出流程用，**不可恢复**）。

        `timeout` 只用于「取消在跑任务」的等待；`shutdown(wait=True)` 本身仍会
        等待线程真正退出——这是刻意的，任务线程正在写数据库，硬杀会留下半截
        事务。
        """
        with self._lock:
            self._closed = True
        self.cancel_running(timeout)
        self._executor.shutdown(wait=True, cancel_futures=True)
        with self._lock:
            self._futures.clear()
            self._requested.clear()

    def restart(self) -> None:
        """重建线程池，使池可以重新接受任务（幂等：未关闭时是空操作）。"""
        with self._lock:
            if not self._closed:
                return
            self._executor = self._new_executor()
            self._closed = False
            self._futures.clear()
            self._requested.clear()
        log.info("正文补拉池已重建")

    def stop_all(self, timeout: float = 5.0) -> None:
        """兼容旧名：等价于 `shutdown()`（不可恢复）。"""
        self.shutdown(timeout)


def _noop() -> None:
    """`cancel_running` 用的栅栏任务（必须能被线程池直接执行）。"""

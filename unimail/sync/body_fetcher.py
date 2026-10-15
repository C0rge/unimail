"""按需/预取邮件正文：有界并发的后台补拉。

改造要点（v1.5.0，P9）
----------------------
此前每次补拉都新建一条 `QThread` 并各自完成「TCP + TLS + LOGIN」：
并发打开 10 封邮件就是 10 次握手、10 条连接，账号多时既慢又容易被
服务端判定为异常登录。现在改为：

* 复用 `SessionPool` 的保活会话（同账号串行、跨账号并行）；
* 用 `ThreadPoolExecutor` 限制总并发（`max_workers = min(4, CPU)`）；
* 提供 `prefetch()` 后台预取可见行，点开即显，不再出现「正在拉取正文…」。
"""
from __future__ import annotations

import contextlib
import logging
import os
from concurrent.futures import Future, ThreadPoolExecutor

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
    """管理正文补拉任务：去重、限流、可取消。"""

    def __init__(self, account_service: AccountService, mails: MailRepository,
                 bus: EventBus, sessions: SessionPool | None = None,
                 max_workers: int | None = None) -> None:
        self.account_service = account_service
        self.mails = mails
        self.bus = bus
        self.sessions = sessions
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers or default_workers(),
            thread_name_prefix="unimail-body",
        )
        self._futures: dict[str, Future] = {}
        self._requested: set[str] = set()
        self._closed = False

    # ------------------------------------------------------------ 查询
    def is_pending(self, mail_id: str) -> bool:
        return mail_id in self._requested

    def pending_count(self) -> int:
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
            if mail_id in self._requested:
                continue
            if self.request(mail_id):
                n += 1
        if n:
            log.debug("已提交 %d 封邮件的正文预取", n)
        return n

    def _submit(self, mail_id: str, row: dict, task_id: str, label: str) -> bool:
        if self._closed or mail_id in self._requested:
            return False
        self._requested.add(mail_id)
        self.bus.task_started.emit(task_id, f"{label} {mail_id[:8]}")
        fut = self._executor.submit(self._work, mail_id, row)
        self._futures[mail_id] = fut

        def _done(f: Future, mid: str = mail_id) -> None:
            self._finalize(mid, f)

        fut.add_done_callback(_done)
        return True

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
    def stop_all(self, timeout: float = 5.0) -> None:
        """停止接受新任务并等待在跑的完成（退出流程用）。"""
        self._closed = True
        for fut in list(self._futures.values()):
            fut.cancel()
        self._executor.shutdown(wait=True, cancel_futures=True)
        self._futures.clear()
        self._requested.clear()

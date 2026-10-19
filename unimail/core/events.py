"""事件总线：解耦后台同步线程与 UI。"""
from __future__ import annotations

from PySide6.QtCore import QObject, Signal


class EventBus(QObject):
    """基于 Qt 信号的事件总线，保证跨线程投递回主线程。

    设计演变（v1.4.0，P7 的前置条件）
    --------------------------------
    此前是「无负载广播」：同步线程只喊一声 `mail_added(account_id)`，
    UI 收到后只能**整表重查数据库 + 整表 reset**。即使只多了一封邮件，
    也要重跑一次筛选查询，且 `beginResetModel` 会让滚动位置与选中项全部丢失。

    现在同步侧直接给出「新增了哪些 mail_id」：

        mails_inserted(account_id, [mail_id, ...])
        mails_removed([mail_id, ...])

    列表模型据此做增量插入/删除，不再整表 reset。旧信号全部保留，
    因此既有接线不需要一次性改完。

    任务类事件（`task_*`）为「任务面板 + 单任务取消」提供统一的进度通道：
    同步、附件下载、正文预取都走同一组信号，面板只按 task_id 聚合。
    """

    # ---------------------------------------------------------- 邮件同步
    mail_added = Signal(str)              # account_id（保留兼容）
    mails_inserted = Signal(str, list)    # account_id, [mail_id, ...]（带负载）
    mails_removed = Signal(list)          # [mail_id, ...]
    sync_started = Signal(str)            # account_id
    sync_progress = Signal(str, int)      # account_id, fetched
    sync_finished = Signal(str, int)      # account_id, total_new
    sync_error = Signal(str, str)         # account_id, message

    # ---------------------------------------------------------- 数据变更
    mail_updated = Signal(str)            # mail_id
    mail_deleted = Signal(str)            # mail_id
    accounts_changed = Signal()
    contacts_changed = Signal()           # 通讯录增删改（UI 刷新联系人列表）
    filter_changed = Signal()

    # ---------------------------------------------------------- 状态
    status_message = Signal(str, int)     # text, timeout_ms

    # ---------------------------------------------------------- 任务
    task_started = Signal(str, str)          # task_id, label
    task_progress = Signal(str, int, int)    # task_id, current, total（total<0 表示未知）
    task_finished = Signal(str, bool, str)   # task_id, ok, message

    def emit_mail_added(self, account_id: str) -> None:
        self.mail_added.emit(account_id)

    def emit_mails_inserted(self, account_id: str, mail_ids: list[str]) -> None:
        if mail_ids:
            self.mails_inserted.emit(account_id, list(mail_ids))

    def emit_mails_removed(self, mail_ids: list[str]) -> None:
        if mail_ids:
            self.mails_removed.emit(list(mail_ids))

    def emit_mail_updated(self, mail_id: str) -> None:
        self.mail_updated.emit(mail_id)

    def emit_task_started(self, task_id: str, label: str) -> None:
        self.task_started.emit(task_id, label)

    def emit_task_progress(self, task_id: str, current: int, total: int) -> None:
        self.task_progress.emit(task_id, current, total)

    def emit_task_finished(self, task_id: str, ok: bool, message: str = "") -> None:
        self.task_finished.emit(task_id, ok, message)

    def emit_status(self, text: str, timeout_ms: int = 4000) -> None:
        self.status_message.emit(text, timeout_ms)

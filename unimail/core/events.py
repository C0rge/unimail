"""事件总线：解耦后台同步线程与 UI。"""
from __future__ import annotations

from PySide6.QtCore import QObject, Signal


class EventBus(QObject):
    """基于 Qt 信号的事件总线，保证跨线程投递回主线程。"""

    # 邮件同步相关
    mail_added = Signal(str)         # account_id
    sync_started = Signal(str)       # account_id
    sync_progress = Signal(str, int)  # account_id, fetched
    sync_finished = Signal(str, int)  # account_id, total_new
    sync_error = Signal(str, str)     # account_id, message

    # 数据变更
    mail_updated = Signal(str)       # mail_id
    mail_deleted = Signal(str)       # mail_id
    accounts_changed = Signal()
    filter_changed = Signal()

    # 状态
    status_message = Signal(str, int)  # text, timeout_ms

    def emit_mail_added(self, account_id: str) -> None:
        self.mail_added.emit(account_id)

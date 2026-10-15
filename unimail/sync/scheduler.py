"""同步调度器：主线程心跳，按各账号周期触发同步。"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from PySide6.QtCore import QObject, QTimer

from ..config import SCHEDULER_TICK
from ..core.events import EventBus
from ..core.services import AccountService

log = logging.getLogger(__name__)


class Scheduler(QObject):
    """周期性检查各账号是否到期，到期则派发同步任务。

    设计要点：
      - 心跳在主线程，仅做轻量判断，不阻塞 UI
      - 实际网络 IO 在 WorkerPool 的 QThread 中执行
      - 账号级别按 sync_interval 独立计时
    """

    def __init__(self, account_service: AccountService, worker_pool, bus: EventBus,
                 tick_seconds: int = SCHEDULER_TICK) -> None:
        super().__init__()
        self.account_service = account_service
        self.worker_pool = worker_pool
        self.bus = bus
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.tick)
        self._tick_seconds = tick_seconds
        self._enabled = True
        self._first_run_done = False

    # ------------------------------------------------------------ 控制
    def start(self) -> None:
        self._timer.start(self._tick_seconds * 1000)
        log.info("调度器已启动，心跳 %ds", self._tick_seconds)

    def stop(self) -> None:
        self._timer.stop()

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        if enabled:
            self._timer.start(self._tick_seconds * 1000)
        else:
            self._timer.stop()

    @property
    def enabled(self) -> bool:
        return self._enabled

    # ------------------------------------------------------------ 心跳
    def tick(self) -> None:
        if not self._enabled:
            return
        now = datetime.now(timezone.utc)
        for account in self.account_service.list():
            if account.status == "disabled":
                continue
            if account.last_synced_at is None:
                due = True
            else:
                last = account.last_synced_at
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                due = (now - last).total_seconds() >= account.sync_interval
            if due and not self.worker_pool.is_running(account.id):
                self.worker_pool.dispatch(account)
        self._first_run_done = True

    def sync_now(self, account_id: str | None = None) -> int:
        """立即同步：指定账号或全部账号。返回派发数量。"""
        dispatched = 0
        for account in self.account_service.list():
            if account_id and account.id != account_id:
                continue
            if account.status == "disabled":
                continue
            if self.worker_pool.dispatch(account):
                dispatched += 1
        return dispatched

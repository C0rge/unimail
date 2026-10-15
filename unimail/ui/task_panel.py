"""任务面板：把「后台正在做什么」变成可见、可取消。

为什么需要它
------------
改造前所有后台工作都是**不可见的**：同步在进行时，界面上只有状态栏一句
「正在同步 xxx…」，几秒后消失；正文补拉、附件下载完全不露痕迹。
用户遇到的第一个问题往往是「到底卡住了还是在干活？」——尤其是首次同步
要拉几百封邮件、可能持续几分钟的时候。

这里把 EventBus 的 `task_started / task_progress / task_finished` 三件套
聚合成一个列表：每个 task_id 一行，含标签、进度条（总量未知时显示
不确定态）、耗时与取消按钮。面板在没有任何任务时自动隐藏，
不占界面空间。

为什么用 task_id 聚合而不是「消息流」
------------------------------------
同一账号的同步会反复发 `task_started`（每次心跳都派发一次）。
如果按事件append，面板会在一分钟内堆出几十行同名任务。
按 id 归并后，同一个任务只有一行，进度在原位更新——这才是用户
想看到的信息密度。
"""
from __future__ import annotations

import time

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from . import icons

# 已完成的任务保留一小段时间，让用户看到「刚才那件事成功了」，
# 否则进度条一闪而过，反而像没发生过。
LINGER_MS = 4000
MAX_ROWS = 6


class TaskRow(QWidget):
    """单个任务的一行：标签 + 进度 + 取消。"""

    cancel_clicked = Signal(str)

    def __init__(self, task_id: str, label: str, parent=None) -> None:
        super().__init__(parent)
        self.task_id = task_id
        self.started_at = time.monotonic()
        self.finished = False

        layout = QHBoxLayout(self)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(6)

        self.label = QLabel(label)
        self.label.setObjectName("Hint")
        self.label.setToolTip(label)
        layout.addWidget(self.label, 1)

        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setFixedWidth(74)
        self.progress.setRange(0, 0)          # 未知总量 → 不确定态动画
        layout.addWidget(self.progress)

        self.btn = QPushButton()
        self.btn.setObjectName("IconButton")
        self.btn.setFixedSize(20, 20)
        self.btn.setToolTip("取消该任务")
        self.btn.clicked.connect(lambda: self.cancel_clicked.emit(self.task_id))
        layout.addWidget(self.btn)

    # ------------------------------------------------------------ 更新
    def apply_theme(self, palette: dict) -> None:
        self.btn.setIcon(icons.icon("close", palette.get("text_faint", "#5d6b7d"), 12))

    def set_label(self, label: str) -> None:
        self.label.setText(label)
        self.label.setToolTip(label)

    def set_progress(self, current: int, total: int) -> None:
        if total is None or total < 0:
            self.progress.setRange(0, 0)
            return
        self.progress.setRange(0, max(1, total))
        self.progress.setValue(max(0, min(current, total)))

    def mark_finished(self, ok: bool, message: str) -> None:
        self.finished = True
        self.progress.setRange(0, 100)
        self.progress.setValue(100 if ok else 0)
        elapsed = time.monotonic() - self.started_at
        text = self.label.text().split("  ·")[0]
        tail = message or ("完成" if ok else "失败")
        self.label.setText(f"{text}  ·  {tail}（{elapsed:.1f}s）")
        self.label.setObjectName("Hint" if ok else "Danger")
        self.label.style().unpolish(self.label)
        self.label.style().polish(self.label)
        self.btn.setEnabled(False)


class TaskPanel(QFrame):
    """后台任务列表。无任务时自隐藏。"""

    cancel_requested = Signal(str)     # task_id

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("Panel")
        self._rows: dict[str, TaskRow] = {}
        self._theme: dict = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 4, 12, 8)
        layout.setSpacing(2)

        title = QLabel("后台任务")
        title.setObjectName("SectionTitle")
        layout.addWidget(title)

        self.holder = QVBoxLayout()
        self.holder.setSpacing(1)
        layout.addLayout(self.holder)

        self._timers: dict[str, QTimer] = {}
        self.setVisible(False)

    # ------------------------------------------------------------ 主题
    def apply_theme(self, palette: dict) -> None:
        self._theme = dict(palette)
        for row in self._rows.values():
            row.apply_theme(self._theme)

    # ------------------------------------------------------------ 事件
    def on_started(self, task_id: str, label: str) -> None:
        row = self._rows.get(task_id)
        if row is None:
            row = TaskRow(task_id, label, self)
            row.cancel_clicked.connect(self.cancel_requested.emit)
            if self._theme:
                row.apply_theme(self._theme)
            self._rows[task_id] = row
            self.holder.addWidget(row)
            self._trim()
        else:
            # 同一 id 再次开始（例如下一次定时同步）：重置为进行中
            row.finished = False
            row.started_at = time.monotonic()
            row.btn.setEnabled(True)
            row.set_label(label)
            row.progress.setRange(0, 0)
        self._cancel_linger(task_id)
        self._refresh_visibility()

    def on_progress(self, task_id: str, current: int, total: int) -> None:
        row = self._rows.get(task_id)
        if row is not None and not row.finished:
            row.set_progress(current, total)

    def on_finished(self, task_id: str, ok: bool, message: str) -> None:
        row = self._rows.get(task_id)
        if row is None:
            return
        row.mark_finished(ok, message)
        self._schedule_linger(task_id)

    # ------------------------------------------------------------ 内部
    def _schedule_linger(self, task_id: str) -> None:
        self._cancel_linger(task_id)
        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.timeout.connect(lambda tid=task_id: self._drop(tid))
        timer.start(LINGER_MS)
        self._timers[task_id] = timer

    def _cancel_linger(self, task_id: str) -> None:
        timer = self._timers.pop(task_id, None)
        if timer is not None:
            timer.stop()
            timer.deleteLater()

    def _drop(self, task_id: str) -> None:
        self._cancel_linger(task_id)
        row = self._rows.pop(task_id, None)
        if row is not None:
            self.holder.removeWidget(row)
            row.setParent(None)
            row.deleteLater()
        self._refresh_visibility()

    def _trim(self) -> None:
        """超过上限时优先丢弃已完成的最旧行，保留正在进行中的。"""
        if len(self._rows) <= MAX_ROWS:
            return
        finished = [tid for tid, r in self._rows.items() if r.finished]
        for tid in finished:
            if len(self._rows) <= MAX_ROWS:
                break
            self._drop(tid)

    def _refresh_visibility(self) -> None:
        self.setVisible(bool(self._rows))

    # ------------------------------------------------------------ 查询
    def active_ids(self) -> list[str]:
        return [tid for tid, r in self._rows.items() if not r.finished]

    def row_count(self) -> int:
        return len(self._rows)

    def clear_finished(self) -> None:
        for tid in [t for t, r in self._rows.items() if r.finished]:
            self._drop(tid)


__all__ = ["MAX_ROWS", "TaskPanel", "TaskRow"]

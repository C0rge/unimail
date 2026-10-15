"""筛选栏：平台、关键词、时间范围、未读。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from PySide6.QtCore import QDateTime, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDateTimeEdit,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
)

from ..config import PLATFORMS

TIME_PRESETS = [
    ("全部时间", None),
    ("今天", 1),
    ("近 3 天", 3),
    ("近 7 天", 7),
    ("近 30 天", 30),
    ("自定义…", "custom"),
]


class FilterBar(QFrame):
    """顶部筛选条，条件变化时发出 filter_changed。"""

    filter_changed = Signal()
    refresh_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("Panel")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(9)

        # 平台
        self.platform_box = QComboBox()
        self.platform_box.addItem("全部平台", None)
        for key, cfg in PLATFORMS.items():
            self.platform_box.addItem(cfg.name, key)
        self.platform_box.currentIndexChanged.connect(lambda: self.filter_changed.emit())
        layout.addWidget(self.platform_box)

        # 时间预设
        self.time_box = QComboBox()
        for label, val in TIME_PRESETS:
            self.time_box.addItem(label, val)
        self.time_box.currentIndexChanged.connect(self._on_time_preset)
        layout.addWidget(self.time_box)

        # 自定义时间（默认隐藏）
        self.date_from = QDateTimeEdit()
        self.date_from.setCalendarPopup(True)
        self.date_from.setDisplayFormat("yyyy-MM-dd")
        self.date_from.setDateTime(QDateTime.currentDateTime().addDays(-7))
        self.date_from.dateTimeChanged.connect(lambda: self.filter_changed.emit())
        layout.addWidget(self.date_from)

        self.date_to = QDateTimeEdit()
        self.date_to.setCalendarPopup(True)
        self.date_to.setDisplayFormat("yyyy-MM-dd")
        self.date_to.setDateTime(QDateTime.currentDateTime())
        self.date_to.dateTimeChanged.connect(lambda: self.filter_changed.emit())
        layout.addWidget(self.date_to)

        dash = QLabel("—")
        dash.setObjectName("Hint")
        self.dash = dash
        layout.addWidget(dash)
        self.date_from.hide()
        self.date_to.hide()
        self.dash.hide()

        # 关键词
        self.search = QLineEdit()
        self.search.setObjectName("SearchBox")
        self.search.setPlaceholderText("搜索发件人 / 主题 / 正文…")
        self.search.setClearButtonEnabled(True)
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(280)
        self._debounce.timeout.connect(self.filter_changed.emit)
        self.search.textChanged.connect(lambda: self._debounce.start())
        layout.addWidget(self.search, 1)

        # 未读
        self.unread_only = QCheckBox("仅未读")
        self.unread_only.stateChanged.connect(lambda: self.filter_changed.emit())
        layout.addWidget(self.unread_only)

        # 刷新
        self.refresh_btn = QPushButton("刷新")
        self.refresh_btn.setObjectName("Ghost")
        self.refresh_btn.clicked.connect(self.refresh_requested.emit)
        layout.addWidget(self.refresh_btn)

    # ------------------------------------------------------------ 交互
    def _on_time_preset(self) -> None:
        is_custom = self.time_box.currentData() == "custom"
        self.date_from.setVisible(is_custom)
        self.date_to.setVisible(is_custom)
        self.dash.setVisible(is_custom)
        self.filter_changed.emit()

    def reset(self) -> None:
        self.platform_box.setCurrentIndex(0)
        self.time_box.setCurrentIndex(0)
        self.search.clear()
        self.unread_only.setChecked(False)

    # ------------------------------------------------------------ 取值
    def current_platform(self) -> str | None:
        return self.platform_box.currentData()

    def current_keyword(self) -> str:
        return self.search.text().strip()

    def date_range(self) -> tuple[datetime | None, datetime | None]:
        preset = self.time_box.currentData()
        if preset is None:
            return None, None
        now = datetime.now(timezone.utc)
        if preset == "custom":
            d1 = self.date_from.dateTime().toPython()
            d2 = self.date_to.dateTime().toPython()
            d1 = d1.replace(hour=0, minute=0, second=0, tzinfo=timezone.utc)
            d2 = d2.replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
            return d1, d2
        days = int(preset)
        start = (now - timedelta(days=days)).replace(hour=0, minute=0, second=0,
                                                     microsecond=0)
        return start, now

    def is_unread_only(self) -> bool:
        return self.unread_only.isChecked()

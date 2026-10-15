"""左侧账号面板：账号列表 + 未读计数 + 添加/删除。"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QPainter, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPushButton,
    QVBoxLayout,
)

from ..config import platform_color, platform_name
from ..core.models import Account


def _dot_pixmap(color: str, size: int = 9) -> QPixmap:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setBrush(QColor(color))
    p.setPen(Qt.NoPen)
    p.drawEllipse(0, 0, size, size)
    p.end()
    return pm


class AccountPanel(QFrame):
    """显示「全部邮箱」+ 每个账号，支持切换与右键菜单。"""

    account_selected = Signal(object)   # Account | None
    add_requested = Signal()
    remove_requested = Signal(str)      # account_id
    sync_requested = Signal(str)        # account_id
    mark_all_read_requested = Signal(str)
    manage_requested = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.setFixedWidth(228)
        self._accounts: list[Account] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 10)
        layout.setSpacing(0)

        title = QLabel("UniMail")
        title.setObjectName("AppTitle")
        layout.addWidget(title)

        self.summary = QLabel("")
        self.summary.setObjectName("Hint")
        self.summary.setContentsMargins(16, 0, 16, 8)
        layout.addWidget(self.summary)

        self.list = QListWidget()
        self.list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list.customContextMenuRequested.connect(self._on_context_menu)
        self.list.itemSelectionChanged.connect(self._on_selection)
        layout.addWidget(self.list, 1)

        bottom = QVBoxLayout()
        bottom.setContentsMargins(12, 8, 12, 0)
        bottom.setSpacing(6)

        self.sync_btn = QPushButton("立即同步全部")
        self.sync_btn.setObjectName("Primary")
        self.sync_btn.clicked.connect(lambda: self.sync_requested.emit(""))
        bottom.addWidget(self.sync_btn)

        self.add_btn = QPushButton("+  添加邮箱账号")
        self.add_btn.setObjectName("Ghost")
        self.add_btn.clicked.connect(self.add_requested.emit)
        bottom.addWidget(self.add_btn)

        layout.addLayout(bottom)

    # ------------------------------------------------------------ 刷新
    def set_accounts(self, accounts: list[Account], counts: dict[str, tuple[int, int]],
                     total: tuple[int, int]) -> None:
        self._accounts = accounts
        current = self.current_account_id()
        self.list.blockSignals(True)
        self.list.clear()

        total_all, unread_all = total
        item = QListWidgetItem()
        item.setData(Qt.UserRole, None)
        item.setText(self._row_text("全部邮箱", total_all, unread_all))
        item.setIcon(self._icon("#4c8dff", unread_all > 0))
        self.list.addItem(item)

        for acc in accounts:
            total_n, unread_n = counts.get(acc.id, (0, 0))
            text = self._row_text(acc.label, total_n, unread_n)
            it = QListWidgetItem()
            it.setData(Qt.UserRole, acc.id)
            it.setText(text)
            it.setIcon(self._icon(platform_color(acc.platform), unread_n > 0))
            status_tip = {
                "ok": "正常", "syncing": "同步中", "error": "同步异常", "disabled": "已停用",
            }.get(acc.status, acc.status)
            it.setToolTip(f"{acc.email}\n平台：{platform_name(acc.platform)}\n状态：{status_tip}")
            self.list.addItem(it)

        # 恢复选中
        self._reselect(current)
        self.list.blockSignals(False)

        self.summary.setText(
            f"{len(accounts)} 个账号 · {total_all} 封邮件 · {unread_all} 未读"
            if accounts else "尚未添加账号"
        )

    def _reselect(self, account_id: str | None) -> None:
        for i in range(self.list.count()):
            if self.list.item(i).data(Qt.UserRole) == account_id:
                self.list.setCurrentRow(i)
                return
        if self.list.count():
            self.list.setCurrentRow(0)

    @staticmethod
    def _row_text(name: str, total: int, unread: int) -> str:
        suffix = f"   {unread}" if unread else (f"   {total}" if total else "")
        return f"{name}{suffix}"

    @staticmethod
    def _icon(color: str, highlight: bool):
        from PySide6.QtGui import QIcon
        return QIcon(_dot_pixmap(color if highlight else "#3a4557"))

    def current_account_id(self) -> str | None:
        item = self.list.currentItem()
        return item.data(Qt.UserRole) if item else None

    def current_account(self) -> Account | None:
        aid = self.current_account_id()
        if not aid:
            return None
        return next((a for a in self._accounts if a.id == aid), None)

    def select_account(self, account_id: str | None) -> None:
        self._reselect(account_id)

    # ------------------------------------------------------------ 事件
    def _on_selection(self) -> None:
        self.account_selected.emit(self.current_account())

    def _on_context_menu(self, pos) -> None:
        item = self.list.itemAt(pos)
        if item is None:
            return
        account_id = item.data(Qt.UserRole)
        account = next((a for a in self._accounts if a.id == account_id), None)
        if account is None:
            return

        menu = QMenu(self)
        act_sync = menu.addAction("立即同步")
        act_read = menu.addAction("全部标记为已读")
        menu.addSeparator()
        act_manage = menu.addAction("账号设置")
        act_remove = menu.addAction("删除账号")

        chosen = menu.exec(self.list.viewport().mapToGlobal(pos))
        if chosen == act_sync:
            self.sync_requested.emit(account.id)
        elif chosen == act_read:
            self.mark_all_read_requested.emit(account.id)
        elif chosen == act_manage:
            self.manage_requested.emit(account.id)
        elif chosen == act_remove:
            self.remove_requested.emit(account.id)

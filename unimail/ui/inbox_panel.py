"""中间栏：统一收件箱（表格 + 空状态）。"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHeaderView,
    QLabel,
    QMenu,
    QStackedLayout,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from ..core.models import Mail, MailSummary
from .mail_model import COL_PLATFORM, COL_SENDER, COL_SUBJECT, COL_TIME, COL_UNREAD, MailTableModel


class EmptyState(QWidget):
    def __init__(self, title: str, hint: str, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(8)
        t = QLabel(title)
        t.setObjectName("EmptyTitle")
        t.setAlignment(Qt.AlignCenter)
        h = QLabel(hint)
        h.setObjectName("EmptyHint")
        h.setAlignment(Qt.AlignCenter)
        h.setWordWrap(True)
        layout.addWidget(t)
        layout.addWidget(h)


class InboxPanel(QFrame):
    """统一收件箱视图。"""

    mail_selected = Signal(str)          # mail_id
    mail_double_clicked = Signal(str)
    mark_read_requested = Signal(str, bool)
    star_requested = Signal(str)
    delete_requested = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("Panel")
        self.model = MailTableModel(self)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.stack = QStackedLayout()
        root.addLayout(self.stack, 1)

        # 表格页
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(40)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_context_menu)
        self.table.setWordWrap(False)

        header = self.table.horizontalHeader()
        header.setHighlightSections(False)
        header.setSectionResizeMode(COL_UNREAD, QHeaderView.Fixed)
        header.setSectionResizeMode(COL_SENDER, QHeaderView.Interactive)
        header.setSectionResizeMode(COL_SUBJECT, QHeaderView.Stretch)
        header.setSectionResizeMode(COL_PLATFORM, QHeaderView.Fixed)
        header.setSectionResizeMode(COL_TIME, QHeaderView.Fixed)
        self.table.setColumnWidth(COL_UNREAD, 26)
        self.table.setColumnWidth(COL_SENDER, 150)
        self.table.setColumnWidth(COL_PLATFORM, 92)
        self.table.setColumnWidth(COL_TIME, 74)

        self.table.selectionModel().currentRowChanged.connect(self._on_row_changed)
        self.table.doubleClicked.connect(self._on_double_clicked)

        # 空状态页
        self.empty = EmptyState("收件箱为空", "点击左侧「添加邮箱账号」开始，\n或在筛选栏调整搜索条件。")

        self.stack.addWidget(self.table)
        self.stack.addWidget(self.empty)

    # ------------------------------------------------------------ 数据
    def set_mails(self, mails: list[MailSummary], empty_hint: str | None = None) -> None:
        selected = self.current_mail_id()
        self.model.set_mails(mails)
        if mails:
            self.stack.setCurrentWidget(self.table)
            if selected:
                row = self.model.row_of(selected)
                if row >= 0:
                    self.table.selectRow(row)
                    return
            self.table.clearSelection()
        else:
            if empty_hint:
                self.empty.layout().itemAt(1).widget().setText(empty_hint)
            self.stack.setCurrentWidget(self.empty)

    def current_mail_id(self) -> str | None:
        idx = self.table.currentIndex()
        if not idx.isValid():
            return None
        return self.model.data(idx, Qt.UserRole)

    def select_mail(self, mail_id: str) -> None:
        row = self.model.row_of(mail_id)
        if row >= 0:
            self.table.selectRow(row)

    def refresh_row(self, mail: MailSummary | Mail) -> None:
        self.model.replace_mail(mail)

    # ------------------------------------------------------------ 事件
    def _on_row_changed(self, current, _previous) -> None:
        if current.isValid():
            mail_id = self.model.data(current, Qt.UserRole)
            if mail_id:
                self.mail_selected.emit(mail_id)

    def _on_double_clicked(self, index) -> None:
        mail_id = self.model.data(index, Qt.UserRole)
        if mail_id:
            self.mail_double_clicked.emit(mail_id)

    def keyPressEvent(self, event) -> None:
        if event.key() in (Qt.Key_Delete, Qt.Key_Backspace) and event.modifiers() == Qt.NoModifier:
            mail_id = self.current_mail_id()
            if mail_id:
                self.delete_requested.emit(mail_id)
            return
        super().keyPressEvent(event)

    def _on_context_menu(self, pos) -> None:
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        mail_id = self.model.data(index, Qt.UserRole)
        mail = self.model.mail_at(index.row())
        if not mail_id or mail is None:
            return

        menu = QMenu(self)
        act_toggle = menu.addAction("标为未读" if mail.is_read else "标为已读")
        act_star = menu.addAction("取消星标" if mail.is_starred else "加星标")
        menu.addSeparator()
        act_delete = menu.addAction("删除本地副本")

        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen == act_toggle:
            self.mark_read_requested.emit(mail_id, not mail.is_read)
        elif chosen == act_star:
            self.star_requested.emit(mail_id)
        elif chosen == act_delete:
            self.delete_requested.emit(mail_id)

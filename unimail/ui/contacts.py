"""通讯录对话框：列表 + 搜索 + 添加/编辑/删除。

为什么是独立 `QDialog` 而不是主窗口里的一个面板
----------------------------------------------
通讯录是低频操作（查一下、补一个人），不值得在主窗口三栏布局里常驻一块。
做成「文件」菜单里弹出的对话框，与「设置」「关于」同构，代码边界也更清晰：
本文件只负责「把用户意图翻译成一次 `ContactService` 调用」，其余交给服务层。

编辑与添加共用同一个 `_open_editor`：两者只是「有没有初始值」的区别，
拆成两段会重复一套表单校验逻辑。
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
)

from ..core.models import Contact
from ..core.services import ContactService
from . import icons


class ContactDialog(QDialog):
    """查看 / 管理通讯录。"""

    def __init__(self, contacts: ContactService, parent=None) -> None:
        super().__init__(parent)
        self.contacts = contacts
        self._items: list[Contact] = []
        self.setWindowTitle("通讯录")
        self.resize(560, 560)

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 16)
        root.setSpacing(10)

        head = QLabel("通讯录")
        head.setStyleSheet("font-size: 17px; font-weight: 600;")
        root.addWidget(head)

        hint = QLabel(
            "往来过的发件人会在这里被自动收集；你也可以手动添加联系人。"
            "数据只保存在本地加密数据库里。"
        )
        hint.setObjectName("Hint")
        hint.setWordWrap(True)
        root.addWidget(hint)

        # ---- 搜索框 ----
        self.search = QLineEdit()
        self.search.setPlaceholderText("按姓名或邮箱搜索…")
        self.search.textChanged.connect(self._reload)
        root.addWidget(self.search)

        # ---- 列表 ----
        self.list = QListWidget()
        self.list.itemDoubleClicked.connect(self._on_edit)
        root.addWidget(self.list, 1)

        # ---- 按钮 ----
        row = QHBoxLayout()
        self.btn_add = QPushButton("添加…")
        self.btn_add.setObjectName("Primary")
        self.btn_add.setIcon(icons.icon("plus", "#ffffff", 14))
        self.btn_add.clicked.connect(self._on_add)
        row.addWidget(self.btn_add)

        self.btn_edit = QPushButton("编辑…")
        self.btn_edit.setIcon(icons.icon("settings", "#8b98a9", 14))
        self.btn_edit.clicked.connect(self._on_edit)
        row.addWidget(self.btn_edit)

        self.btn_del = QPushButton("删除")
        self.btn_del.setIcon(icons.icon("trash", "#8b98a9", 14))
        self.btn_del.clicked.connect(self._on_delete)
        row.addWidget(self.btn_del)

        row.addStretch(1)
        close = QPushButton("关闭")
        close.clicked.connect(self.accept)
        row.addWidget(close)
        root.addLayout(row)

        self._reload()

    # ------------------------------------------------------------ 列表
    def _reload(self) -> None:
        keyword = self.search.text().strip()
        self._items = self.contacts.list(keyword)
        self.list.clear()
        for contact in self._items:
            item = QListWidgetItem()
            item.setData(Qt.UserRole, contact.id)
            item.setText(contact.name or contact.email)
            # 子行显示邮箱；没有名字的联系人只显示邮箱、不重复
            if contact.name:
                item.setToolTip(f"{contact.name} <{contact.email}>")
            else:
                item.setToolTip(contact.email)
            self.list.addItem(item)

    def _selected(self) -> Contact | None:
        item = self.list.currentItem()
        if item is None:
            return None
        contact_id = item.data(Qt.UserRole)
        return next((c for c in self._items if c.id == contact_id), None)

    # ------------------------------------------------------------ 增删改
    def _on_add(self) -> None:
        editor = ContactEditDialog(self.contacts, parent=self)
        if editor.exec() == QDialog.Accepted:
            self._reload()

    def _on_edit(self) -> None:
        contact = self._selected()
        if contact is None:
            QMessageBox.information(self, "通讯录", "请先选择一个联系人。")
            return
        editor = ContactEditDialog(self.contacts, contact=contact, parent=self)
        if editor.exec() == QDialog.Accepted:
            self._reload()

    def _on_delete(self) -> None:
        contact = self._selected()
        if contact is None:
            QMessageBox.information(self, "通讯录", "请先选择一个联系人。")
            return
        label = contact.name or contact.email
        ret = QMessageBox.question(
            self, "删除联系人", f"确定删除联系人「{label}」吗？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if ret != QMessageBox.Yes:
            return
        self.contacts.remove(contact.id)
        self._reload()


class ContactEditDialog(QDialog):
    """添加 / 编辑单个联系人。"""

    def __init__(self, contacts: ContactService, contact: Contact | None = None,
                 parent=None) -> None:
        super().__init__(parent)
        self.contacts = contacts
        self.contact = contact
        self.setWindowTitle("编辑联系人" if contact else "添加联系人")
        self.setFixedWidth(440)

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 18)
        root.setSpacing(12)

        form = QFormLayout()
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignRight)

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("可选")
        self.name_edit.setText(contact.name if contact else "")
        form.addRow("姓名", self.name_edit)

        self.email_edit = QLineEdit()
        self.email_edit.setPlaceholderText("name@example.com")
        self.email_edit.setText(contact.email if contact else "")
        # 编辑态下邮箱是唯一键，不允许改（改邮箱等价于删旧建新，界面不提供）。
        if contact is not None:
            self.email_edit.setEnabled(False)
            self.email_edit.setToolTip("邮箱是唯一标识，不可修改；需要更换请删除后重新添加。")
        form.addRow("邮箱", self.email_edit)

        self.note_edit = QPlainTextEdit()
        self.note_edit.setPlaceholderText("备注（可选）")
        self.note_edit.setPlainText(contact.note if contact else "")
        self.note_edit.setFixedHeight(72)
        form.addRow("备注", self.note_edit)

        root.addLayout(form)

        self.err = QLabel("")
        self.err.setStyleSheet("color: #f2545b; font-size: 12px;")
        self.err.setWordWrap(True)
        root.addWidget(self.err)

        buttons = QDialogButtonBox()
        self.ok_btn = buttons.addButton(
            "保存", QDialogButtonBox.AcceptRole)
        self.ok_btn.setObjectName("Primary")
        buttons.addButton("取消", QDialogButtonBox.RejectRole)
        buttons.accepted.connect(self._on_save)
        buttons.rejected.connect(self.reject)
        root.addLayout(buttons)

    def _on_save(self) -> None:
        email = self.email_edit.text().strip()
        if "@" not in email:
            self.err.setText("请输入有效的邮箱地址")
            return
        name = self.name_edit.text().strip()
        note = self.note_edit.toPlainText().strip()
        try:
            if self.contact is None:
                self.contacts.add(email, name=name, note=note)
            else:
                self.contacts.update(self.contact.id, {"name": name, "note": note})
        except ValueError as exc:
            self.err.setText(str(exc))
            return
        self.accept()


__all__ = ["ContactDialog"]

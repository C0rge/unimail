"""对话框：主密码登录、添加账号、关于。"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ..config import APP_NAME, APP_VERSION, PLATFORMS, platform_name
from ..core.models import AccountDraft


class LoginDialog(QDialog):
    """主密码登录 / 首次设置。"""

    def __init__(self, is_first_run: bool, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.is_first_run = is_first_run
        self.password: str = ""
        self.setWindowTitle("UniMail")
        self.setFixedWidth(420)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 20)
        layout.setSpacing(12)

        title = QLabel("设置主密码" if is_first_run else "解锁 UniMail")
        title.setStyleSheet("font-size: 19px; font-weight: 600;")
        layout.addWidget(title)

        desc = QLabel(
            "主密码用于加解本地数据库与账号凭据，不会上传、不会保存。"
            "一旦遗忘，数据将无法恢复，请务必牢记。"
            if is_first_run else
            "输入主密码以解锁本地加密数据库。"
        )
        desc.setWordWrap(True)
        desc.setObjectName("Hint")
        layout.addWidget(desc)

        self.pwd = QLineEdit()
        self.pwd.setEchoMode(QLineEdit.Password)
        self.pwd.setPlaceholderText("主密码")
        layout.addWidget(self.pwd)

        self.pwd2 = QLineEdit()
        self.pwd2.setEchoMode(QLineEdit.Password)
        self.pwd2.setPlaceholderText("再次输入以确认")
        if is_first_run:
            layout.addWidget(self.pwd2)

        self.err = QLabel("")
        self.err.setStyleSheet("color: #f2545b; font-size: 12px;")
        self.err.setWordWrap(True)
        layout.addWidget(self.err)

        buttons = QDialogButtonBox()
        self.ok_btn = buttons.addButton(
            "创建并进入" if is_first_run else "解锁",
            QDialogButtonBox.AcceptRole,
        )
        self.ok_btn.setObjectName("Primary")
        buttons.addButton("退出", QDialogButtonBox.RejectRole)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.pwd.returnPressed.connect(self._on_accept)
        if is_first_run:
            self.pwd2.returnPressed.connect(self._on_accept)
        self.pwd.setFocus()

    def _on_accept(self) -> None:
        pwd = self.pwd.text()
        if len(pwd) < 6:
            self.err.setText("主密码至少 6 位")
            return
        if self.is_first_run and pwd != self.pwd2.text():
            self.err.setText("两次输入不一致")
            return
        self.password = pwd
        self.accept()


class AddAccountDialog(QDialog):
    """添加邮箱账号。"""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.draft: AccountDraft | None = None
        self.setWindowTitle("添加邮箱账号")
        self.setFixedWidth(520)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 22, 26, 20)
        layout.setSpacing(14)

        title = QLabel("添加邮箱账号")
        title.setStyleSheet("font-size: 18px; font-weight: 600;")
        layout.addWidget(title)

        form = QFormLayout()
        form.setSpacing(11)
        form.setLabelAlignment(Qt.AlignRight)

        self.platform_box = QComboBox()
        for key, cfg in PLATFORMS.items():
            self.platform_box.addItem(cfg.name, key)
        self.platform_box.currentIndexChanged.connect(self._on_platform_changed)
        form.addRow("平台", self.platform_box)

        self.email_edit = QLineEdit()
        self.email_edit.setPlaceholderText("your@email.com")
        form.addRow("邮箱地址", self.email_edit)

        self.display_edit = QLineEdit()
        self.display_edit.setPlaceholderText("可选，用于区分多个账号")
        form.addRow("备注名称", self.display_edit)

        self.pwd_edit = QLineEdit()
        self.pwd_edit.setEchoMode(QLineEdit.Password)
        self.pwd_edit.setPlaceholderText("密码 / 授权码")
        form.addRow("密码/授权码", self.pwd_edit)

        # 自定义服务器字段（仅自定义平台可见）
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("imap.example.com")
        self.host_label = QLabel("IMAP 服务器")
        form.addRow(self.host_label, self.host_edit)

        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(993)
        self.port_label = QLabel("端口")
        form.addRow(self.port_label, self.port_spin)

        self.ssl_check = QCheckBox("使用 SSL/TLS")
        self.ssl_check.setChecked(True)
        form.addRow("", self.ssl_check)

        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(30, 86400)
        self.interval_spin.setValue(300)
        self.interval_spin.setSuffix(" 秒")
        form.addRow("自动刷新间隔", self.interval_spin)

        layout.addLayout(form)

        self.hint = QLabel("")
        self.hint.setObjectName("Hint")
        self.hint.setWordWrap(True)
        layout.addWidget(self.hint)

        self.verify_check = QCheckBox("添加前先验证连接（推荐）")
        self.verify_check.setChecked(True)
        layout.addWidget(self.verify_check)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setStyleSheet("font-size: 12px;")
        layout.addWidget(self.status)

        buttons = QDialogButtonBox()
        self.ok_btn = buttons.addButton("添加", QDialogButtonBox.AcceptRole)
        self.ok_btn.setObjectName("Primary")
        buttons.addButton("取消", QDialogButtonBox.RejectRole)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._on_platform_changed()

    # ------------------------------------------------------------ 交互
    def _current_platform(self) -> str:
        return self.platform_box.currentData()

    def _on_platform_changed(self) -> None:
        key = self._current_platform()
        cfg = PLATFORMS[key]
        is_custom = key == "custom"

        self.host_label.setVisible(is_custom)
        self.host_edit.setVisible(is_custom)
        self.port_label.setVisible(is_custom)
        self.port_spin.setVisible(is_custom)
        self.ssl_check.setVisible(is_custom)

        if not is_custom:
            self.host_edit.setText(cfg.imap_host)
            self.port_spin.setValue(cfg.imap_port)
            self.ssl_check.setChecked(cfg.use_ssl)
            self.email_edit.setPlaceholderText(
                "username@gmail.com" if key == "gmail" else "your@email.com"
            )

        hint = cfg.auth_hint
        if cfg.help_url:
            hint += f"\n帮助文档：{cfg.help_url}"
        self.hint.setText(hint)
        self.status.setText("")

    def _on_accept(self) -> None:
        email = self.email_edit.text().strip()
        password = self.pwd_edit.text()
        if "@" not in email:
            self.status.setText("请输入有效的邮箱地址")
            self.status.setStyleSheet("color: #f2545b; font-size: 12px;")
            return
        if not password:
            self.status.setText("请输入密码或授权码")
            self.status.setStyleSheet("color: #f2545b; font-size: 12px;")
            return

        self.draft = AccountDraft(
            platform=self._current_platform(),
            email=email,
            password=password,
            display_name=self.display_edit.text().strip(),
            imap_host=self.host_edit.text().strip(),
            imap_port=self.port_spin.value(),
            use_ssl=self.ssl_check.isChecked(),
            sync_interval=self.interval_spin.value(),
        )
        self.accept()

    @property
    def should_verify(self) -> bool:
        return self.verify_check.isChecked()


class AboutDialog(QDialog):
    def __init__(self, encryption_level: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("关于 UniMail")
        self.setFixedWidth(440)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 22, 26, 20)
        layout.setSpacing(10)

        t = QLabel(f"{APP_NAME} v{APP_VERSION}")
        t.setStyleSheet("font-size: 18px; font-weight: 600;")
        layout.addWidget(t)

        body = QLabel(
            "多平台邮箱统一管理程序。\n\n"
            "· 支持 QQ / 163 / Gmail / Outlook / 自定义 IMAP\n"
            "· 统一收件箱、多维筛选、已读未读\n"
            "· IMAP 增量同步 + 定时自动刷新\n"
            "· 主密码派生密钥，本地加密存储\n\n"
            f"当前加密等级：{encryption_level}"
        )
        body.setWordWrap(True)
        layout.addWidget(body)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

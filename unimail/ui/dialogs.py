"""对话框：主密码登录、添加账号、设置、首启向导、关于。"""
from __future__ import annotations

import contextlib
import logging

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ..config import (
    APP_NAME,
    APP_VERSION,
    DATA_DIR,
    PASSWORD_MIN_LENGTH,
    PLATFORMS,
    sqlcipher_pip_hint,
)
from ..core.models import AccountDraft
from ..core.security import password_policy_error, password_strength
from . import icons
from .settings import FONT_SCALES, THEME_MODES, UiSettings

log = logging.getLogger(__name__)

THEME_LABELS = [("跟随系统", "system"), ("深色", "dark"), ("浅色", "light")]
VIEW_LABELS = [("列表", "list"), ("会话（按主题归并）", "thread")]
SCALE_LABELS = [("小 (90%)", 0.9), ("标准 (100%)", 1.0),
                ("大 (110%)", 1.1), ("特大 (125%)", 1.25)]


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

        # 实时强度提示：只在「首次设置」时出现，避免解锁流程里暴露
        # 「你的密码很弱」这种反向信息（攻击者不需要知道）。
        self.strength = QLabel("")
        self.strength.setObjectName("Hint")
        self.strength.setWordWrap(True)
        if is_first_run:
            layout.addWidget(self.strength)
            self.pwd.textChanged.connect(self._update_strength)

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

    def _update_strength(self) -> None:
        pwd = self.pwd.text()
        if not pwd:
            self.strength.setText(f"至少 {PASSWORD_MIN_LENGTH} 位；建议混合大小写、数字与符号。")
            return
        _, label = password_strength(pwd)
        self.strength.setText(f"强度：{label}")

    def _on_accept(self) -> None:
        pwd = self.pwd.text()
        # 只在「首次设置」时施加长度策略。解锁流程绝不校验策略——
        # 老库的主密码可能短于当前下限，卡住就等于用户被自己锁在门外。
        if self.is_first_run:
            policy_error = password_policy_error(pwd)
            if policy_error:
                self.err.setText(policy_error)
                return
            if pwd != self.pwd2.text():
                self.err.setText("两次输入不一致")
                return
        elif not pwd:
            self.err.setText("请输入主密码")
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
    """关于页：把「当前到底处在什么安全状态」讲清楚。"""

    def __init__(self, encryption_level: str, parent: QWidget | None = None,
                 *, kdf: str = "", ctx=None) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.setWindowTitle("关于 UniMail")
        self.setFixedWidth(500)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 22, 26, 20)
        layout.setSpacing(10)

        head = QHBoxLayout()
        logo = QLabel()
        logo.setPixmap(icons.pixmap("shield", "#4c8dff", 34))
        head.addWidget(logo)
        col = QVBoxLayout()
        col.setSpacing(2)
        t = QLabel(f"{APP_NAME}")
        t.setStyleSheet("font-size: 19px; font-weight: 600;")
        col.addWidget(t)
        v = QLabel(f"版本 {APP_VERSION} · 多平台邮箱统一管理")
        v.setObjectName("Hint")
        col.addWidget(v)
        head.addLayout(col, 1)
        layout.addLayout(head)

        layout.addWidget(_divider())

        facts = [
            ("数据库加密", encryption_level or "未知"),
            ("密钥派生", kdf or "未记录"),
            ("数据目录", str(DATA_DIR)),
        ]
        if ctx is not None:
            # 诊断信息只是展示用：任何一项取不到就跳过，不能让「关于」
            # 对话框自己崩掉
            with contextlib.suppress(Exception):
                stats = ctx.sessions.stats()
                facts.append(("IMAP 保活会话",
                              f"{stats['sessions']}/{stats['max_sessions']}"
                              f"（占用 {stats['in_use']}）"))
            with contextlib.suppress(Exception):
                facts.append(("待回写标记", str(ctx.mails.pending_flag_count())))

        form = QFormLayout()
        form.setSpacing(8)
        form.setLabelAlignment(Qt.AlignRight)
        for key, value in facts:
            label = QLabel(str(value))
            label.setObjectName("Mono")
            label.setWordWrap(True)
            form.addRow(key, label)
        layout.addLayout(form)

        layout.addWidget(_divider())

        body = QLabel(
            "· 支持 QQ / 163 / Gmail / Outlook / 自定义 IMAP\n"
            "· 统一收件箱、全文检索（含中文逐字切分）、会话视图\n"
            "· IMAP 增量同步 + 保活连接 + 可取消任务\n"
            "· 主密码派生密钥（Argon2id），本地整库加密\n\n"
            "本程序不加载邮件中的任何远程资源：跟踪像素、远程 CSS 与\n"
            "内嵌图片默认全部拦截，需要时由你显式点击加载。"
        )
        body.setWordWrap(True)
        body.setObjectName("Hint")
        layout.addWidget(body)

        buttons = QHBoxLayout()
        copy_btn = QPushButton("复制诊断信息")
        copy_btn.setObjectName("Ghost")
        copy_btn.clicked.connect(lambda: self._copy_diagnostics(facts))
        buttons.addWidget(copy_btn)
        buttons.addStretch(1)
        box = QDialogButtonBox(QDialogButtonBox.Close)
        box.rejected.connect(self.reject)
        box.accepted.connect(self.accept)
        buttons.addWidget(box)
        layout.addLayout(buttons)

    def _copy_diagnostics(self, facts) -> None:
        import platform
        import sys

        from PySide6.QtWidgets import QApplication
        lines = [
            f"{APP_NAME} {APP_VERSION}",
            f"Python {sys.version.split()[0]} on {platform.platform()}",
        ]
        lines += [f"{k}: {v}" for k, v in facts]
        # 刻意不含邮箱地址、账号数量、主题等可识别信息——「诊断信息」
        # 经常被整段贴到公开的 issue 里，这里只放排障真正需要的东西。
        QApplication.clipboard().setText("\n".join(lines))
        QMessageBox.information(self, "已复制", "诊断信息已复制到剪贴板（不含邮箱地址）。")


def _divider() -> QFrame:
    line = QFrame()
    line.setObjectName("Divider")
    line.setFrameShape(QFrame.HLine)
    line.setFixedHeight(1)
    return line


class SettingsDialog(QDialog):
    """统一设置面板：外观 / 行为 / 安全 / 数据。"""

    # 主题改动即时预览（对话框还没点确定时主窗口也要跟着变）
    preview_requested = Signal(str, float)      # theme_mode, font_scale

    def __init__(self, ctx, settings: UiSettings,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.settings = settings
        self.setWindowTitle("设置")
        self.setMinimumWidth(560)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.stack = QStackedWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(self.stack)
        root.addWidget(scroll, 1)

        self.stack.addWidget(self._page_appearance())
        self.stack.addWidget(self._page_behavior())
        self.stack.addWidget(self._page_security())
        self.stack.addWidget(self._page_data())

        nav = QHBoxLayout()
        nav.setContentsMargins(26, 8, 26, 14)
        for i, label in enumerate(("外观", "行为", "安全", "数据")):
            btn = QPushButton(label)
            btn.setObjectName("Ghost")
            btn.clicked.connect(lambda _=False, idx=i: self.stack.setCurrentIndex(idx))
            nav.addWidget(btn)
        nav.addStretch(1)
        box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        box.button(QDialogButtonBox.Save).setText("保存")
        box.button(QDialogButtonBox.Save).setObjectName("Primary")
        box.button(QDialogButtonBox.Cancel).setText("取消")
        box.accepted.connect(self._on_save)
        box.rejected.connect(self._on_cancel)
        nav.addWidget(box)
        root.addLayout(nav)

        self._theme_at_open = (settings.theme_mode, settings.font_scale)

    # ------------------------------------------------------------ 外观
    def _page_appearance(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(26, 20, 26, 16)
        outer.setSpacing(12)

        title = QLabel("外观")
        title.setStyleSheet("font-size: 17px; font-weight: 600;")
        outer.addWidget(title)

        form = QFormLayout()
        form.setSpacing(11)
        form.setLabelAlignment(Qt.AlignRight)

        self.theme_box = QComboBox()
        for label, value in THEME_LABELS:
            self.theme_box.addItem(label, value)
        _select_data(self.theme_box, self.settings.theme_mode)
        self.theme_box.currentIndexChanged.connect(self._emit_preview)
        form.addRow("主题", self.theme_box)

        self.scale_box = QComboBox()
        for label, value in SCALE_LABELS:
            self.scale_box.addItem(label, value)
        _select_data(self.scale_box, self.settings.font_scale)
        self.scale_box.currentIndexChanged.connect(self._emit_preview)
        form.addRow("字号", self.scale_box)

        self.view_box = QComboBox()
        for label, value in VIEW_LABELS:
            self.view_box.addItem(label, value)
        _select_data(self.view_box, self.settings.view_mode)
        form.addRow("列表样式", self.view_box)

        outer.addLayout(form)

        hint = QLabel(
            "「跟随系统」读取 Windows 的浅色/深色应用设置（macOS 读取外观偏好）。\n"
            "在 Linux 上没有跨桌面环境的统一接口，会退回深色并允许在此手动覆盖。"
        )
        hint.setObjectName("Hint")
        hint.setWordWrap(True)
        outer.addWidget(hint)
        outer.addStretch(1)
        return page

    # ------------------------------------------------------------ 行为
    def _page_behavior(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(26, 20, 26, 16)
        outer.setSpacing(10)

        title = QLabel("行为")
        title.setStyleSheet("font-size: 17px; font-weight: 600;")
        outer.addWidget(title)

        self.chk_flags = QCheckBox("把「标为已读 / 星标」同步回服务器")
        self.chk_flags.setChecked(self.settings.sync_server_flags)
        outer.addWidget(self.chk_flags)
        outer.addWidget(_hint(
            "关闭后状态只在本地生效，手机上或网页版的已读状态不会跟着变。"
            "变更会排队，下次同步时推送。"
        ))

        self.chk_delete_server = QCheckBox("删除邮件时，同时移入服务器垃圾箱")
        self.chk_delete_server.setChecked(self.settings.delete_on_server)
        outer.addWidget(self.chk_delete_server)
        warn_delete = _hint(
            "⚠️ 默认关闭时，「删除」只移除本机副本——服务器上的邮件不受影响，"
            "重置同步或换设备后会重新出现。\n"
            "开启后，删除会先把邮件移入服务器垃圾箱（可在垃圾箱恢复），再移除"
            "本机副本；服务器操作失败时不动本机数据。\n"
            "需要服务器支持 UIDPLUS；不支持时会明确报错并保持本机副本不变。"
        )
        warn_delete.setObjectName("Warning")
        warn_delete.setWordWrap(True)
        outer.addWidget(warn_delete)

        self.chk_prefetch = QCheckBox("后台预取正文（点开即显）")
        self.chk_prefetch.setChecked(self.settings.prefetch_bodies)
        outer.addWidget(self.chk_prefetch)
        outer.addWidget(_hint(
            "在后台用保活连接预取列表可见邮件的正文，点开时不必等网络。"
            "会略微增加邮箱流量。"
        ))

        self.chk_inline = QCheckBox("自动加载邮件中的内嵌图片")
        self.chk_inline.setChecked(self.settings.inline_images_auto)
        outer.addWidget(self.chk_inline)
        warning = _hint(
            "⚠️ 内嵌图片（cid: 引用）与远程图片在隐私上是同一件事："
            "发件人可以据此确认你何时、从哪个 IP 打开了邮件。默认关闭。"
        )
        warning.setObjectName("Warning")
        warning.setWordWrap(True)
        outer.addWidget(warning)

        self.chk_tray = QCheckBox("关闭窗口时最小化到系统托盘")
        self.chk_tray.setChecked(self.settings.minimize_to_tray)
        outer.addWidget(self.chk_tray)

        self.chk_notify = QCheckBox("收到新邮件时显示系统通知")
        self.chk_notify.setChecked(self.settings.show_notifications)
        outer.addWidget(self.chk_notify)

        self.chk_lock_min = QCheckBox("最小化到托盘时自动锁定")
        self.chk_lock_min.setChecked(self.settings.lock_on_minimize)
        outer.addWidget(self.chk_lock_min)

        outer.addStretch(1)
        return page

    # ------------------------------------------------------------ 安全
    def _page_security(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(26, 20, 26, 16)
        outer.setSpacing(10)

        title = QLabel("安全")
        title.setStyleSheet("font-size: 17px; font-weight: 600;")
        outer.addWidget(title)

        level = self.ctx.db.encryption_level if self.ctx and self.ctx.db else "未知"
        outer.addWidget(_kv("数据库加密", level))

        outer.addWidget(_divider())
        outer.addWidget(_section("设备绑定免密解锁"))

        binding = getattr(self.ctx, "device_binding", None)
        if binding is None or not binding.available():
            label = _hint("当前系统不提供可用的设备绑定后端（仅支持 Windows 与 macOS），"
                          "因此不显示该功能。")
            label.setWordWrap(True)
            outer.addWidget(label)
            self.chk_device = None
            self.btn_bind = None
            self.lbl_bind = None
            outer.addStretch(1)
            return page

        self.chk_device = QCheckBox(f"启用设备绑定（{binding.describe()}）")
        self.chk_device.setChecked(self.settings.device_unlock and binding.is_bound())
        outer.addWidget(self.chk_device)

        risk = _hint(
            "⚠️ 开启后，本机上任何以你的账户运行的进程都能取到主密钥，"
            "等同于把「本机安全」当成唯一的防线。\n"
            "主密码改变时绑定会自动解除。建议只在个人独占的设备上开启。\n"
            "数据目录被复制到别的机器或别的用户下时，绑定会自然失效并退回密码解锁。"
        )
        risk.setObjectName("Warning")
        risk.setWordWrap(True)
        outer.addWidget(risk)

        row = QHBoxLayout()
        self.btn_bind = QPushButton("立即绑定当前会话")
        self.btn_bind.setObjectName("Ghost")
        self.btn_bind.clicked.connect(self._on_bind)
        row.addWidget(self.btn_bind)

        self.btn_unbind = QPushButton("解除绑定")
        self.btn_unbind.setObjectName("Ghost")
        self.btn_unbind.clicked.connect(self._on_unbind)
        row.addWidget(self.btn_unbind)
        row.addStretch(1)
        outer.addLayout(row)

        self.lbl_bind = QLabel("")
        self.lbl_bind.setObjectName("Hint")
        self.lbl_bind.setWordWrap(True)
        outer.addWidget(self.lbl_bind)
        self._refresh_binding_label()

        outer.addStretch(1)
        return page

    # ------------------------------------------------------------ 数据
    def _page_data(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(26, 20, 26, 16)
        outer.setSpacing(10)

        title = QLabel("数据")
        title.setStyleSheet("font-size: 17px; font-weight: 600;")
        outer.addWidget(title)

        outer.addWidget(_kv("数据目录", str(DATA_DIR)))

        db = self.ctx.db if self.ctx else None
        if db is not None:
            outer.addWidget(_kv("加密等级", db.encryption_level))
            outer.addWidget(_kv("支持整库重加密", "是" if db.rekey_supported else "否"))

        from ..storage import sqlcipher_available
        if not sqlcipher_available():
            warn = _hint("环境未安装 sqlcipher3，数据库无法整库加密。\n"
                         f"安装命令：{sqlcipher_pip_hint()}")
            warn.setObjectName("Warning")
            warn.setWordWrap(True)
            outer.addWidget(warn)

        outer.addWidget(_divider())
        outer.addWidget(_hint(
            "导出与迁移等重操作请在主窗口的「文件」菜单中执行：\n"
            "· 导出恢复包（仅含 salt / 迭代次数，不含任何密文）\n"
            "· 数据库加密设置（明文 ↔ 整库加密）\n"
            "· 修改主密码（会重新加密全部凭据并解除设备绑定）"
        ))
        outer.addStretch(1)
        return page

    # ------------------------------------------------------------ 绑定
    def _refresh_binding_label(self) -> None:
        binding = getattr(self.ctx, "device_binding", None)
        if binding is None or self.lbl_bind is None:
            return
        if binding.is_bound():
            self.lbl_bind.setText(f"状态：已绑定（{binding.bound_at() or '时间未知'}）")
            if self.btn_bind:
                self.btn_bind.setEnabled(False)
        else:
            self.lbl_bind.setText("状态：未绑定")
            if self.btn_bind:
                self.btn_bind.setEnabled(True)

    def _on_bind(self) -> None:
        binding = getattr(self.ctx, "device_binding", None)
        if binding is None:
            return
        ret = QMessageBox.warning(
            self, "确认启用设备绑定",
            "开启后，本机上任何以你的账户运行的程序都可以取出主密钥并解密全部邮件。\n\n"
            "这等于用「本机安全」替代「主密码强度」。确定要继续吗？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if ret != QMessageBox.Yes:
            return
        try:
            binding.bind(self.ctx.security.master_key_copy(), label=str(DATA_DIR))
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "绑定失败", str(exc))
            return
        if self.chk_device:
            self.chk_device.setChecked(True)
        self._refresh_binding_label()
        QMessageBox.information(self, "已绑定", "下次启动可在锁定界面一键解锁。")

    def _on_unbind(self) -> None:
        binding = getattr(self.ctx, "device_binding", None)
        if binding is None:
            return
        binding.unbind()
        if self.chk_device:
            self.chk_device.setChecked(False)
        self._refresh_binding_label()
        QMessageBox.information(self, "已解除", "设备绑定已删除，之后需要输入主密码。")

    # ------------------------------------------------------------ 提交
    def _emit_preview(self) -> None:
        self.preview_requested.emit(self.theme_box.currentData(),
                                    float(self.scale_box.currentData()))

    def _on_cancel(self) -> None:
        mode, scale = self._theme_at_open
        self.preview_requested.emit(mode, scale)
        self.reject()

    def _on_save(self) -> None:
        s = self.settings
        s.theme_mode = _combo_value(self.theme_box, THEME_MODES, "system")
        s.font_scale = _combo_value(self.scale_box, FONT_SCALES, 1.0)
        s.view_mode = _combo_value(self.view_box, ("list", "thread"), "list")
        s.sync_server_flags = self.chk_flags.isChecked()
        s.delete_on_server = self.chk_delete_server.isChecked()
        s.prefetch_bodies = self.chk_prefetch.isChecked()
        s.inline_images_auto = self.chk_inline.isChecked()
        s.minimize_to_tray = self.chk_tray.isChecked()
        s.show_notifications = self.chk_notify.isChecked()
        s.lock_on_minimize = self.chk_lock_min.isChecked()
        if self.chk_device is not None:
            s.device_unlock = self.chk_device.isChecked()
        s.sanitize()
        self.accept()


def _combo_value(box: QComboBox, allowed, fallback):
    value = box.currentData()
    return value if value in allowed else fallback


def _select_data(box: QComboBox, value) -> None:
    idx = box.findData(value)
    box.setCurrentIndex(idx if idx >= 0 else 0)


def _hint(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("Hint")
    label.setWordWrap(True)
    return label


def _section(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("SectionTitle")
    label.setContentsMargins(0, 0, 0, 0)
    return label


def _kv(key: str, value: str) -> QWidget:
    row = QWidget()
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(10)
    k = QLabel(key)
    k.setObjectName("Hint")
    k.setFixedWidth(130)
    layout.addWidget(k)
    v = QLabel(str(value))
    v.setObjectName("Mono")
    v.setWordWrap(True)
    v.setTextInteractionFlags(Qt.TextSelectableByMouse)
    layout.addWidget(v, 1)
    return row


class FirstRunWizard(QDialog):
    """首启向导：三步把「这东西安全在哪、接下来做什么」讲明白。

    出现的时机是「解锁成功但一个账号都没有」——既可能是全新用户，
    也可能是把数据清空后重来的老用户，两种情况都需要这段说明。
    """

    add_account_requested = Signal()

    def __init__(self, encryption_level: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("欢迎使用 UniMail")
        self.setMinimumWidth(520)
        self._step = 0

        root = QVBoxLayout(self)
        root.setContentsMargins(30, 26, 30, 20)
        root.setSpacing(14)

        self.title = QLabel("")
        self.title.setStyleSheet("font-size: 20px; font-weight: 600;")
        root.addWidget(self.title)

        self.body = QLabel("")
        self.body.setWordWrap(True)
        self.body.setTextFormat(Qt.RichText)
        root.addWidget(self.body, 1)

        self.step_label = QLabel("")
        self.step_label.setObjectName("Hint")
        root.addWidget(self.step_label)

        buttons = QHBoxLayout()
        self.skip_btn = QPushButton("跳过")
        self.skip_btn.setObjectName("Ghost")
        self.skip_btn.clicked.connect(self.reject)
        buttons.addWidget(self.skip_btn)
        buttons.addStretch(1)

        self.back_btn = QPushButton("上一步")
        self.back_btn.setObjectName("Ghost")
        self.back_btn.clicked.connect(self._back)
        buttons.addWidget(self.back_btn)

        self.next_btn = QPushButton("下一步")
        self.next_btn.setObjectName("Primary")
        self.next_btn.clicked.connect(self._next)
        buttons.addWidget(self.next_btn)
        root.addLayout(buttons)

        self._pages = self._build_pages(encryption_level)
        self._render()

    def _build_pages(self, level: str) -> list[tuple[str, str]]:
        return [
            (
                f"欢迎使用 {APP_NAME}",
                "把 QQ、163、Gmail、Outlook 以及任意 IMAP 邮箱收进同一个收件箱。<br><br>"
                "这个向导会用三步说明它<b>怎么保护你的邮件</b>，"
                "以及第一次使用需要做什么。<br><br>"
                "随时可以点「跳过」直接开始。",
            ),
            (
                "你的数据保存在哪里",
                f"数据库位于：<br><code>{DATA_DIR}</code><br><br>"
                f"当前加密等级：<b>{level or '未知'}</b><br><br>"
                "· 主密码经 Argon2id 派生后用于整库加密，密码本身不落盘；<br>"
                "· 邮箱授权码用独立密钥二次加密，即使数据库被拷走也读不出；<br>"
                "· 附件目录中的文件名经过安全化处理，不会带出目录外。<br><br>"
                "请务必牢记主密码——它没有任何找回途径。",
            ),
            (
                "接下来做什么",
                "点击「开始使用」后：<br><br>"
                "1. 在左下角点「添加邮箱账号」，填入邮箱与<b>授权码</b>"
                "（不是登录密码，各平台都需要单独开启 IMAP）；<br>"
                "2. 首次同步会拉取最近 100 封，之后每 5 分钟增量同步；<br>"
                "3. 用 <b>J / K</b> 上下翻阅，<b>空格</b>展开会话，"
                "<b>U</b> 切换已读，<b>S</b> 加星标，<b>Ctrl+F</b> 搜索。<br><br>"
                "邮件里的远程图片与内嵌图片默认<b>不会加载</b>，"
                "需要时在详情面板手动点一下。",
            ),
        ]

    def _render(self) -> None:
        title, body = self._pages[self._step]
        self.title.setText(title)
        self.body.setText(body)
        self.step_label.setText(f"第 {self._step + 1} / {len(self._pages)} 步")
        self.back_btn.setEnabled(self._step > 0)
        self.next_btn.setText("开始使用" if self._step == len(self._pages) - 1 else "下一步")

    def _back(self) -> None:
        if self._step > 0:
            self._step -= 1
            self._render()

    def _next(self) -> None:
        if self._step < len(self._pages) - 1:
            self._step += 1
            self._render()
            return
        self.accept()
        self.add_account_requested.emit()


"""锁屏遮罩：空闲超时或手动锁定时覆盖主窗口，要求重新认证。

与「锁定即退出」的差别
----------------------
改造前 `Ctrl+L` 和空闲超时的处理是 `ctx.shutdown()` + `self.close()`：
数据确实锁上了，但**所有未保存的界面状态、滚动位置、展开的会话全部消失**，
而且重新输入主密码要再跑一遍 Argon2id（约 0.4 s）并重建全部后台线程。
用户的实际感受是「它把我的程序关了」。

现在的语义是「锁屏」而不是「退出」：遮罩盖住窗口内容，键盘鼠标事件被
遮罩吃掉，后台同步照常进行（同步线程不读屏幕，也没有新的数据暴露面）。
重新认证走 `SecurityService.verify_password()`——它只校验，不重建会话密钥，
因此不存在「重新解密数据库」这一步。

遮罩必须**真正挡住内容**：用的是完全不透明的底色，而不是半透明+模糊——
后者仍能让人辨认出邮件主题的大致轮廓（截图、肩窥都算泄露）。
遮罩尺寸随父窗口变化（装了事件过滤器跟进 `resize`），
菜单栏、状态栏同样被盖住，不留下任何可交互的入口。
"""
from __future__ import annotations

import logging
from typing import ClassVar

from PySide6.QtCore import QEvent, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..core.security import UnlockGuard
from . import icons

log = logging.getLogger(__name__)


class LockOverlay(QWidget):
    """覆盖整个主窗口的锁定层。"""

    unlocked = Signal()
    quit_requested = Signal()

    def __init__(self, ctx, settings=None, parent=None) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.settings = settings
        self.setObjectName("LockOverlay")
        # 纯 QWidget 子类默认不画 QSS 背景（没有 WA_StyledBackground 时
        # 样式表的 background 规则会被忽略）——这正是「遮罩看起来透明」的
        # 真正原因，而不是颜色写错。
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setAutoFillBackground(True)
        self._theme: dict = {}
        self._attempts = 0
        # 与登录页**共用同一份持久化的退避状态**（同一个 guard 文件）。
        # 此前锁屏完全没接 UnlockGuard：登录页精心实现的递增等待在这里形同虚设，
        # 挂机时可以对主密码做无限次在线尝试（每次都是 GUI 线程上跑一遍
        # Argon2id ≈ 0.4 s）。v1.6.1 修正。
        self._guard = UnlockGuard()
        self._cooldown_timer = QTimer(self)
        self._cooldown_timer.setInterval(500)
        self._cooldown_timer.timeout.connect(self._tick_cooldown)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addStretch(1)

        row = QHBoxLayout()
        row.addStretch(1)
        card = QFrame()
        card.setObjectName("LockCard")
        card.setFixedWidth(360)
        row.addWidget(card)
        row.addStretch(1)
        root.addLayout(row)
        root.addStretch(1)

        inner = QVBoxLayout(card)
        inner.setContentsMargins(26, 24, 26, 22)
        inner.setSpacing(12)

        self.icon_label = QLabel()
        self.icon_label.setAlignment(Qt.AlignCenter)
        inner.addWidget(self.icon_label)

        title = QLabel("已锁定")
        title.setObjectName("DetailSubject")
        title.setAlignment(Qt.AlignCenter)
        inner.addWidget(title)

        self.hint = QLabel("输入主密码继续使用")
        self.hint.setObjectName("Hint")
        self.hint.setAlignment(Qt.AlignCenter)
        self.hint.setWordWrap(True)
        inner.addWidget(self.hint)

        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText("主密码")
        self.password.returnPressed.connect(self._try_unlock)
        inner.addWidget(self.password)

        self.device_btn = QPushButton("使用本机设备解锁")
        self.device_btn.setObjectName("Ghost")
        self.device_btn.clicked.connect(self._try_device_unlock)
        self.device_btn.hide()
        inner.addWidget(self.device_btn)

        self.error = QLabel("")
        self.error.setObjectName("Danger")
        self.error.setAlignment(Qt.AlignCenter)
        self.error.setWordWrap(True)
        self.error.hide()
        inner.addWidget(self.error)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.quit_btn = QPushButton("退出程序")
        self.quit_btn.setObjectName("Ghost")
        self.quit_btn.clicked.connect(self.quit_requested.emit)
        buttons.addWidget(self.quit_btn)

        self.unlock_btn = QPushButton("解锁")
        self.unlock_btn.setObjectName("Primary")
        self.unlock_btn.setDefault(True)
        self.unlock_btn.clicked.connect(self._try_unlock)
        buttons.addWidget(self.unlock_btn, 1)
        inner.addLayout(buttons)

        self.footer = QLabel("")
        self.footer.setObjectName("Hint")
        self.footer.setAlignment(Qt.AlignCenter)
        inner.addWidget(self.footer)

    # ------------------------------------------------------------ 主题
    def apply_theme(self, palette: dict) -> None:
        self._theme = dict(palette)
        # 用**控件级**样式表而不是依赖应用级 QSS：遮罩的底色是安全属性，
        # 不允许被任何一条更宽泛的规则（例如 `QWidget { background: … }`）
        # 悄悄改掉——那会让遮罩变透明而无人察觉。
        self.setStyleSheet(
            f"QWidget#LockOverlay {{ background: {palette.get('bg', '#0f1216')}; }}")
        from PySide6.QtGui import QColor, QPalette
        pal = self.palette()
        pal.setColor(QPalette.Window, QColor(palette.get("bg", "#0f1216")))
        self.setPalette(pal)
        self.setAutoFillBackground(True)
        self.icon_label.setPixmap(
            icons.pixmap("lock", palette.get("text_dim", "#8b98a9"), 30))

    # ------------------------------------------------------------ 生命周期
    def lock(self, reason: str = "") -> None:
        """显示遮罩并抢占焦点。"""
        self._attempts = 0
        self.error.hide()
        self.password.clear()
        self.hint.setText(reason or "输入主密码继续使用")
        self._refresh_device_button()
        self._sync_cooldown()
        parent = self.parentWidget()
        if parent is not None:
            self.setGeometry(parent.rect())
        self.show()
        self.raise_()
        self.setFocus(Qt.OtherFocusReason)
        # 延迟再抢一次焦点：窗口刚显示时 Qt 还会把焦点给上一个控件
        QTimer.singleShot(50, self.password.setFocus)

    def _refresh_device_button(self) -> None:
        enabled = bool(getattr(self.settings, "device_unlock", False))
        binding = getattr(self.ctx, "device_binding", None)
        if enabled and binding is not None and binding.is_bound():
            self.device_btn.show()
            self.footer.setText(f"设备绑定：{binding.describe()}")
        else:
            self.device_btn.hide()
            self.footer.setText("")

    def is_locked(self) -> bool:
        return self.isVisible()

    # ------------------------------------------------------------ 认证
    def _sync_cooldown(self) -> None:
        """按退避状态启用/禁用输入并显示剩余秒数。"""
        wait = self._guard.remaining_wait()
        if wait <= 0:
            self._cooldown_timer.stop()
            self.password.setEnabled(True)
            self.unlock_btn.setEnabled(True)
            self.device_btn.setEnabled(True)
            return
        self.password.setEnabled(False)
        self.unlock_btn.setEnabled(False)
        self.error.setText(f"尝试过于频繁，请等待 {wait:.0f} 秒后重试")
        self.error.show()
        if not self._cooldown_timer.isActive():
            self._cooldown_timer.start()

    def _tick_cooldown(self) -> None:
        if self._guard.remaining_wait() > 0:
            self._sync_cooldown()
            return
        self.error.hide()
        self._sync_cooldown()
        self._refresh_device_button()
        self.password.setFocus()

    def _try_unlock(self) -> None:
        if self._guard.remaining_wait() > 0:
            self._sync_cooldown()
            return
        password = self.password.text()
        if not password:
            return
        try:
            params, verifier, _driver = self.ctx._read_security_meta()   # noqa: SLF001
        except Exception as exc:  # noqa: BLE001 - 元数据坏了要如实说明
            self._fail(f"无法读取安全元数据：{exc}")
            return

        # 校验要在 GUI 线程里跑一遍 Argon2id（约 0.4 s）。给一个忙碌提示，并且
        # 只 repaint 不 processEvents —— 后者会让「解锁」按钮在等待期内被再次
        # 点中，触发并发的第二次密钥派生。
        self.error.setText("正在校验…")
        self.error.show()
        self.password.setEnabled(False)
        self.unlock_btn.setEnabled(False)
        self.error.repaint()
        try:
            ok = self.ctx.security.verify_password(password, params, verifier)
        finally:
            self.password.setEnabled(True)
            self.unlock_btn.setEnabled(True)

        if ok:
            self._guard.reset()
            self._cooldown_timer.stop()
            self.error.hide()
            self.password.clear()
            self.hide()
            self.unlocked.emit()
            return
        delay = self._guard.record_failure()
        self._attempts += 1
        self._fail(f"主密码不正确（第 {self._attempts} 次，需等待 {delay:.0f} 秒）")
        self._sync_cooldown()

    def _try_device_unlock(self) -> None:
        binding = getattr(self.ctx, "device_binding", None)
        if binding is None:
            return
        key = binding.recall()
        if not key:
            self.device_btn.setEnabled(False)
            self.device_btn.setText("设备绑定不可用（已解绑或系统拒绝）")
            self._fail("设备绑定在本机不可用，请改用主密码")
            return
        try:
            self.ctx.security.restore_from_master_key(key)
        except Exception as exc:  # noqa: BLE001
            self._fail(f"设备解锁失败：{exc}")
            return
        # 设备密钥与当前库对不上（例如改过主密码但绑定没解）：退回密码
        if not self._verify_key_matches():
            self.ctx.security.lock()
            self._fail("设备绑定与本数据库不匹配，请用主密码解锁")
            return
        self.hide()
        self.unlocked.emit()

    def _verify_key_matches(self) -> bool:
        try:
            _params, verifier, _driver = self.ctx._read_security_meta()   # noqa: SLF001
            from ..core.security import SecurityService
            return SecurityService.make_verifier(
                self.ctx.security.master_key_copy()) == verifier
        except Exception:
            log.warning("设备解锁后校验主密钥失败", exc_info=True)
            return False

    def _fail(self, message: str) -> None:
        self.error.setText(message)
        self.error.show()
        self.password.selectAll()
        self.password.setFocus()

    # ------------------------------------------------------------ 拦截
    def mousePressEvent(self, event) -> None:
        # 吞掉点击：遮罩下就是主窗口内容，任何穿透都会泄漏信息
        event.accept()

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key_Escape:
            self.password.setFocus()
            return
        # Tab 在遮罩内部循环，不要把焦点交给下面的主窗口
        super().keyPressEvent(event)
        if self.password.hasFocus() is False and event.key() == Qt.Key_Tab:
            self.password.setFocus()

    def eventFilter(self, obj, event) -> bool:
        """跟随父窗口尺寸变化（父窗口 resize 时遮罩不会自动变大）。"""
        if obj is self.parentWidget() and event.type() == QEvent.Resize:
            self.setGeometry(self.parentWidget().rect())
        return super().eventFilter(obj, event)


class IdleWatcher(QWidget):
    """挂在应用上的空闲监视器：任何用户输入都刷新「最后活动时间」。

    为什么用全局事件过滤器而不是给每个控件装 `eventFilter`：
    空闲判定需要覆盖**所有**输入路径（键盘、鼠标、滚轮、触摸、拖放）。
    逐个控件注册必然会漏掉一个，而漏掉的那条路径会让自动锁定在用户
    正在操作时突然触发——比不锁定更糟。
    """

    activity = Signal()

    EVENTS: ClassVar[frozenset] = frozenset({
        QEvent.MouseButtonPress, QEvent.MouseButtonRelease, QEvent.MouseMove,
        QEvent.KeyPress, QEvent.KeyRelease, QEvent.Wheel, QEvent.TouchBegin,
        QEvent.TabletMove, QEvent.DragEnter, QEvent.Drop, QEvent.FocusIn,
    })

    def eventFilter(self, obj, event) -> bool:
        if event.type() in self.EVENTS:
            self.activity.emit()
        return super().eventFilter(obj, event)


__all__ = ["IdleWatcher", "LockOverlay"]

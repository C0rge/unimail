"""主窗口：三栏布局 + 状态栏 + 事件接线 + 托盘 + 锁屏。

这个文件是「所有东西最终汇合的地方」，因此值得说明它的接线原则：

1. **UI 不直接读写数据库。** 所有动作都通过 `ctx` 里的服务层，
   视图只负责把用户意图翻译成一次服务调用。
2. **后台线程只发信号，不碰控件。** 跨线程的信号由 Qt 自动排队到主线程；
   这里明确声明 `QueuedConnection` 语义依赖（默认行为即满足，因为
   `EventBus` 属于主线程）。
3. **增量优先。** 收到 `mails_inserted` 时先尝试增量插入；只有在
   「当前筛选条件可能受影响」时才回退到整表重查。这是 v1.4.0 里
   用户最直观能感知到的改进——后台来新邮件不再把滚动位置顶掉。
4. **锁屏与退出是两件事。** `Ctrl+L` / 空闲超时 → 弹遮罩（进程继续跑，
   后台同步不断）；`Ctrl+Q` / 托盘退出 → 停线程、关库、退出进程。
5. **网络 IO 一律不在这条线程上。** 附件下载/预览、内嵌图下载、`.eml` /
   `.mbox` 导出、「移入服务器垃圾箱」的批量删除都经 `IoTaskRunner` 提交到
   后台线程池，结果用信号排队回主线程再更新界面（P1）。
"""
from __future__ import annotations

import contextlib
import logging
from datetime import datetime

from PySide6.QtCore import QEvent, Qt, QTimer
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QSplitter,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from ..config import APP_NAME, AUTO_LOCK_SECONDS, IDLE_POLL_SECONDS
from ..core.models import MailFilter
from ..core.search_query import parse_query
from ..core.security import SecurityError
from ..platforms import ImapError
from . import icons
from .account_panel import AccountPanel
from .compose import ComposeDialog
from .contacts import ContactDialog
from .context import AppContext
from .detail_panel import DetailPanel
from .dialogs import AboutDialog, AddAccountDialog, FirstRunWizard, SettingsDialog
from .filter_bar import FilterBar
from .inbox_panel import InboxPanel
from .io_runner import IoTaskRunner
from .lockscreen import IdleWatcher, LockOverlay
from .settings import UiSettings
from .task_panel import TaskPanel
from .theme import ThemeManager
from .tray import TrayIcon

log = logging.getLogger(__name__)

# 列表每页行数（滚动加载）。200 是「一屏多一点」的量：再小会让滚动频繁等查询，
# 再大会让首屏查询变慢、内存占用上升。
PAGE_SIZE = 200
# 非时间排序时一次性取多少。这些排序键（发件人/主题/平台…）没有
# `(col, date DESC)` 形式的覆盖索引，而且 keyset 游标只对 (date, id) 成立，
# 所以不做滚动加载——取一个足够大的窗口，并在界面上说明范围。
SORT_SCAN_LIMIT = 2000


class MainWindow(QMainWindow):
    def __init__(self, context: AppContext, settings: UiSettings | None = None,
                 theme: ThemeManager | None = None) -> None:
        super().__init__()
        self.ctx = context
        self.settings = settings or UiSettings.load()
        self.theme = theme or ThemeManager(self.settings.theme_mode,
                                           self.settings.font_scale)
        self.setWindowTitle(f"{APP_NAME} — 多平台邮箱统一管理")
        self.resize(1320, 840)
        self.setMinimumSize(1020, 640)

        self._last_sync_status: dict[str, str] = {}
        self._locked = False
        self._quitting = False
        self._view_mode = self.settings.view_mode
        # 列表分页游标：上一页最后一行的 (date, id)。None 表示已经到末页。
        self._page_cursor: tuple[datetime, str] | None = None
        self._has_more = False
        self._loading_more = False
        # 后台 IO 提交点：复用正文补拉池的线程池，不另起第三条线程生命周期。
        self._io = IoTaskRunner(context.body_pool, self)
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.timeout.connect(self.reload_mails)

        self._build_ui()
        self._wire_events()
        self._install_shortcuts()
        self._apply_theme()
        self._setup_tray()
        self._setup_lock()

        # 立即渲染本地已有数据，再延迟触发网络同步
        self.refresh_accounts()
        self.reload_mails()
        QTimer.singleShot(150, self._restore_geometry)
        QTimer.singleShot(250, self._offer_kdf_upgrade)
        QTimer.singleShot(400, self._initial_sync)
        QTimer.singleShot(800, self._maybe_first_run)

    # ================================================================ UI
    def _build_ui(self) -> None:
        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.setHandleWidth(1)
        self.splitter.setChildrenCollapsible(False)

        # 左：账号 + 任务面板
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(0)
        self.account_panel = AccountPanel()
        ll.addWidget(self.account_panel, 1)
        self.task_panel = TaskPanel()
        ll.addWidget(self.task_panel)
        self.splitter.addWidget(left)

        # 中：筛选 + 收件箱
        center = QWidget()
        cl = QVBoxLayout(center)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)
        self.filter_bar = FilterBar()
        cl.addWidget(self.filter_bar)
        self.inbox_panel = InboxPanel()
        cl.addWidget(self.inbox_panel, 1)
        self.splitter.addWidget(center)

        # 右：详情
        self.detail_panel = DetailPanel()
        self.splitter.addWidget(self.detail_panel)

        self.splitter.setSizes([236, 700, 400])
        self.splitter.setStretchFactor(1, 3)
        self.splitter.setStretchFactor(2, 2)

        root.addWidget(self.splitter)
        self.setCentralWidget(central)

        # 状态栏
        bar = QStatusBar()
        bar.setSizeGripEnabled(False)
        self.status_text = QLabel("就绪")
        self.status_text.setObjectName("StatusBar")
        self.encryption_label = QLabel("")
        self.encryption_label.setObjectName("StatusBar")
        self.pending_label = QLabel("")
        self.pending_label.setObjectName("StatusBar")
        bar.addWidget(self.status_text, 1)
        bar.addPermanentWidget(self.pending_label)
        bar.addPermanentWidget(self.encryption_label)
        self.setStatusBar(bar)
        self._refresh_security_labels()
        self._refresh_delete_label()

        self.detail_panel.inline_resolver = self._resolve_inline
        self.detail_panel.inline_missing = self._inline_missing
        self._build_menu()

    def _build_menu(self) -> None:
        menubar = self.menuBar()

        m_file = menubar.addMenu("文件")
        act_compose = QAction(icons.icon("mail", "#8b98a9", 14), "写邮件…", self)
        act_compose.setShortcut("Ctrl+E")
        act_compose.triggered.connect(self._on_compose)
        m_file.addAction(act_compose)

        act_add = QAction(icons.icon("plus", "#8b98a9", 14), "添加邮箱账号…", self)
        act_add.setShortcut("Ctrl+N")
        act_add.triggered.connect(self._on_add_account)
        m_file.addAction(act_add)

        act_sync = QAction(icons.icon("refresh", "#8b98a9", 14), "立即同步全部", self)
        act_sync.setShortcut("F5")
        act_sync.triggered.connect(lambda: self._sync_all())
        m_file.addAction(act_sync)

        m_file.addSeparator()
        act_contacts = QAction(icons.icon("contacts", "#8b98a9", 14), "通讯录…", self)
        act_contacts.triggered.connect(self._on_contacts)
        m_file.addAction(act_contacts)

        act_import = QAction(icons.icon("export", "#8b98a9", 14),
                             "导出当前列表为 CSV…", self)
        act_import.triggered.connect(lambda: self._on_export("csv", []))
        m_file.addAction(act_import)

        act_settings = QAction(icons.icon("settings", "#8b98a9", 14), "设置…", self)
        act_settings.setShortcut("Ctrl+,")
        act_settings.triggered.connect(self._on_settings)
        m_file.addAction(act_settings)

        m_file.addSeparator()
        act_pwd = QAction(icons.icon("key", "#8b98a9", 14), "修改主密码…", self)
        act_pwd.triggered.connect(self._on_change_password)
        m_file.addAction(act_pwd)

        act_recovery = QAction(icons.icon("shield", "#8b98a9", 14),
                               "导出恢复包…", self)
        act_recovery.triggered.connect(self._on_export_recovery)
        m_file.addAction(act_recovery)

        act_encrypt = QAction("数据库加密设置…", self)
        act_encrypt.triggered.connect(self._on_encryption_settings)
        m_file.addAction(act_encrypt)

        act_lock = QAction(icons.icon("lock", "#8b98a9", 14), "立即锁定", self)
        act_lock.setShortcut("Ctrl+L")
        act_lock.triggered.connect(self.lock)
        m_file.addAction(act_lock)

        m_file.addSeparator()
        act_quit = QAction(icons.icon("close", "#8b98a9", 14), "退出", self)
        act_quit.setShortcut("Ctrl+Q")
        act_quit.triggered.connect(self.quit_app)
        m_file.addAction(act_quit)

        m_view = menubar.addMenu("视图")
        act_refresh = QAction(icons.icon("refresh", "#8b98a9", 14), "刷新列表", self)
        act_refresh.triggered.connect(self.reload_mails)
        m_view.addAction(act_refresh)

        act_reset = QAction("重置筛选", self)
        act_reset.triggered.connect(self.filter_bar.reset)
        m_view.addAction(act_reset)

        m_view.addSeparator()
        act_thread = QAction(icons.icon("layout-thread", "#8b98a9", 14),
                             "切换会话视图", self)
        act_thread.setShortcut("Ctrl+G")
        act_thread.triggered.connect(self.toggle_view_mode)
        m_view.addAction(act_thread)

        act_focus = QAction("聚焦搜索框", self)
        act_focus.setShortcut("Ctrl+F")
        act_focus.triggered.connect(self._focus_search)
        m_view.addAction(act_focus)

        m_theme = m_view.addMenu(icons.icon("sun", "#8b98a9", 14), "主题")
        for label, value in (("跟随系统", "system"), ("深色", "dark"), ("浅色", "light")):
            act = QAction(label, self)
            act.setCheckable(True)
            act.setChecked(self.settings.theme_mode == value)
            act.triggered.connect(lambda _=False, v=value: self._set_theme_mode(v))
            m_theme.addAction(act)

        m_help = menubar.addMenu("帮助")
        act_guide = QAction("使用向导", self)
        act_guide.triggered.connect(self._show_wizard)
        m_help.addAction(act_guide)

        act_about = QAction("关于 UniMail", self)
        act_about.triggered.connect(self._on_about)
        m_help.addAction(act_about)

    def _install_shortcuts(self) -> None:
        bindings = [
            (QKeySequence("Ctrl+R"), lambda: self._sync_all()),
            (QKeySequence("Ctrl+A"), lambda: self.account_panel.select_account(None)),
            (QKeySequence("Escape"), self._on_escape),
        ]
        self._actions = []
        for seq, slot in bindings:
            a = QAction(self)
            a.setShortcut(seq)
            a.triggered.connect(slot)
            self.addAction(a)
            self._actions.append(a)

    # ================================================================ 主题
    def _apply_theme(self) -> None:
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(self.theme.stylesheet())
        palette = self.theme.palette_dict()
        self.inbox_panel.apply_theme(palette)
        self.account_panel.apply_theme(palette)
        self.detail_panel.apply_theme(palette)
        self.task_panel.apply_theme(palette)
        self.filter_bar.apply_theme(palette)
        if getattr(self, "tray", None) is not None:
            self.tray.apply_theme(palette)
        if getattr(self, "lock_overlay", None) is not None:
            self.lock_overlay.apply_theme(palette)

    def _set_theme_mode(self, mode: str) -> None:
        self.settings.theme_mode = mode
        self.theme.set_mode(mode)
        self.settings.save()
        self._apply_theme()
        self.set_status(f"主题已切换为{'跟随系统' if mode == 'system' else ('深色' if mode == 'dark' else '浅色')}")

    def _apply_settings(self) -> None:
        """设置对话框保存后统一落地到运行时。"""
        self.theme.set_mode(self.settings.theme_mode)
        self.theme.set_scale(self.settings.font_scale)
        self._apply_theme()

        self.ctx.mails.sync_server_flags = self.settings.sync_server_flags
        self._refresh_delete_label()
        self.detail_panel.auto_inline = self.settings.inline_images_auto
        if self.settings.view_mode != self._view_mode:
            self._view_mode = self.settings.view_mode
            self.inbox_panel.toolbar.set_view_mode(self._view_mode)
            self.reload_mails()
        if self.tray is not None:
            if self.settings.minimize_to_tray:
                self.tray.show()
            else:
                self.tray.hide()
        self._refresh_security_labels()

    # ================================================================ 接线
    def _wire_events(self) -> None:
        ap = self.account_panel
        ap.add_requested.connect(self._on_add_account)
        ap.remove_requested.connect(self._on_remove_account)
        ap.sync_requested.connect(self._on_sync_account)
        ap.mark_all_read_requested.connect(self._on_mark_all_read)
        ap.manage_requested.connect(self._on_manage_account)
        ap.account_selected.connect(self._on_account_selected)

        self.filter_bar.filter_changed.connect(self._on_filter_changed)
        self.filter_bar.refresh_requested.connect(lambda: self._sync_all())

        ip = self.inbox_panel
        ip.mail_selected.connect(self._on_mail_selected)
        ip.mail_double_clicked.connect(self._on_mail_selected)
        ip.mark_read_requested.connect(self._on_mark_read)
        ip.star_requested.connect(self._on_star)
        ip.delete_requested.connect(self._on_delete_mail)
        ip.mark_read_many_requested.connect(self._on_mark_read_many)
        ip.star_many_requested.connect(self._on_star_many)
        ip.delete_many_requested.connect(self._on_delete_many)
        ip.export_requested.connect(self._on_export)
        ip.thread_toggle_requested.connect(self._on_thread_toggle)
        ip.load_more_requested.connect(self._load_more)
        ip.notice.connect(self.set_status)

        dp = self.detail_panel
        dp.attachment_requested.connect(self._on_download_attachment)
        dp.preview_requested.connect(self._on_preview_attachment)
        dp.inline_download_requested.connect(self._on_download_inline)
        dp.star_requested.connect(self._on_star)
        dp.export_requested.connect(lambda mid: self._on_export("eml", [mid] if mid else []))
        dp.reply_requested.connect(lambda mid: self._on_reply(mid, reply_all=False))
        dp.reply_all_requested.connect(lambda mid: self._on_reply(mid, reply_all=True))
        dp.forward_requested.connect(self._on_forward)

        self.task_panel.cancel_requested.connect(self._on_cancel_task)

        bus = self.ctx.bus
        bus.accounts_changed.connect(self.refresh_accounts)
        bus.mail_updated.connect(self._on_mail_updated)
        bus.mail_deleted.connect(self._on_mail_deleted)
        bus.mails_inserted.connect(self._on_mails_inserted)
        bus.mails_removed.connect(self._on_mails_removed)
        bus.sync_started.connect(self._on_sync_started)
        bus.sync_finished.connect(self._on_sync_finished)
        bus.sync_error.connect(self._on_sync_error)
        bus.filter_changed.connect(self.reload_mails)
        bus.status_message.connect(lambda text, ms: self.statusBar().showMessage(text, ms))

        bus.task_started.connect(self.task_panel.on_started)
        bus.task_progress.connect(self.task_panel.on_progress)
        bus.task_finished.connect(self.task_panel.on_finished)

    def _setup_tray(self) -> None:
        self.tray: TrayIcon | None = None
        if not TrayIcon.available():
            log.info("系统托盘不可用，跳过托盘初始化")
            return
        self.tray = TrayIcon(self, self.theme.palette_dict())
        self.tray.show_requested.connect(self._restore_from_tray)
        self.tray.sync_requested.connect(lambda: self._sync_all())
        self.tray.lock_requested.connect(self.lock)
        self.tray.settings_requested.connect(self._on_settings)
        self.tray.quit_requested.connect(self.quit_app)
        if self.settings.minimize_to_tray:
            self.tray.show()

    def _setup_lock(self) -> None:
        self.lock_overlay = LockOverlay(self.ctx, self.settings, self)
        self.lock_overlay.hide()
        self.lock_overlay.unlocked.connect(self._on_unlocked)
        self.lock_overlay.quit_requested.connect(self.quit_app)
        self.installEventFilter(self.lock_overlay)
        # `_apply_theme()` 跑在 `_setup_lock()` 之前（遮罩还不存在），
        # 因此这里要单独补一次上色。
        self.lock_overlay.apply_theme(self.theme.palette_dict())

        self._idle = IdleWatcher(self)
        app = QApplication.instance()
        if app is not None:
            app.installEventFilter(self._idle)
        self._idle.activity.connect(self._on_activity)

        self._lock_timer = QTimer(self)
        self._lock_timer.timeout.connect(self._check_auto_lock)
        self._lock_timer.start(max(5, IDLE_POLL_SECONDS) * 1000)

    # ================================================================ 启动
    def _restore_geometry(self) -> None:
        data = self.settings.window_geometry
        if not data:
            return
        try:
            import base64

            from PySide6.QtCore import QByteArray
            self.restoreGeometry(QByteArray(base64.b64decode(data)))
        except (ValueError, TypeError):
            log.debug("窗口几何恢复失败", exc_info=True)

    def _save_geometry(self) -> None:
        try:
            import base64
            self.settings.window_geometry = base64.b64encode(
                bytes(self.saveGeometry())).decode("ascii")
        except (ValueError, TypeError):
            pass

    def _maybe_first_run(self) -> None:
        if self.ctx.accounts is None:
            return
        if self.ctx.accounts.list():
            return
        # 没有任何账号：无论是全新用户还是清空重来，都值得看一遍说明
        self._show_wizard(auto=True)

    def _initial_sync(self) -> None:
        if self.ctx.scheduler:
            self.ctx.scheduler.start()
        if self.ctx.accounts and self.ctx.accounts.list():
            self._sync_all()
        else:
            self.set_status("欢迎使用 UniMail — 请先添加一个邮箱账号")

    def _show_wizard(self, auto: bool = False) -> None:
        level = self.ctx.db.encryption_level if self.ctx.db else ""
        dlg = FirstRunWizard(level, self if not auto else None)
        dlg.add_account_requested.connect(self._on_add_account)
        dlg.exec()

    # ================================================================ 账号
    def refresh_accounts(self) -> None:
        if not self.ctx.accounts or not self.ctx.mails:
            return
        accounts = self.ctx.accounts.list()
        counts = self.ctx.mails.counts()
        total = self.ctx.mails.total_counts()
        self.account_panel.set_accounts(accounts, counts, total)
        if self.tray is not None:
            self.tray.set_unread(total[1],
                                 [(a.label, counts.get(a.id, (0, 0))[1]) for a in accounts])
        self._refresh_security_labels()

    def _refresh_delete_label(self) -> None:
        """让删除菜单的文案与真实行为一致。

        默认行为是「只删本机副本」，菜单就必须这么写——否则用户会以为
        服务器上的邮件也没了。开启服务器删除后，文案要相应改成「移入
        服务器垃圾箱」，同样是因为两者后果完全不同。
        """
        label = ("删除（移入服务器垃圾箱）" if self._delete_uses_server()
                 else "删除本地副本")
        self.inbox_panel.set_delete_label(label)

    def _refresh_security_labels(self) -> None:
        level = self.ctx.db.encryption_level if self.ctx.db else ""
        self.encryption_label.setText(f"🔒 {level}" if level else "")
        self._refresh_outbox_label()

    def _refresh_outbox_label(self) -> None:
        """状态栏的「待办」区：待同步标记 + 待发送邮件合并显示。

        两者本质不同——「待同步标记」是本地已知、只差推到服务器的已读/星标，
        用户无需干预；「待发送」是整封邮件还没送达，可能要重试。但状态栏
        空间有限，合并成一段比各占一个常驻标签更清晰。
        """
        flags = 0
        try:
            flags = self.ctx.mails.pending_flag_count() if self.ctx.mails else 0
        except Exception:  # noqa: BLE001 - 仅状态展示
            flags = 0
        pending = failed = 0
        if self.ctx.compose is not None:
            try:
                counts = self.ctx.compose.counts()
                pending = counts.get("pending", 0) + counts.get("sending", 0)
                failed = counts.get("failed", 0)
            except Exception:  # noqa: BLE001 - 仅状态展示
                pending = failed = 0
        parts = []
        if flags:
            parts.append(f"待同步标记 {flags}")
        if pending:
            parts.append(f"待发送 {pending} 封")
        if failed:
            parts.append(f"发送失败 {failed} 封")
        self.pending_label.setText(" · ".join(parts))

    def _on_account_selected(self, account) -> None:
        if self.ctx.accounts:
            self.ctx.accounts.set_active(account.id if account else None)
        self._refresh_folders()

    def _refresh_folders(self) -> None:
        """刷新文件夹下拉：列出当前账号（或全部）已同步的文件夹。

        数据来源是本地 mails 表（同步 worker 已经按服务器 LIST 拉过），
        不额外发网络请求。在账号切换、同步完成后调用——文件夹集合会随
        同步逐渐变全。
        """
        if self.ctx.mails is None:
            return
        try:
            folders = self.ctx.mails.list_folders(self.ctx.accounts.active_id)
        except Exception:  # noqa: BLE001 - 仅刷新下拉，不影响主流程
            folders = []
        self.filter_bar.set_folders(folders)

    # ================================================================ 发信
    def _on_compose(self) -> None:
        """写新邮件。"""
        if self._locked or self.ctx.compose is None:
            return
        accounts = self.ctx.accounts.list()
        if not accounts:
            QMessageBox.information(
                self, "还没有邮箱账号",
                "请先在「文件 → 添加邮箱账号」中添加一个账号，然后就能在这里写邮件了。")
            return
        dlg = ComposeDialog(self.ctx.compose, accounts, parent=self,
                            contacts=self.ctx.contacts)
        dlg.sent.connect(self._on_mail_sent)
        dlg.exec()

    def _on_reply(self, mail_id: str, *, reply_all: bool = False) -> None:
        """回复（或全部回复）一封已收邮件。"""
        if self._locked or self.ctx.compose is None:
            return
        try:
            draft = self.ctx.compose.build_reply(mail_id, reply_all=reply_all)
        except ValueError as exc:
            QMessageBox.warning(self, "无法回复", str(exc))
            return
        accounts = self.ctx.accounts.list()
        dlg = ComposeDialog(self.ctx.compose, accounts, draft, parent=self,
                            contacts=self.ctx.contacts)
        dlg.sent.connect(self._on_mail_sent)
        dlg.exec()

    def _on_forward(self, mail_id: str) -> None:
        """转发一封已收邮件。"""
        if self._locked or self.ctx.compose is None:
            return
        try:
            draft = self.ctx.compose.build_forward(mail_id)
        except ValueError as exc:
            QMessageBox.warning(self, "无法转发", str(exc))
            return
        accounts = self.ctx.accounts.list()
        dlg = ComposeDialog(self.ctx.compose, accounts, draft, parent=self,
                            contacts=self.ctx.contacts)
        dlg.sent.connect(self._on_mail_sent)
        dlg.exec()

    def send_outbox_item(self, msg_id: str) -> None:
        """在后台线程投递一封已入队的邮件。

        为什么不在 `ComposeDialog` 里同步发送：那一步包含完整 SMTP 会话
        （最坏 30 秒），放在对话框的 `accept()` 之前会冻结界面。对话框只负责
        「写入队列 + 关闭」，实际投递交给这里——与附件下载、导出走同一条
        后台 IO 通道（`io_runner.py`），结果回主线程后如实汇报。
        """
        if self.ctx.compose is None:
            return

        def done(result, error) -> None:
            if error is not None:
                self.set_status("发送失败")
                QMessageBox.warning(self, "发送失败",
                                    f"邮件未能发出：\n\n{_io_error_text(error)}\n\n"
                                    "它已保存在发件箱里，可以从那里重试。")
                self._refresh_outbox_label()
                return
            if result.ok:
                self.set_status("邮件已发送")
            else:
                self.set_status("发送失败")
                QMessageBox.warning(self, "发送失败",
                                    f"{result.error}\n\n邮件已保存在发件箱里，可以从那里重试。")
            self._refresh_outbox_label()

        self._run_io(lambda: self.ctx.compose.send_one(msg_id), done,
                     key=f"smtp:{msg_id}")

    def _on_mail_sent(self) -> None:
        """撰写对话框关闭后刷新发件箱计数。"""
        self._refresh_outbox_label()

    def _on_add_account(self) -> None:
        # 锁屏期间遮罩之外的动作一律拒绝：遮罩只是视觉层，菜单快捷键与
        # 托盘菜单仍能触发这些入口（设置页尤其危险：可改加密模式、可绑定设备密钥）。
        if self._locked:
            return
        dlg = AddAccountDialog(self)
        if dlg.exec() != AddAccountDialog.Accepted or dlg.draft is None:
            return
        draft = dlg.draft

        if dlg.should_verify:
            self.set_status(f"正在验证 {draft.email} 的凭据…")

            def done(result, error) -> None:
                if error is not None:
                    self.set_status("凭据验证失败")
                    QMessageBox.warning(self, "连接失败",
                                        f"无法使用该凭据登录：\n\n{_io_error_text(error)}")
                    return
                ok, msg = result
                if not ok:
                    self.set_status("凭据验证失败")
                    QMessageBox.warning(self, "连接失败", f"无法使用该凭据登录：\n\n{msg}")
                    return
                self.set_status("凭据验证通过")
                self._finish_add_account(draft)

            # 「试连校验」= TCP + TLS 握手 + LOGIN，是一整串网络往返（最长 30 秒）。
            # 此前它在 GUI 线程上同步执行，配合 `processEvents()` 只能把一次长阻塞
            # 切成很多次短阻塞：窗口期间不重绘、点不动，正是「界面无响应」的一种。
            self._run_io(lambda: self.ctx.accounts.verify(draft), done,
                         key=f"verify:{draft.platform}:{draft.email}")
            return

        self._finish_add_account(draft)

    def _finish_add_account(self, draft) -> None:
        try:
            account = self.ctx.accounts.add(draft)
        except (ValueError, SecurityError) as exc:
            QMessageBox.warning(self, "添加失败", str(exc))
            return

        self.set_status(f"已添加 {account.email}，正在首次同步…")
        self.refresh_accounts()
        self.account_panel.select_account(account.id)
        self._on_sync_account(account.id)

    def _on_remove_account(self, account_id: str) -> None:
        # 锁屏期间遮罩之外的动作一律拒绝：遮罩只是视觉层，菜单快捷键与
        # 托盘菜单仍能触发这些入口（设置页尤其危险：可改加密模式、可绑定设备密钥）。
        if self._locked:
            return
        account = self.ctx.accounts.get(account_id)
        if account is None:
            return
        ret = QMessageBox.question(
            self, "删除账号",
            f"确定删除账号 {account.email} 吗？\n\n"
            "该账号的本地邮件副本与已保存凭据都会被一并清除，此操作不可撤销。",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if ret != QMessageBox.Yes:
            return
        # 顺序很重要：先停掉该账号正在跑的同步并**等它退出**，再删数据。
        # 只关会话不够——worker 可能正好在 `insert_mails_batch` 里，把整页
        # 数据写进一个即将消失的账号（mails 表对 accounts 没有外键，数据库
        # 层面拦不住），留下永远不会被清理的孤儿行。
        stopped = True
        if self.ctx.pool:
            stopped = self.ctx.pool.stop_account(account_id, timeout_ms=5000)
        self.ctx.sessions.close_account(account_id)
        self.ctx.accounts.remove(account_id)
        self.detail_panel.clear()
        self.refresh_accounts()
        self.reload_mails()
        if stopped:
            self.set_status(f"已删除账号 {account.email}")
        else:
            self.set_status(
                f"已删除账号 {account.email}（同步任务未能在 5 秒内退出，"
                "可能有少量本地数据残留；下次同步前不会影响使用）"
            )

    def _on_manage_account(self, account_id: str) -> None:
        # 锁屏期间遮罩之外的动作一律拒绝：遮罩只是视觉层，菜单快捷键与
        # 托盘菜单仍能触发这些入口（设置页尤其危险：可改加密模式、可绑定设备密钥）。
        if self._locked:
            return
        account = self.ctx.accounts.get(account_id)
        if account is None:
            return
        QMessageBox.information(
            self, "账号信息",
            f"邮箱：{account.email}\n"
            f"平台：{account.platform}\n"
            f"IMAP：{account.imap_host}:{account.imap_port} "
            f"({'SSL' if account.use_ssl else '明文'})\n"
            f"刷新间隔：{account.sync_interval} 秒\n"
            f"状态：{account.status}\n\n"
            "如需修改密码或服务器，请删除后重新添加。",
        )

    def _on_mark_all_read(self, account_id: str) -> None:
        self.ctx.mails.mark_all_read(account_id)
        self.refresh_accounts()
        self.reload_mails()
        self.set_status("已全部标记为已读")

    # ================================================================ 同步
    def _sync_all(self) -> None:
        # 锁屏期间遮罩之外的动作一律拒绝：遮罩只是视觉层，菜单快捷键与
        # 托盘菜单仍能触发这些入口（设置页尤其危险：可改加密模式、可绑定设备密钥）。
        if self._locked:
            return
        if not self.ctx.scheduler:
            return
        n = self.ctx.scheduler.sync_now(None)
        self.set_status(f"已派发 {n} 个账号的同步任务" if n else "暂无需要同步的账号")

    def _on_sync_account(self, account_id: str) -> None:
        # 锁屏期间遮罩之外的动作一律拒绝：遮罩只是视觉层，菜单快捷键与
        # 托盘菜单仍能触发这些入口（设置页尤其危险：可改加密模式、可绑定设备密钥）。
        if self._locked:
            return
        if not account_id:
            self._sync_all()
            return
        n = self.ctx.scheduler.sync_now(account_id)
        if n:
            self.set_status("正在同步该账号…")

    def _on_sync_started(self, account_id: str) -> None:
        account = self.ctx.accounts.get(account_id)
        name = account.email if account else account_id
        self._last_sync_status[account_id] = "syncing"
        self.set_status(f"正在同步 {name}…")

    def _on_sync_finished(self, account_id: str, new_count: int) -> None:
        account = self.ctx.accounts.get(account_id)
        name = account.email if account else account_id
        self._last_sync_status.pop(account_id, None)
        self.set_status(f"{name}：新增 {new_count} 封邮件" if new_count
                        else f"{name}：已是最新")
        self.refresh_accounts()
        self._refresh_security_labels()
        # 同步可能带来新文件夹（首次同步把非 INBOX 文件夹拉进来），刷新下拉
        self._refresh_folders()
        if new_count:
            self._notify_new_mail(account_id, name, new_count)
            self._maybe_prefetch()

    def _on_sync_error(self, account_id: str, message: str) -> None:
        account = self.ctx.accounts.get(account_id)
        name = account.email if account else account_id
        self._last_sync_status.pop(account_id, None)
        self.set_status(f"{name} 同步失败")
        log.warning("同步失败 %s: %s", name, message)
        self.refresh_accounts()
        # 只弹一次，避免定时刷新时反复打扰
        if not getattr(self, "_error_shown", False):
            self._error_shown = True
            QMessageBox.warning(
                self, "同步失败",
                f"账号 {name} 同步失败：\n\n{message}\n\n"
                "请检查网络、授权码是否过期，或该平台 IMAP 服务是否已开启。",
            )

    def _notify_new_mail(self, account_id: str, name: str, count: int) -> None:
        if self.tray is None or not self.settings.show_notifications:
            return
        # 锁屏或托盘态下不弹通知：通知会把主题/发件人显示在锁屏之上，
        # 等于绕过锁定。用户解锁后会看到未读数。
        if self._locked or not self.isVisible():
            return
        subjects: list[str] = []
        try:
            recent = self.ctx.mails.inbox(
                MailFilter(account_id=account_id, limit=3))
            subjects = [m.subject or "" for m in recent]
        except Exception:
            log.debug("读取最新主题失败", exc_info=True)
        self.tray.notify_new_mail(name, subjects, account_id)

    def _on_cancel_task(self, task_id: str) -> None:
        if task_id.startswith("sync:") and self.ctx.pool:
            account_id = task_id.split(":", 1)[1]
            if self.ctx.pool.cancel_account(account_id):
                self.set_status("已请求取消同步…")
                return
        self.set_status("该任务已结束或无法取消")

    # ================================================================ 列表
    def _on_filter_changed(self) -> None:
        self._search_timer.start(180)

    def _focus_search(self) -> None:
        self.filter_bar.search.setFocus()
        self.filter_bar.search.selectAll()

    def reload_mails(self) -> None:
        if not self.ctx.mails:
            return
        flt = self._current_filter()
        keyword = flt.keyword
        hint = None
        # 只有「按时间倒序」能安全地 keyset 翻页：游标就是 (date, id)。
        # 换成别的排序键时游标与排序不一致，翻页会重复或漏行，因此那几种
        # 排序一次性取够（排序仍然下推到 SQL，不会出现「只排当前页」）。
        paged = flt.order == "time" and flt.desc
        flt.limit = PAGE_SIZE if paged else SORT_SCAN_LIMIT
        self._page_cursor = None
        self._has_more = False

        if self._view_mode == "thread":
            threads = self.ctx.mails.threads(flt)
            mails = [t.latest for t in threads]
            hit = self.ctx.mails.search_count(flt) if keyword else None
            if not threads:
                hint = self._empty_hint(flt)
            self.inbox_panel.set_mails(mails, hint, hit_count=hit, keyword=keyword,
                                       thread_mode=True, threads=threads)
            self.inbox_panel.set_has_more(False)
            self._reopen_expanded_threads()
        else:
            mails = self.ctx.mails.inbox(flt)
            hit = self.ctx.mails.search_count(flt) if keyword else None
            if not mails:
                hint = self._empty_hint(flt)
            self.inbox_panel.set_mails(mails, hint, hit_count=hit, keyword=keyword)
            if paged and len(mails) >= PAGE_SIZE:
                self._page_cursor = self._cursor_of(mails)
            self._has_more = self._page_cursor is not None
            self.inbox_panel.set_has_more(self._has_more)

        self.refresh_accounts()
        self._maybe_prefetch()
        if keyword:
            self.set_status(f"「{keyword}」命中 {hit if hit is not None else len(mails)} 封")
        elif not paged:
            self.set_status(f"已按当前列排序 · 最多显示 {SORT_SCAN_LIMIT} 封")

    @staticmethod
    def _cursor_of(mails) -> tuple[datetime, str] | None:
        """取这一页最后一行的 `(date, id)` 作为下一页的游标。"""
        for mail in reversed(mails):
            if mail.date is not None:
                return mail.date, mail.id
        return None

    def _load_more(self) -> None:
        """列表视图：加载下一页（keyset 游标，不重排已加载的行）。

        串行化由 `_loading_more` 保证：滚动事件在快速拖动时会连续触发，
        没有这个闩就会同时发出多个相同游标的查询。
        """
        if (self._locked or self._loading_more or not self._has_more
                or self._page_cursor is None or not self.ctx.mails
                or self._view_mode != "list"):
            return
        self._loading_more = True
        try:
            flt = self._current_filter()
            flt.limit = PAGE_SIZE
            flt.before_date, flt.before_id = self._page_cursor
            mails = self.ctx.mails.inbox(flt)
            if not mails:
                self._has_more = False
                self._page_cursor = None
                self.inbox_panel.set_has_more(False)
                return
            self.inbox_panel.append_mails(mails)
            self._page_cursor = self._cursor_of(mails)
            self._has_more = len(mails) >= PAGE_SIZE and self._page_cursor is not None
            self.inbox_panel.set_has_more(self._has_more)
        except Exception:
            log.exception("加载下一页失败")
            self._has_more = False
            self.inbox_panel.set_has_more(False)
        finally:
            self._loading_more = False

    def _current_filter(self) -> MailFilter:
        d_from, d_to = self.filter_bar.date_range()
        order_key, desc = self.inbox_panel.model.sort_state
        # 搜索框支持前缀语法（from:/subject:/has:/is: 等），先解析再分别
        # 填入结构化字段与自由关键词。语法解析失败（不认识的 has:xxx）
        # 通过 _on_search_syntax_error 提示，不阻断查询。
        parsed = parse_query(self.filter_bar.current_keyword())
        return MailFilter(
            account_id=self.ctx.accounts.active_id,
            platform=self.filter_bar.current_platform() or parsed.platform or None,
            folder=self.filter_bar.current_folder() or parsed.folder or None,
            keyword=parsed.keyword,
            from_addr=parsed.from_addr,
            to_addr=parsed.to_addr,
            subject=parsed.subject,
            has_attachment=parsed.has_attachment,
            starred_only=parsed.starred_only,
            unread_only=(self.filter_bar.is_unread_only()
                         if parsed.unread_only is None else parsed.unread_only),
            date_from=d_from,
            date_to=d_to,
            # 排序下推到 SQL：只在已加载的一页内排序会让「按发件人排序」
            # 显示的是一个残缺的顺序，用户无从知道它只覆盖了 200 封。
            order="time" if order_key == "time" else order_key,
            desc=desc,
        )

    def _empty_hint(self, flt: MailFilter) -> str:
        if flt.keyword or flt.platform or flt.unread_only or flt.date_from:
            return "没有符合筛选条件的邮件，\n试试放宽条件或重置筛选。"
        if not self.ctx.accounts.list():
            return "还没有绑定任何邮箱账号。\n点击左下角「添加邮箱账号」开始使用。"
        return "这个账号下还没有邮件。"

    def toggle_view_mode(self) -> None:
        self._view_mode = "thread" if self._view_mode == "list" else "list"
        self.settings.view_mode = self._view_mode
        self.settings.save()
        self.inbox_panel.toolbar.set_view_mode(self._view_mode)
        self.reload_mails()
        self.set_status("已切换到会话视图" if self._view_mode == "thread" else "已切换到列表视图")

    def _on_thread_toggle(self, thread_key: str, row: int) -> None:
        if not self.ctx.mails:
            return
        members = self.ctx.mails.thread_mails(thread_key, limit=200)
        self.inbox_panel.toggle_thread(thread_key, row, members)

    def _reopen_expanded_threads(self) -> None:
        """刷新后把用户展开过的会话重新摊开。

        `set_threads` 只重建线程头，成员行需要按 key 重新查库插入——
        否则模型记住了「展开」，屏幕上却只有一行，箭头与会话数会自相矛盾。
        """
        if self.ctx.mails is None:
            return
        for key in list(self.inbox_panel.expanded_thread_keys()):
            row = self.inbox_panel.row_of_thread(key)
            if row < 0:
                continue
            members = self.ctx.mails.thread_mails(key, limit=200)
            self.inbox_panel.model.set_thread_members(key, members, row)

    # ================================================================ 邮件
    def _on_mail_selected(self, mail_id: str) -> None:
        if not mail_id or self.ctx.mails is None:
            return
        mail = self.ctx.mails.get(mail_id)
        if mail is None:
            return

        if (self.ctx.body_pool and not (mail.body_text or mail.body_html)
                and self.ctx.body_pool.request(mail_id)):
            self.set_status("正在拉取邮件正文…")

        self.detail_panel.show_mail(mail)
        if not mail.is_read:
            self.ctx.mails.mark_read(mail_id, True)
            mail.is_read = True
            self.inbox_panel.refresh_row(mail.to_summary())
            self.refresh_accounts()
            self._refresh_security_labels()

    def _on_mail_body_fetched(self, mail_id: str) -> None:
        if self.inbox_panel.current_mail_id() != mail_id:
            return
        mail = self.ctx.mails.get(mail_id)
        if mail:
            self.detail_panel.show_mail(mail)
            self.set_status("正文已加载")

    def _on_mail_updated(self, mail_id: str) -> None:
        self._refresh_security_labels()
        self._on_mail_body_fetched(mail_id)

    def _on_mail_deleted(self, mail_id: str) -> None:
        self.inbox_panel.remove_mails([mail_id])
        if self.detail_panel._mail is not None and self.detail_panel._mail.id == mail_id:  # noqa: SLF001
            self.detail_panel.clear()
        self.refresh_accounts()

    def _on_mails_inserted(self, account_id: str, mail_ids: list[str]) -> None:
        """增量插入：只有「当前筛选确实包含这些新邮件」时才插进列表。"""
        if not mail_ids or self.ctx.mails is None:
            return
        if self._view_mode == "thread" or self.filter_bar.current_keyword():
            self.reload_mails()
            return
        active = self.ctx.accounts.active_id
        if active and active != account_id:
            return
        flt = self._current_filter()
        if flt.platform or flt.date_from or flt.unread_only:
            self.reload_mails()
            return
        summaries = self.ctx.mails.summaries_by_ids(mail_ids)
        n = self.inbox_panel.insert_mails(summaries)
        self.refresh_accounts()
        if n:
            self.set_status(f"收到 {n} 封新邮件")
            self._maybe_prefetch()

    def _on_mails_removed(self, mail_ids: list[str]) -> None:
        if mail_ids:
            self.inbox_panel.remove_mails(list(mail_ids))
            self.refresh_accounts()

    def _maybe_prefetch(self) -> None:
        """后台预取可见行的正文（设置开关 + 有会话池时才做）。"""
        if not self.settings.prefetch_bodies or self.ctx.body_pool is None:
            return
        if self._locked:
            return
        ids = self.inbox_panel.model.mail_ids()[:12]
        if ids:
            self.ctx.body_pool.prefetch(ids, limit=6)

    # ================================================================ 批量
    def _selected_or(self, mail_id: str) -> list[str]:
        ids = self.inbox_panel.selected_ids()
        return ids or ([mail_id] if mail_id else [])

    def _on_mark_read(self, mail_id: str, is_read: bool) -> None:
        self._on_mark_read_many(self._selected_or(mail_id), is_read)

    def _on_mark_read_many(self, mail_ids: list[str], is_read: bool) -> None:
        if not mail_ids:
            return
        n = self.ctx.mails.mark_read_many(mail_ids, is_read)
        self._refresh_rows(mail_ids)
        self.refresh_accounts()
        self._refresh_security_labels()
        self.set_status(f"已把 {n} 封标为{'已读' if is_read else '未读'}")

    def _on_star(self, mail_id: str) -> None:
        ids = self._selected_or(mail_id)
        if not ids:
            return
        current = self.ctx.mails.get(ids[0])
        target = not current.is_starred if current else True
        self._on_star_many(ids, target)

    def _on_star_many(self, mail_ids: list[str], starred: bool) -> None:
        if not mail_ids:
            return
        n = self.ctx.mails.star_many(mail_ids, starred)
        self._refresh_rows(mail_ids)
        self.set_status(f"已为 {n} 封{'加星标' if starred else '取消星标'}"
                        + ("（将在下次同步时回写服务器）"
                           if self.settings.sync_server_flags else ""))
        self._refresh_security_labels()

    def _on_delete_mail(self, mail_id: str) -> None:
        self._on_delete_many(self._selected_or(mail_id))

    def _delete_uses_server(self) -> bool:
        return bool(getattr(self.settings, "delete_on_server", False))

    def _on_delete_many(self, mail_ids: list[str]) -> None:
        if not mail_ids:
            return
        on_server = self._delete_uses_server()
        # 单封「删除本地副本」沿用旧行为、不再二次确认（与常见邮件客户端一致）；
        # 一旦涉及服务器则**无论封数**都要确认——那是本程序撤销不了的动作。
        if on_server or len(mail_ids) > 1:
            if on_server:
                title = "移入服务器垃圾箱"
                body = (f"确定把选中的 {len(mail_ids)} 封邮件移入服务器垃圾箱吗？\n\n"
                        "邮件会先被移进垃圾箱（可在垃圾箱里恢复），随后移除本机副本。\n"
                        "若服务器拒绝或网络失败，本机副本会**保持不变**。")
            else:
                title = "删除本地副本"
                body = (f"确定删除选中的 {len(mail_ids)} 封邮件吗？\n\n"
                        "只删除本机副本，服务器上的邮件不受影响。\n"
                        "注意：重置同步或换设备后，这些邮件会重新出现。\n"
                        "（可在设置 → 行为中开启「同时移入服务器垃圾箱」）")
            ret = QMessageBox.question(
                self, title, body,
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            )
            if ret != QMessageBox.Yes:
                return

        if not on_server:
            self.ctx.mails.delete_many(mail_ids)
            self._after_delete(mail_ids)
            self.set_status(f"已删除 {len(mail_ids)} 封本地副本（服务器邮件不受影响）")
            return

        # 走服务器是**逐封一次 IMAP 往返**（还要先 SELECT 一次），选几百封就是
        # 几百次串行等待，必须在后台跑。
        self.set_status(f"正在把 {len(mail_ids)} 封邮件移入服务器垃圾箱…")

        def done(result, error) -> None:
            if error is not None:
                self.set_status("移入服务器垃圾箱失败")
                QMessageBox.warning(
                    self, "删除失败",
                    "移入服务器垃圾箱的过程中出错，已中止。\n\n"
                    f"{_io_error_text(error)}\n\n"
                    "已成功移入垃圾箱的邮件会在下一次同步时从列表消失；"
                    "本机副本不会被主动删除。",
                )
                return
            self._after_delete(result.removed_ids)
            if result.failed:
                # 失败的必须逐条说出来：只报「删了 N 封」会让用户以为整批都成功了，
                # 而这批里恰恰有几封还留在服务器上。
                shown = "\n".join(f"· {reason}" for _mid, reason in result.failed[:3])
                more = "" if len(result.failed) <= 3 else \
                    f"\n（另有 {len(result.failed) - 3} 封同类失败）"
                QMessageBox.warning(
                    self, "部分邮件未能删除",
                    f"已移入垃圾箱：{result.removed} 封\n"
                    f"失败：{len(result.failed)} 封（本机副本保持不变）\n\n{shown}{more}",
                )
                self.set_status(
                    f"已移入垃圾箱 {result.removed} 封，{len(result.failed)} 封失败（本机副本未动）")
            else:
                self.set_status(f"已把 {result.removed} 封邮件移入服务器垃圾箱并删除本机副本")

        self._run_io(lambda: self.ctx.mails.delete_many(mail_ids, on_server=True),
                     done, key="delete:server")

    def _after_delete(self, mail_ids: list[str]) -> None:
        if not mail_ids:
            return
        self.inbox_panel.remove_mails(mail_ids)
        current = self.detail_panel._mail  # noqa: SLF001
        if current is not None and current.id in mail_ids:
            self.detail_panel.clear()
        self.refresh_accounts()

    def _refresh_rows(self, mail_ids: list[str]) -> None:
        summaries = self.ctx.mails.summaries_by_ids(mail_ids)
        self.inbox_panel.refresh_rows(summaries)

    # ================================================================ 导出
    def _on_export(self, kind: str, mail_ids: list[str]) -> None:
        # 锁屏期间遮罩之外的动作一律拒绝：遮罩只是视觉层，菜单快捷键与
        # 托盘菜单仍能触发这些入口（设置页尤其危险：可改加密模式、可绑定设备密钥）。
        if self._locked:
            return
        if kind == "csv":
            self._export_csv()
            return
        if not mail_ids:
            self.set_status("请先选择要导出的邮件")
            return
        if kind == "eml":
            self._export_eml(mail_ids[0])
        elif kind == "mbox":
            self._export_mbox(mail_ids)

    def _export_eml(self, mail_id: str) -> None:
        mail = self.ctx.mails.get(mail_id)
        if mail is None:
            return
        default = _safe_name(mail.subject or "mail") + ".eml"
        path, _ = QFileDialog.getSaveFileName(self, "导出为 .eml", default,
                                              "邮件文件 (*.eml)")
        if not path:
            return
        self.set_status("正在导出…")

        def done(dest, error) -> None:
            if error is not None:
                self.set_status("导出失败")
                QMessageBox.warning(self, "导出失败", _io_error_text(error))
                return
            self.set_status(f"已导出：{dest}")

        # 导出要先去服务器取原始报文，是一次完整往返 —— 不能在 GUI 线程做
        self._run_io(lambda: self.ctx.mails.export_eml(mail_id, path),
                     done, key=f"export:{path}")

    def _export_mbox(self, mail_ids: list[str]) -> None:
        default = "unimail-导出.mbox"
        path, _ = QFileDialog.getSaveFileName(self, "导出为 .mbox", default,
                                              "mbox 归档 (*.mbox)")
        if not path:
            return
        total = len(mail_ids)
        self.set_status(f"正在导出 {total} 封邮件…")

        def report(done: int, all_: int) -> None:
            self.set_status(f"正在导出 {done}/{all_}…")

        # 进度的节流放在**工作线程**：几百封邮件逐封回投会把主线程事件队列
        # 刷满，反而让界面更卡。只在百分比变化或最后一封时回投一次。
        last = [-1]

        def progress(done: int, all_: int) -> None:
            pct = (done * 100) // max(1, all_)
            if pct == last[0] and done != all_:
                return
            last[0] = pct
            self._io.post(report, done, all_)

        def done(result, error) -> None:
            if error is not None:
                self.set_status("导出失败")
                QMessageBox.warning(self, "导出失败", _io_error_text(error))
                return
            dest, written = result
            self.set_status(f"已导出 {written} 封到 {dest}")
            QMessageBox.information(
                self, "导出完成",
                f"已导出 {written} 封邮件到：\n{dest}\n\n"
                "该格式可被 Thunderbird、mutt 等客户端直接导入。",
            )

        def work():
            return self.ctx.mails.export_mbox(mail_ids, path, progress=progress)

        self._run_io(work, done, key=f"export:{path}")

    def _export_csv(self) -> None:
        flt = self._current_filter()
        default = "unimail-邮件清单.csv"
        path, _ = QFileDialog.getSaveFileName(self, "导出 CSV 清单", default,
                                              "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            dest, rows = self.ctx.mails.export_csv(flt, path)
        except OSError as exc:
            QMessageBox.warning(self, "导出失败", str(exc))
            return
        self.set_status(f"已导出 {rows} 行到 {dest}")
        QMessageBox.information(self, "导出完成",
                                f"已导出 {rows} 行到：\n{dest}\n\n"
                                "文件带 UTF-8 BOM，Excel 打开不会乱码。")

    # ================================================================ 后台 IO
    def _run_io(self, fn, handler, key: str | None = None) -> bool:
        """把一次阻塞式服务调用丢到后台线程，完成后回主线程执行 `handler`。

        这里是所有网络 IO 的唯一入口（P1），因此维护窗口的检查也收在这里：
        「改主密码 / 迁移数据库加密」期间 `ctx.quiesced` 为真，此时提交的
        IMAP 往返可能在 rekey 之后才落盘，写出用旧密钥加密的行——直接拒绝。
        """
        if self.ctx.quiesced:
            self.set_status("正在维护数据库，请稍后再试")
            return False
        return self._io.submit(fn, handler, key=key)

    # ================================================================ 附件
    def _on_download_attachment(self, attachment_id: str) -> None:
        self.set_status("正在下载附件…")

        def done(result, error) -> None:
            if error is not None:
                self.set_status("附件下载失败")
                QMessageBox.warning(self, "下载失败", _io_error_text(error))
                return
            self.set_status(f"附件已保存到：{result.path}")
            lines = [f"附件已保存到：\n{result.path}"]
            if result.size:
                lines.append(f"\n大小：{result.size / 1024:.1f} KB")
            if result.danger and result.name_hint:
                lines.append(f"\n⚠️ {result.name_hint}")
            QMessageBox.information(
                self, "附件已下载" + ("（已做安全处理）" if result.danger else ""),
                "\n".join(lines),
            )

        self._run_io(lambda: self.ctx.mails.download_attachment(attachment_id),
                     done, key=f"attach:{attachment_id}")

    def _on_preview_attachment(self, attachment_id: str) -> None:
        att = self.ctx.mails.attachments.get(attachment_id)
        title = att.filename if att else "预览"
        self.set_status("正在准备预览…")

        def done(result, error) -> None:
            if error is not None:
                self.set_status("预览失败")
                QMessageBox.warning(self, "预览失败", _io_error_text(error))
                return
            kind, payload = result
            self.set_status("预览就绪")
            self.detail_panel.show_preview(kind, payload, title)

        self._run_io(lambda: self.ctx.mails.preview_attachment(attachment_id),
                     done, key=f"preview:{attachment_id}")

    def _resolve_inline(self, mail_id: str, content_id: str) -> bytes | None:
        if self.ctx.mails is None:
            return None
        return self.ctx.mails.inline_resource(mail_id, content_id)

    def _inline_missing(self, mail_id: str):
        if self.ctx.mails is None:
            return []
        return self.ctx.mails.inline_missing(mail_id)

    def _on_download_inline(self, mail_id: str) -> None:
        if self.ctx.mails is None:
            return
        self.set_status("正在下载内嵌图片…")

        def done(result, error) -> None:
            if error is not None:
                self.set_status("内嵌图片下载失败")
                QMessageBox.warning(self, "下载失败", _io_error_text(error))
                return
            ok, failed = result
            mail = self.ctx.mails.get(mail_id) if self.ctx.mails else None
            if mail is not None:
                self.detail_panel.show_mail(mail)
            msg = f"已加载 {ok} 张内嵌图片"
            if failed:
                msg += f"，{failed} 张失败"
            self.set_status(msg)

        self._run_io(lambda: self.ctx.mails.download_inline_images(mail_id),
                     done, key=f"inline:{mail_id}")

    # ================================================================ 锁定
    def _on_activity(self) -> None:
        self.ctx.security.touch()

    def lock(self, reason: str = "") -> None:
        if self._locked:
            return
        self._locked = True
        self._save_geometry()
        # 锁定时把详情面板里的正文清掉：遮罩是实心层，但详情面板的内容
        # 仍然留在内存与 DWM 缩略图缓存里，清掉更彻底。
        self.detail_panel.clear()

        # 遮罩是主窗口的**子控件**，盖不住同级顶层窗口：图片/文本预览是
        # 独立 QDialog，同步错误是 QMessageBox，锁定后它们仍会置顶显示，
        # 正文与图片保持可见、可拖动、可最大化。
        self._close_transient_windows()

        # 真正降回未解锁态：停后台 → 断会话 → 关库 → 清密钥。
        # 解锁时重新跑 KDF 并重建服务（见 `AppContext.lock()`）。
        # 只盖遮罩而不清密钥，「锁屏」就只是防肩窥，不是防物理接触。
        self.set_status("正在锁定…")
        QApplication.processEvents()
        try:
            self.ctx.lock()
        except Exception:
            log.exception("锁屏时释放安全上下文失败")

        self.menuBar().setEnabled(False)
        if self.tray is not None:
            self.tray.set_locked(True)

        self.lock_overlay.lock(reason)
        log.info("界面已锁定")

    def _close_transient_windows(self) -> None:
        """关闭所有会盖在遮罩之上的顶层窗口。

        `QApplication.topLevelWidgets()` 里既有主窗口也有独立对话框；
        逐个关掉 `QDialog`（`QMessageBox` 是它的子类）即可覆盖预览与错误弹窗。
        """
        for widget in QApplication.topLevelWidgets():
            if widget is self or widget is self.lock_overlay:
                continue
            if widget.isVisible() and isinstance(widget, QDialog):
                widget.close()

    def _on_unlocked(self) -> None:
        self._locked = False
        # 不依赖信号发送方（遮罩/未来的其它解锁入口）顺手隐藏自己：
        # 这里是「已解锁」的唯一权威落点，漏掉一次就是明文内容裸露。
        self.lock_overlay.hide()
        self.menuBar().setEnabled(True)
        if self.tray is not None:
            self.tray.set_locked(False)
        self.ctx.security.touch()
        # 锁屏时数据库连接被关闭、密钥被清空，解锁是**重新打开**的：
        # 内存里的模型、计数缓存、会话池全部是新的，必须整表重载。
        self.refresh_accounts()
        self.reload_mails()
        if self.ctx.scheduler:
            self.ctx.scheduler.start()
        # 放在 reload 之后：刷新过程可能自己写状态栏，别把提示盖掉
        self.set_status("已解锁")

    def _check_auto_lock(self) -> None:
        if self._locked:
            return
        if self.ctx.security.idle_seconds() >= AUTO_LOCK_SECONDS:
            minutes = int(AUTO_LOCK_SECONDS // 60)
            self.lock(f"已闲置超过 {minutes} 分钟，为保护邮件内容已自动锁定。")

    def _on_escape(self) -> None:
        if self._locked:
            return
        if self.filter_bar.current_keyword():
            self.filter_bar.search.clear()

    # ================================================================ 托盘
    def _restore_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()
        if self._locked:
            self.lock_overlay.raise_()

    def changeEvent(self, event) -> None:
        if (event.type() == QEvent.WindowStateChange and self.isMinimized()
                and self.settings.minimize_to_tray and self.tray is not None):
            QTimer.singleShot(0, self.hide)
            if self.settings.lock_on_minimize:
                self.lock("窗口已最小化到托盘，已自动锁定。")
        super().changeEvent(event)

    def closeEvent(self, event) -> None:
        if not self._quitting and self.settings.minimize_to_tray and self.tray is not None:
            event.ignore()
            self._save_geometry()
            self.settings.save()
            self.hide()
            if self.settings.lock_on_minimize:
                self.lock("窗口已隐藏到托盘，已自动锁定。")
            else:
                self.tray.notify(APP_NAME, "已最小化到系统托盘，仍在后台收信。")
            return
        self.quit_app()

    def quit_app(self) -> None:
        """真正退出：停线程 → 关库 → 退出进程。"""
        if self._quitting:
            return
        self._quitting = True
        # 先掐掉后台 IO 的回投：接下来要停线程、关库，任何「下载失败」之类的
        # 结果弹窗都会卡在退出路径上。
        self._io.stop()
        self._save_geometry()
        try:
            self.settings.save()
        except OSError:
            log.debug("保存设置失败", exc_info=True)

        self.set_status("正在停止后台任务…")
        QApplication.processEvents()
        stragglers = []
        try:
            stragglers = self.ctx.shutdown()
        except Exception:
            log.exception("关闭时出错")
        if stragglers:
            QMessageBox.warning(
                self, "仍有任务未结束",
                "以下账号的同步任务未能在超时内结束，进程即将退出：\n"
                + "\n".join(f"· {s}" for s in stragglers)
                + "\n\n已提交的数据库事务不会丢失。",
            )
        if self.tray is not None:
            self.tray.hide()
        self._detach_global_filters()
        event_loop = QApplication.instance()
        if event_loop is not None:
            event_loop.quit()
        self.close()

    def _detach_global_filters(self) -> None:
        """退出前摘掉装在应用 / 窗口上的全局事件过滤器。

        过滤器对象的生命周期跟着窗口走，而 `QApplication` 在解释器退出时
        才销毁——不摘掉的话，销毁顺序不确定会让 Qt 回调一个已释放的
        过滤器对象（表现为退出阶段 `munmap_chunk(): invalid pointer`）。
        """
        event_loop = QApplication.instance()
        if event_loop is not None and getattr(self, "_idle", None) is not None:
            event_loop.removeEventFilter(self._idle)
        if getattr(self, "lock_overlay", None) is not None:
            self.removeEventFilter(self.lock_overlay)

    # ================================================================ 菜单动作
    def _on_contacts(self) -> None:
        # 锁屏期间遮罩之外的动作一律拒绝（与设置页同一条安全红线）。
        if self._locked or self.ctx.contacts is None:
            return
        ContactDialog(self.ctx.contacts, self).exec()

    def _on_settings(self) -> None:
        # 锁屏期间遮罩之外的动作一律拒绝：遮罩只是视觉层，菜单快捷键与
        # 托盘菜单仍能触发这些入口（设置页尤其危险：可改加密模式、可绑定设备密钥）。
        if self._locked:
            return
        dlg = SettingsDialog(self.ctx, self.settings, self)
        dlg.preview_requested.connect(self._preview_theme)
        if dlg.exec() == SettingsDialog.Accepted:
            self._apply_settings()
            self.set_status("设置已保存")
        else:
            self._preview_theme(self.settings.theme_mode, self.settings.font_scale)

    def _preview_theme(self, mode: str, scale: float) -> None:
        """设置对话框里的即时预览（不落盘，取消时自动还原）。"""
        self.theme.set_mode(mode)
        self.theme.set_scale(scale)
        self._apply_theme()

    def _on_about(self) -> None:
        # 锁屏期间遮罩之外的动作一律拒绝：遮罩只是视觉层，菜单快捷键与
        # 托盘菜单仍能触发这些入口（设置页尤其危险：可改加密模式、可绑定设备密钥）。
        if self._locked:
            return
        level = self.ctx.db.encryption_level if self.ctx.db else "未知"
        kdf = ""
        # 元数据读不到（驱动不匹配等）不该挡住「关于」对话框
        with contextlib.suppress(Exception):
            params, _v, _d = self.ctx._read_security_meta()      # noqa: SLF001
            kdf = params.display
        AboutDialog(level, self, kdf=kdf, ctx=self.ctx).exec()

    def _on_export_recovery(self) -> None:
        # 锁屏期间遮罩之外的动作一律拒绝：遮罩只是视觉层，菜单快捷键与
        # 托盘菜单仍能触发这些入口（设置页尤其危险：可改加密模式、可绑定设备密钥）。
        if self._locked:
            return
        default = str(self.ctx._sidecar.with_name("unimail-recovery.json"))  # noqa: SLF001
        path, _ = QFileDialog.getSaveFileName(self, "导出恢复包", default,
                                             "JSON 文件 (*.json)")
        if not path:
            return
        try:
            dest = self.ctx.export_recovery_bundle(path)
        except (SecurityError, OSError) as exc:
            QMessageBox.warning(self, "导出失败", str(exc))
            return
        QMessageBox.information(
            self, "恢复包已导出",
            f"已导出到：\n{dest}\n\n"
            "该文件只含 salt / 迭代次数 / 算法标识，不含密码或任何密文。\n"
            "请离线保存：侧车文件损坏时靠它重建密钥派生参数。",
        )

    def _on_encryption_settings(self) -> None:
        # 锁屏期间遮罩之外的动作一律拒绝：遮罩只是视觉层，菜单快捷键与
        # 托盘菜单仍能触发这些入口（设置页尤其危险：可改加密模式、可绑定设备密钥）。
        if self._locked:
            return
        from ..storage import sqlcipher_available
        db = self.ctx.db
        if db is None:
            return
        if not sqlcipher_available():
            from ..config import sqlcipher_pip_hint
            QMessageBox.information(
                self, "数据库加密",
                f"当前加密等级：{db.encryption_level}\n\n"
                "环境未安装 sqlcipher3，无法启用整库加密。\n"
                "安装依赖后重启即可在启动时选择迁移：\n"
                f"    {sqlcipher_pip_hint()}",
            )
            return

        if db.encrypted:
            ret = QMessageBox.question(
                self, "数据库加密",
                f"当前加密等级：{db.encryption_level}\n\n"
                "是否解除整库加密（迁移为明文）？\n"
                "明文库的主题、正文、发件人可被本机其它程序读取，"
                "且会保留 *.encrypted.bak 备份。",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            )
            target = "plaintext"
        else:
            ret = QMessageBox.question(
                self, "数据库加密",
                f"当前加密等级：{db.encryption_level}\n\n"
                "是否立即启用整库加密（SQLCipher AES-256）？\n"
                "原库会备份为 *.plaintext.bak，迁移失败不会改动原库。",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes,
            )
            target = "encrypted"
        if ret != QMessageBox.Yes:
            return

        self.set_status("正在迁移数据库加密模式…")
        QApplication.processEvents()
        try:
            driver = self.ctx.migrate_encryption(target)
        except (SecurityError, OSError, RuntimeError) as exc:
            QMessageBox.warning(self, "迁移失败", f"数据库保持原状。\n\n{exc}")
            self.set_status("迁移失败")
            return

        level = self.ctx.db.encryption_level if self.ctx.db else driver
        self._refresh_security_labels()
        leftover = ""
        backup = self.ctx.last_plaintext_backup
        if backup is not None:
            # 只有保留配置生效或删除失败时才会走到这里，必须说清楚
            leftover = (
                f"\n\n注意：明文备份仍留在 {backup.name}。"
                "它是一份完整可读的数据库副本，会抵消整库加密的保护——"
                "确认新库能正常打开后，请手工删除该文件。"
            )
        QMessageBox.information(self, "迁移完成", f"当前加密等级：{level}{leftover}")

    def _on_change_password(self) -> None:
        # 锁屏期间遮罩之外的动作一律拒绝：遮罩只是视觉层，菜单快捷键与
        # 托盘菜单仍能触发这些入口（设置页尤其危险：可改加密模式、可绑定设备密钥）。
        if self._locked:
            return
        from PySide6.QtWidgets import QInputDialog

        from ..config import PASSWORD_MIN_LENGTH
        from ..core.security import password_strength

        old, ok = QInputDialog.getText(self, "修改主密码", "当前主密码：",
                                       QLineEdit_EchoMode_Password())
        if not ok or not old:
            return
        new, ok = QInputDialog.getText(
            self, "修改主密码",
            f"新主密码（至少 {PASSWORD_MIN_LENGTH} 位，建议混合大小写、数字与符号）：",
            QLineEdit_EchoMode_Password(),
        )
        if not ok:
            return
        if len(new) < PASSWORD_MIN_LENGTH:
            QMessageBox.warning(
                self, "修改失败",
                f"新主密码至少 {PASSWORD_MIN_LENGTH} 位。\n\n"
                "主密码是保护全部邮件与登录凭据的唯一屏障，"
                "且离线爆破不受尝试次数限制——长度是最有效的强度来源。",
            )
            return
        score, label = password_strength(new)
        if score <= 1:
            ret = QMessageBox.warning(
                self, "密码强度偏低",
                f"当前强度评估：{label}\n\n"
                "建议再加入大写字母、数字或符号，或进一步加长。\n"
                "仍要使用这个密码吗？",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            )
            if ret != QMessageBox.Yes:
                return
        if new == old:
            QMessageBox.information(self, "无需修改", "新主密码与当前密码相同。")
            return

        self.set_status("正在重新加密凭据与数据库…")
        QApplication.processEvents()
        try:
            result = self.ctx.change_password(old, new)
        except SecurityError as exc:
            QMessageBox.warning(self, "修改失败", str(exc))
            self.set_status("修改失败")
            return

        # 如实告知实际发生了什么，不笼统说"成功"
        lines = [
            "主密码已更新。",
            f"· 已重新加密 {result.credentials_rotated} 个账号的登录凭据",
        ]
        if result.database_rekeyed:
            lines.append("· 数据库已整库重新加密（SQLCipher AES-256）")
        else:
            lines.append(
                "· 数据库未整库重新加密：当前为降级模式（未安装 SQLCipher），"
                "数据库本身为明文，仅登录凭据受字段级加密保护。\n"
                "  如需整库加密，请在「文件 → 数据库加密设置」中迁移。"
            )
        if result.kdf:
            lines.append(f"· 密钥派生参数已更新为：{result.kdf}")
        if self.ctx.device_binding.is_bound():
            lines.append("· 设备绑定的主密钥已失效，已自动解除（需重新绑定）")
        lines.append("\n请牢记新密码——遗忘将无法恢复任何数据。")
        QMessageBox.information(self, "主密码已更新", "\n".join(lines))
        self.set_status("主密码已更新，凭据已重新加密")
        self._refresh_security_labels()

    def _offer_kdf_upgrade(self) -> None:
        """旧库的 KDF 弱于当前默认时提示升级（改密码即完成升级）。"""
        if not getattr(self.ctx, "kdf_upgrade_pending", False):
            return
        ret = QMessageBox.question(
            self, "建议升级密钥派生参数",
            "当前数据库使用的是较早的密钥派生参数（PBKDF2），"
            "在显卡上被暴力破解的成本明显低于现在的默认算法（Argon2id，内存硬）。\n\n"
            "是否现在通过「修改主密码」升级？\n"
            "（不升级也能正常使用，但建议尽快完成。）",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes,
        )
        if ret == QMessageBox.Yes:
            self._on_change_password()

    # ================================================================ 杂项
    def set_status(self, text: str) -> None:
        self.status_text.setText(text)


def _safe_name(text: str, limit: int = 80) -> str:
    """把主题变成安全的文件名片段。"""
    import re
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", text or "").strip().rstrip(". ")
    return (cleaned[:limit] or "mail")


# 后台任务里「本该发生」的异常：直接说它的文案就够清楚。
# 其余异常属于意外，把类型名一并带上，否则用户只看到一句莫名其妙的话。
_IO_EXPECTED_ERRORS = (
    FileNotFoundError, PermissionError, OSError,
    ValueError, SecurityError, ImapError,
)


def _io_error_text(error: BaseException) -> str:
    """把后台任务抛出的异常转成给用户看的一段话。

    后台执行意味着异常不再由 Qt 打到 stderr；如果这里不落成文案，用户看到的
    就只是「点了没反应」。因此宁可啰嗦也要把它说出来。
    """
    text = str(error).strip() or error.__class__.__name__
    if isinstance(error, _IO_EXPECTED_ERRORS):
        return text
    return f"意外错误（{error.__class__.__name__}）：{text}"


def QLineEdit_EchoMode_Password():
    from PySide6.QtWidgets import QLineEdit
    return QLineEdit.Password

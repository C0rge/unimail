"""主窗口：三栏布局 + 状态栏 + 事件接线。"""
from __future__ import annotations

import logging

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QSplitter,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from ..config import APP_NAME, AUTO_LOCK_SECONDS
from ..core.models import MailFilter
from ..core.security import SecurityError
from .account_panel import AccountPanel
from .context import AppContext
from .detail_panel import DetailPanel
from .dialogs import AboutDialog, AddAccountDialog
from .filter_bar import FilterBar
from .inbox_panel import InboxPanel

log = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    def __init__(self, context: AppContext) -> None:
        super().__init__()
        self.ctx = context
        self.setWindowTitle(f"{APP_NAME} — 多平台邮箱统一管理")
        self.resize(1280, 800)
        self.setMinimumSize(1000, 620)

        self._pending_verify: AddAccountDialog | None = None
        self._last_sync_status: dict[str, str] = {}

        self._build_ui()
        self._wire_events()
        self._install_shortcuts()

        # 空闲自动锁定检查
        self._lock_timer = QTimer(self)
        self._lock_timer.timeout.connect(self._check_auto_lock)
        self._lock_timer.start(60_000)

        # 立即渲染本地已有数据，再延迟触发网络同步
        self.refresh_accounts()
        self.reload_mails()
        QTimer.singleShot(200, self._offer_kdf_upgrade)
        QTimer.singleShot(400, self._initial_sync)

    # ------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.setHandleWidth(1)
        self.splitter.setChildrenCollapsible(False)

        # 左：账号
        self.account_panel = AccountPanel()
        self.splitter.addWidget(self.account_panel)

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

        self.splitter.setSizes([228, 720, 420])
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
        bar.addWidget(self.status_text, 1)
        bar.addPermanentWidget(self.encryption_label)
        self.setStatusBar(bar)

        level = self.ctx.db.encryption_level if self.ctx.db else ""
        self.encryption_label.setText(f"🔒 {level}")

        self._build_menu()

    def _build_menu(self) -> None:
        menubar = self.menuBar()

        m_file = menubar.addMenu("文件")
        act_add = QAction("添加邮箱账号…", self)
        act_add.setShortcut("Ctrl+N")
        act_add.triggered.connect(self._on_add_account)
        m_file.addAction(act_add)

        act_sync = QAction("立即同步全部", self)
        act_sync.setShortcut("F5")
        act_sync.triggered.connect(lambda: self._sync_all())
        m_file.addAction(act_sync)

        m_file.addSeparator()
        act_pwd = QAction("修改主密码…", self)
        act_pwd.triggered.connect(self._on_change_password)
        m_file.addAction(act_pwd)

        act_recovery = QAction("导出恢复包…", self)
        act_recovery.triggered.connect(self._on_export_recovery)
        m_file.addAction(act_recovery)

        act_encrypt = QAction("数据库加密设置…", self)
        act_encrypt.triggered.connect(self._on_encryption_settings)
        m_file.addAction(act_encrypt)

        act_lock = QAction("立即锁定", self)
        act_lock.setShortcut("Ctrl+L")
        act_lock.triggered.connect(self._on_lock)
        m_file.addAction(act_lock)

        m_file.addSeparator()
        act_quit = QAction("退出", self)
        act_quit.setShortcut("Ctrl+Q")
        act_quit.triggered.connect(self.close)
        m_file.addAction(act_quit)

        m_view = menubar.addMenu("视图")
        act_refresh = QAction("刷新列表", self)
        act_refresh.triggered.connect(self.reload_mails)
        m_view.addAction(act_refresh)

        act_reset = QAction("重置筛选", self)
        act_reset.triggered.connect(self.filter_bar.reset)
        m_view.addAction(act_reset)

        m_help = menubar.addMenu("帮助")
        act_about = QAction("关于 UniMail", self)
        act_about.triggered.connect(self._on_about)
        m_help.addAction(act_about)

    def _install_shortcuts(self) -> None:
        for seq, slot in [
            (QKeySequence("Ctrl+R"), lambda: self._sync_all()),
            (QKeySequence("Ctrl+A"), lambda: self.account_panel.select_account(None)),
        ]:
            a = QAction(self)
            a.setShortcut(seq)
            a.triggered.connect(slot)
            self.addAction(a)

    # ------------------------------------------------------------ 接线
    def _wire_events(self) -> None:
        ap = self.account_panel
        ap.add_requested.connect(self._on_add_account)
        ap.remove_requested.connect(self._on_remove_account)
        ap.sync_requested.connect(self._on_sync_account)
        ap.mark_all_read_requested.connect(self._on_mark_all_read)
        ap.manage_requested.connect(self._on_manage_account)
        ap.account_selected.connect(self._on_account_selected)

        self.filter_bar.filter_changed.connect(self.reload_mails)
        self.filter_bar.refresh_requested.connect(lambda: self._sync_all())

        ip = self.inbox_panel
        ip.mail_selected.connect(self._on_mail_selected)
        ip.mark_read_requested.connect(self._on_mark_read)
        ip.star_requested.connect(self._on_star)
        ip.delete_requested.connect(self._on_delete_mail)

        self.detail_panel.attachment_requested.connect(self._on_download_attachment)

        bus = self.ctx.bus
        bus.accounts_changed.connect(self.refresh_accounts)
        bus.mail_updated.connect(self._on_mail_updated)
        bus.mail_deleted.connect(lambda _mid: self.reload_mails())
        bus.sync_started.connect(self._on_sync_started)
        bus.sync_finished.connect(self._on_sync_finished)
        bus.sync_error.connect(self._on_sync_error)
        bus.filter_changed.connect(self.reload_mails)
        bus.status_message.connect(lambda text, ms: self.statusBar()
                                   .showMessage(text, ms))

    # ------------------------------------------------------------ 启动
    def _initial_sync(self) -> None:
        """延迟阶段：启动调度器并按需发起首次网络同步。"""
        if self.ctx.scheduler:
            self.ctx.scheduler.start()
        if self.ctx.accounts and self.ctx.accounts.list():
            self._sync_all()
        else:
            self.set_status("欢迎使用 UniMail — 请先添加一个邮箱账号")

    # ------------------------------------------------------------ 账号
    def refresh_accounts(self) -> None:
        if not self.ctx.accounts or not self.ctx.mails:
            return
        accounts = self.ctx.accounts.list()
        counts = self.ctx.mails.counts()
        total = self.ctx.mails.total_counts()
        self.account_panel.set_accounts(accounts, counts, total)

    def _on_account_selected(self, account) -> None:
        if self.ctx.accounts:
            self.ctx.accounts.set_active(account.id if account else None)

    def _on_add_account(self) -> None:
        dlg = AddAccountDialog(self)
        if dlg.exec() != AddAccountDialog.Accepted or dlg.draft is None:
            return
        draft = dlg.draft

        if dlg.should_verify:
            self.set_status(f"正在验证 {draft.email} 的凭据…")
            ok, msg = self.ctx.accounts.verify(draft)
            if not ok:
                QMessageBox.warning(self, "连接失败",
                                    f"无法使用该凭据登录：\n\n{msg}")
                self.set_status("凭据验证失败")
                return
            self.set_status("凭据验证通过")

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
        self.ctx.accounts.remove(account_id)
        self.detail_panel.clear()
        self.refresh_accounts()
        self.reload_mails()
        self.set_status(f"已删除账号 {account.email}")

    def _on_manage_account(self, account_id: str) -> None:
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

    # ------------------------------------------------------------ 同步
    def _sync_all(self) -> None:
        if not self.ctx.scheduler:
            return
        n = self.ctx.scheduler.sync_now(None)
        self.set_status(f"已派发 {n} 个账号的同步任务" if n else "暂无需要同步的账号")

    def _on_sync_account(self, account_id: str) -> None:
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
        if new_count:
            self.set_status(f"{name}：新增 {new_count} 封邮件")
        else:
            self.set_status(f"{name}：已是最新")
        self.refresh_accounts()
        self.reload_mails()

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

    # ------------------------------------------------------------ 邮件
    def reload_mails(self) -> None:
        if not self.ctx.mails:
            return
        d_from, d_to = self.filter_bar.date_range()
        flt = MailFilter(
            account_id=self.ctx.accounts.active_id,
            platform=self.filter_bar.current_platform(),
            keyword=self.filter_bar.current_keyword(),
            date_from=d_from,
            date_to=d_to,
            unread_only=self.filter_bar.is_unread_only(),
        )
        mails = self.ctx.mails.inbox(flt)
        hint = None
        if not mails:
            if flt.keyword or flt.platform or flt.unread_only or flt.date_from:
                hint = "没有符合筛选条件的邮件，\n试试放宽条件或重置筛选。"
            elif not self.ctx.accounts.list():
                hint = "还没有绑定任何邮箱账号。\n点击左下角「添加邮箱账号」开始使用。"
        self.inbox_panel.set_mails(mails, hint)
        self.refresh_accounts()

    def _on_mail_selected(self, mail_id: str) -> None:
        mail = self.ctx.mails.get(mail_id)
        if mail is None:
            return

        # 正文尚未同步（列表只拉了头部）→ 后台补拉
        if (not mail.body_text and not mail.body_html
                and self.ctx.body_pool and self.ctx.body_pool.request(mail_id)):
            self.set_status("正在拉取邮件正文…")

        self.detail_panel.show_mail(mail)
        if not mail.is_read:
            self.ctx.mails.mark_read(mail_id, True)
            mail.is_read = True
            self.inbox_panel.refresh_row(mail.to_summary())
            self.refresh_accounts()

    def _on_mail_body_fetched(self, mail_id: str) -> None:
        """正文补拉完成 → 若当前正选中该邮件则刷新详情。"""
        if self.inbox_panel.current_mail_id() != mail_id:
            return
        mail = self.ctx.mails.get(mail_id)
        if mail:
            self.detail_panel.show_mail(mail)
            self.set_status("正文已加载")

    def _on_mark_read(self, mail_id: str, is_read: bool) -> None:
        self.ctx.mails.mark_read(mail_id, is_read)
        self.reload_mails()

    def _on_star(self, mail_id: str) -> None:
        self.ctx.mails.toggle_star(mail_id)
        mail = self.ctx.mails.get(mail_id)
        if mail:
            self.inbox_panel.refresh_row(mail.to_summary())
            if self.inbox_panel.current_mail_id() == mail_id:
                self.detail_panel.show_mail(mail)

    def _on_delete_mail(self, mail_id: str) -> None:
        self.ctx.mails.delete(mail_id)
        self.detail_panel.clear()
        self.reload_mails()
        self.set_status("已删除本地副本（服务器邮件不受影响）")

    def _on_mail_updated(self, mail_id: str) -> None:
        if self.ctx.mails:
            self.refresh_accounts()
        self._on_mail_body_fetched(mail_id)

    def _on_download_attachment(self, attachment_id: str) -> None:
        try:
            result = self.ctx.mails.download_attachment(attachment_id)
        except (FileNotFoundError, OSError, ValueError, SecurityError) as exc:
            QMessageBox.warning(self, "下载失败", str(exc))
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

    # ------------------------------------------------------------ 其他
    def _on_about(self) -> None:
        level = self.ctx.db.encryption_level if self.ctx.db else "未知"
        AboutDialog(level, self).exec()

    def _on_export_recovery(self) -> None:
        from PySide6.QtWidgets import QFileDialog
        default = str(self.ctx._sidecar.with_name("unimail-recovery.json"))  # noqa: SLF001
        path, _ = QFileDialog.getSaveFileName(
            self, "导出恢复包", default, "JSON 文件 (*.json)"
        )
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

        try:
            driver = self.ctx.migrate_encryption(target)
        except (SecurityError, OSError, RuntimeError) as exc:
            QMessageBox.warning(self, "迁移失败", f"数据库保持原状。\n\n{exc}")
            return

        level = self.ctx.db.encryption_level if self.ctx.db else driver
        self.encryption_label.setText(f"🔒 {level}")
        QMessageBox.information(self, "迁移完成", f"当前加密等级：{level}")

    def _on_change_password(self) -> None:
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

        try:
            result = self.ctx.change_password(old, new)
        except SecurityError as exc:
            QMessageBox.warning(self, "修改失败", str(exc))
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
        lines.append("\n请牢记新密码——遗忘将无法恢复任何数据。")
        QMessageBox.information(self, "主密码已更新", "\n".join(lines))
        self.set_status("主密码已更新，凭据已重新加密")

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

    def _on_lock(self) -> None:
        self.ctx.shutdown()
        QMessageBox.information(self, "已锁定", "数据已锁定，程序即将退出。\n"
                                               "下次启动需重新输入主密码。")
        self.close()

    def _check_auto_lock(self) -> None:
        if self.ctx.security.idle_seconds() >= AUTO_LOCK_SECONDS:
            log.info("空闲超时，自动锁定")
            self.ctx.shutdown()
            self.close()

    def set_status(self, text: str) -> None:
        self.status_text.setText(text)

    def closeEvent(self, event) -> None:
        try:
            self.ctx.shutdown()
        except Exception:
            log.exception("关闭时出错")
        event.accept()


def QLineEdit_EchoMode_Password():
    from PySide6.QtWidgets import QLineEdit
    return QLineEdit.Password

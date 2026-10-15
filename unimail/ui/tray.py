"""系统托盘常驻与桌面通知。

为什么需要托盘
--------------
邮件客户端是**常驻型**应用：它的价值很大一部分来自「后台收信 + 及时提醒」。
改造前关闭窗口就等于退出进程，调度器随之停止——用户必须让窗口一直开着
才能持续收信，而一个占满任务栏的邮箱窗口没人愿意一直摆着。

托盘提供三种行为：
* 关闭窗口 → 隐藏到托盘（调度器继续跑），可由设置关闭；
* 新邮件 → 系统通知（可关），点击通知直达主窗口；
* 右键菜单 → 显示主窗口 / 立即同步 / 退出。

通知的节流
----------
一次同步可能带回来几十封新邮件。逐封弹通知会直接刷爆通知中心，
反而让用户关掉通知权限。这里按「同一账号 N 秒内只弹一次」聚合，
正文里给出数量。
"""
from __future__ import annotations

import logging
import time

from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from ..config import APP_NAME
from . import icons

log = logging.getLogger(__name__)

# 同一账号的通知最小间隔（秒）。首次同步拉回几百封时，
# 这个值决定用户会不会被通知轰炸。
NOTIFY_THROTTLE_SECONDS = 20.0

MAX_NOTIFY_ITEMS = 3


class TrayIcon(QObject):
    """托盘图标 + 菜单 + 通知。"""

    show_requested = Signal()
    sync_requested = Signal()
    quit_requested = Signal()
    settings_requested = Signal()
    lock_requested = Signal()

    def __init__(self, parent=None, palette: dict | None = None) -> None:
        super().__init__(parent)
        self._last_notify: dict[str, float] = {}
        self._theme = dict(palette or {})
        self._pending: dict[str, list[str]] = {}

        self.icon = QSystemTrayIcon()
        self.icon.setToolTip(f"{APP_NAME} — 后台运行中")

        menu = QMenu()
        self.act_show = QAction("显示主窗口", menu)
        self.act_show.triggered.connect(self.show_requested.emit)
        menu.addAction(self.act_show)

        self.act_sync = QAction("立即同步全部", menu)
        self.act_sync.triggered.connect(self.sync_requested.emit)
        menu.addAction(self.act_sync)

        menu.addSeparator()
        self.act_lock = QAction("立即锁定", menu)
        self.act_lock.triggered.connect(self.lock_requested.emit)
        menu.addAction(self.act_lock)

        self.act_settings = QAction("设置…", menu)
        self.act_settings.triggered.connect(self.settings_requested.emit)
        menu.addAction(self.act_settings)

        menu.addSeparator()
        self.act_quit = QAction("退出", menu)
        self.act_quit.triggered.connect(self.quit_requested.emit)
        menu.addAction(self.act_quit)

        self._menu = menu
        self.icon.setContextMenu(menu)
        self.icon.activated.connect(self._on_activated)

        self.apply_theme(self._theme)

    # ------------------------------------------------------------ 主题
    def apply_theme(self, palette: dict) -> None:
        self._theme = dict(palette or {})
        color = self._theme.get("text", "#e6edf3")
        self.icon.setIcon(icons.icon("mailbox", color, 22))
        for act, name in ((self.act_show, "mail-open"), (self.act_sync, "refresh"),
                          (self.act_lock, "lock"), (self.act_settings, "settings"),
                          (self.act_quit, "close")):
            act.setIcon(icons.icon(name, self._theme.get("text_dim", "#8b98a9"), 14))

    # ------------------------------------------------------------ 可用性
    @staticmethod
    def available() -> bool:
        return QSystemTrayIcon.isSystemTrayAvailable()

    def show(self) -> None:
        if self.available():
            self.icon.show()

    def hide(self) -> None:
        self.icon.hide()

    def set_unread(self, unread: int, accounts: list[tuple[str, int]] | None = None) -> None:
        """把未读数写进 tooltip。

        刻意**不改图标**：切换图标会让托盘区域反复重绘，在 Windows 上
        表现为图标闪烁；而 tooltip 已经足够表达「有几封未读」。
        """
        if unread:
            detail = ""
            if accounts:
                top = sorted(accounts, key=lambda x: -x[1])[:3]
                detail = "\n" + "\n".join(f"{name}：{n} 未读" for name, n in top if n)
            self.icon.setToolTip(f"{APP_NAME} — {unread} 封未读{detail}")
        else:
            self.icon.setToolTip(f"{APP_NAME} — 后台运行中")

    # ------------------------------------------------------------ 通知
    def notify_new_mail(self, account_label: str, subjects: list[str],
                        account_id: str = "") -> bool:
        """新邮件通知（带节流）。返回是否真的弹了。"""
        if not self.available() or not self.icon.isVisible():
            return False
        key = account_id or account_label
        now = time.monotonic()
        last = self._last_notify.get(key, 0.0)
        if now - last < NOTIFY_THROTTLE_SECONDS:
            # 节流窗口内：只累积数量，不逐条弹
            self._pending.setdefault(key, []).extend(subjects)
            return False
        subjects = self._pending.pop(key, []) + list(subjects)
        self._last_notify[key] = now

        count = len(subjects)
        title = f"{account_label}：{count} 封新邮件" if count > 1 else f"{account_label}：新邮件"
        body = "\n".join(f"· {s}" for s in subjects[:MAX_NOTIFY_ITEMS] if s)
        if count > MAX_NOTIFY_ITEMS:
            body += f"\n… 以及另外 {count - MAX_NOTIFY_ITEMS} 封"
        # 邮件主题来自第三方，可能带 HTML；托盘通知按纯文本渲染，
        # 但仍要裁掉换行与超长内容，避免把通知区域撑开或伪装成多行标题。
        self.icon.showMessage(title, _sanitize(body, 220),
                              QSystemTrayIcon.Information, 6000)
        return True

    def notify(self, title: str, body: str) -> None:
        if self.available() and self.icon.isVisible():
            self.icon.showMessage(title, _sanitize(body, 220),
                                  QSystemTrayIcon.Information, 5000)

    # ------------------------------------------------------------ 事件
    def _on_activated(self, reason) -> None:
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.show_requested.emit()


def _sanitize(text: str, limit: int) -> str:
    flat = " ".join((text or "").split())
    return flat[:limit] + ("…" if len(flat) > limit else "")


__all__ = ["NOTIFY_THROTTLE_SECONDS", "TrayIcon"]

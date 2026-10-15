"""右侧栏：邮件详情（正文 + 内嵌图片 + 附件卡片）。

v1.5.0 / v1.6.0 的重构要点
=========================

**一、发件人头像。** 列表和详情用同一套「首字母 + 稳定底色」，让
「同一个人」在视觉上可辨认。此前详情页只有一行「发件人：张三 <...>」，
在几十封邮件之间来回对比时几乎没法定位。

**二、附件从列表变卡片。** `QListWidget` 只能显示一行文字，
「文件名 + 大小 + 类型 + 是否危险」挤在一起可读性很差。卡片可以把
「类型图标 / 文件名 / 大小」分三处呈现，并且直接给两个动作按钮
（预览、下载），不必再靠「双击才明白会发生什么」。

**三、内嵌图片与隐私。**
`cid:` 引用的图片在 MIME 里是附件，但渲染时会被正文 `<img src="cid:...">`
引用。默认**不加载**——它与远程图片在隐私上等价（发件人能看到你什么时候
打开了邮件）。详情面板在检测到「有 cid 但本地没有」时显示一个明确按钮，
由用户决定是否拉取；拉取后重绘正文。

`loadResource()` 仍然拒绝一切非本地来源：这是防跟踪像素唯一彻底的办法，
不管邮件里出现什么新奇的加载向量（`srcset`、`background:url()`、`poster`），
只要 QTextBrowser 想取资源就会走到这里。
"""
from __future__ import annotations

import logging

from PySide6.QtCore import QSize, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QImage, QPixmap
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedLayout,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from ..config import DANGEROUS_EXTENSIONS, platform_color, platform_name
from ..core.models import Attachment, Mail
from ..core.services import humanize_time
from . import icons
from .mail_model import avatar_color, initials

log = logging.getLogger(__name__)

IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg"}


def fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


def attachment_kind(filename: str, content_type: str) -> str:
    """给附件选一个图标名（决定卡片长什么样）。"""
    ctype = (content_type or "").lower()
    if ctype.startswith("image/"):
        return "image"
    if ctype.startswith("text/") or ctype in ("application/json", "application/xml"):
        return "file"
    name = (filename or "").lower()
    if any(name.endswith(s) for s in IMAGE_SUFFIXES):
        return "image"
    return "file"


class SafeTextBrowser(QTextBrowser):
    """阻断一切远程资源加载的正文视图。

    这是防跟踪像素/CSS 侧信道**唯一彻底**的办法：不管邮件里出现什么新奇的
    加载向量（`srcset`、`background:url()`、`poster`、未来新增的标签属性），
    只要 QTextBrowser 想取资源，就会走到 `loadResource()`，而这里一律拒绝。
    相比之下继续给正则打补丁永远只能覆盖已知写法。
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._resolver = None       # Callable[[str], bytes | None]
        self.blocked = 0            # 被拦下的资源数（供 UI 提示）
        self.resolved = 0

    def set_inline_resolver(self, resolver) -> None:
        self._resolver = resolver

    def loadResource(self, resource_type, url: QUrl | str):
        target = url.toString() if isinstance(url, QUrl) else str(url)
        scheme = target.split(":", 1)[0].lower() if ":" in target else ""
        if scheme == "cid":
            data = self._resolve_cid(target)
            if data:
                self.resolved += 1
                return data
            self.blocked += 1
            return b""
        if scheme in ("data",) or not scheme:
            # data: 只可能来自我们自己的内联内容（当前并不生成），保守放行空串
            return b""
        self.blocked += 1
        log.debug("已阻断正文中的远程资源请求：%s", target[:120])
        return b""

    def _resolve_cid(self, target: str) -> bytes | None:
        if self._resolver is None:
            return None
        cid = target[4:].strip().strip("<>")
        try:
            return self._resolver(cid)
        except Exception:
            log.debug("解析内嵌资源失败：%s", cid, exc_info=True)
            return None


def is_dangerous(filename: str | None) -> bool:
    """附件名是否落在这个项目列出的可执行扩展名里（UI 与卡片共用）。"""
    if not filename or "." not in filename:
        return False
    return filename.rsplit(".", 1)[-1].strip().lower() in DANGEROUS_EXTENSIONS


class AttachmentCard(QFrame):
    """一个附件的卡片：类型图标 + 文件名 + 大小 + 预览/下载。"""

    preview_requested = Signal(str)
    download_requested = Signal(str)

    def __init__(self, att: Attachment, parent=None) -> None:
        super().__init__(parent)
        self.att = att
        self.setObjectName("Card")
        self._theme: dict = {}

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(10)

        self.icon_label = QLabel()
        self.icon_label.setFixedSize(26, 26)
        self.icon_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.icon_label)

        col = QVBoxLayout()
        col.setSpacing(1)

        name = att.filename or "(未命名)"
        self.name_label = QLabel(name)
        self.name_label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.name_label.setToolTip(name)
        col.addWidget(self.name_label)

        meta = f"{fmt_size(att.size)} · {(att.content_type or '').split(';')[0]}"
        self.meta_label = QLabel(meta)
        self.meta_label.setObjectName("Hint")
        col.addWidget(self.meta_label)
        layout.addLayout(col, 1)

        self.preview_btn = QPushButton("预览")
        self.preview_btn.setObjectName("Ghost")
        self.preview_btn.setFixedHeight(26)
        self.preview_btn.clicked.connect(lambda: self.preview_requested.emit(att.id))
        layout.addWidget(self.preview_btn)

        self.download_btn = QPushButton("下载")
        self.download_btn.setObjectName("Ghost")
        self.download_btn.setFixedHeight(26)
        self.download_btn.clicked.connect(lambda: self.download_requested.emit(att.id))
        layout.addWidget(self.download_btn)

        self.risky = self._is_dangerous(att.filename)
        if self.risky:
            self.meta_label.setObjectName("Danger")
            self.meta_label.setText(f"{meta} · ⚠️ 可执行类型，下载后保留 .download")

    def apply_theme(self, palette: dict) -> None:
        self._theme = dict(palette)
        kind = attachment_kind(self.att.filename, self.att.content_type)
        color = (palette.get("warning", "#d29922") if self.risky
                 else palette.get("text_dim", "#8b98a9"))
        self.icon_label.setPixmap(icons.pixmap(kind, color, 22))
        self.preview_btn.setIcon(icons.icon("search", color, 13))
        self.download_btn.setIcon(
            icons.icon("download", palette.get("accent", "#4c8dff"), 13))

    @staticmethod
    def _is_dangerous(filename: str | None) -> bool:
        return is_dangerous(filename)


class ImagePreviewDialog(QDialog):
    """图片灯箱：可缩放、可另存。"""

    def __init__(self, title: str, image: QImage, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title or "预览")
        self._source = QPixmap.fromImage(image)
        self.resize(820, 620)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        self.view = QLabel()
        self.view.setAlignment(Qt.AlignCenter)
        self.view.setMinimumSize(200, 160)
        self.view.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Ignored)

        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setWidget(self.view)
        area.setAlignment(Qt.AlignCenter)
        layout.addWidget(area, 1)

        row = QHBoxLayout()
        self.info = QLabel(f"{self._source.width()} × {self._source.height()}")
        self.info.setObjectName("Hint")
        row.addWidget(self.info)
        row.addStretch(1)

        fit = QPushButton("适应窗口")
        fit.setObjectName("Ghost")
        fit.clicked.connect(self._render)
        row.addWidget(fit)

        actual = QPushButton("原始大小")
        actual.setObjectName("Ghost")
        actual.clicked.connect(self._render_actual)
        row.addWidget(actual)

        close = QPushButton("关闭")
        close.setObjectName("Primary")
        close.clicked.connect(self.accept)
        row.addWidget(close)
        layout.addLayout(row)

        self._fit = True
        self._render()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self._fit:
            self._render()

    def _render(self) -> None:
        self._fit = True
        area = self.view.parentWidget()
        size = QSize(max(100, area.width() - 20), max(80, area.height() - 20))
        self.view.setPixmap(self._source.scaled(size, Qt.KeepAspectRatio,
                                                Qt.SmoothTransformation))

    def _render_actual(self) -> None:
        self._fit = False
        self.view.setPixmap(self._source)


class DetailPanel(QFrame):
    """显示选中邮件的完整内容。"""

    attachment_requested = Signal(str)         # attachment_id（下载）
    preview_requested = Signal(str)            # attachment_id（内联预览）
    inline_download_requested = Signal(str)    # mail_id（拉取 cid 内嵌图）
    export_requested = Signal(str)             # mail_id
    star_requested = Signal(str)               # mail_id
    open_external_requested = Signal(str)      # url

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("DetailPane")
        self.setMinimumWidth(340)
        self._mail: Mail | None = None
        self._theme: dict = {}
        # 由主窗口按设置注入：是否在打开邮件时自动拉取内嵌图片。
        # 默认 False —— 自动加载内嵌图片等于自动加载远程内容。
        self.auto_inline = False
        # 由主窗口注入：`resolver(mail_id, content_id) -> bytes|None`
        self.inline_resolver = None
        # 由主窗口注入：`inline_missing(mail_id) -> list[Attachment]`
        self.inline_missing = None

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        self.stack = QStackedLayout()
        root.addLayout(self.stack, 1)

        self.stack.addWidget(self._build_empty())
        self.stack.addWidget(self._build_detail())
        self.stack.setCurrentIndex(0)

    # ------------------------------------------------------------ 构建
    def _build_empty(self) -> QWidget:
        empty = QWidget()
        layout = QVBoxLayout(empty)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(8)
        t = QLabel("未选择邮件")
        t.setObjectName("EmptyTitle")
        t.setAlignment(Qt.AlignCenter)
        h = QLabel("从列表中选择一封邮件查看详情")
        h.setObjectName("EmptyHint")
        h.setAlignment(Qt.AlignCenter)
        layout.addWidget(t)
        layout.addWidget(h)
        return empty

    def _build_detail(self) -> QWidget:
        detail = QWidget()
        dl = QVBoxLayout(detail)
        dl.setContentsMargins(18, 16, 18, 12)
        dl.setSpacing(10)

        # ---- 表头
        head = QHBoxLayout()
        head.setSpacing(12)
        self.avatar = QLabel()
        self.avatar.setObjectName("Avatar")
        self.avatar.setFixedSize(38, 38)
        self.avatar.setAlignment(Qt.AlignCenter)
        head.addWidget(self.avatar)

        col = QVBoxLayout()
        col.setSpacing(2)
        self.sender_label = QLabel("")
        self.sender_label.setTextFormat(Qt.RichText)
        self.sender_label.setWordWrap(True)
        col.addWidget(self.sender_label)
        self.recipient_label = QLabel("")
        self.recipient_label.setObjectName("DetailMeta")
        self.recipient_label.setWordWrap(True)
        col.addWidget(self.recipient_label)
        head.addLayout(col, 1)

        self.time_label = QLabel("")
        self.time_label.setObjectName("DetailMeta")
        self.time_label.setAlignment(Qt.AlignRight | Qt.AlignTop)
        head.addWidget(self.time_label)
        dl.addLayout(head)

        self.subject = QLabel("")
        self.subject.setObjectName("DetailSubject")
        self.subject.setWordWrap(True)
        self.subject.setTextInteractionFlags(Qt.TextSelectableByMouse)
        dl.addWidget(self.subject)

        self.chips = QLabel("")
        dl.addWidget(self.chips)

        # ---- 动作行
        actions = QHBoxLayout()
        actions.setSpacing(6)
        self.btn_star = QPushButton("星标")
        self.btn_star.setObjectName("Ghost")
        self.btn_star.clicked.connect(self._toggle_star)
        actions.addWidget(self.btn_star)

        self.btn_export = QPushButton("导出 .eml")
        self.btn_export.setObjectName("Ghost")
        self.btn_export.clicked.connect(
            lambda: self.export_requested.emit(self._mail.id if self._mail else ""))
        actions.addWidget(self.btn_export)

        self.btn_inline = QPushButton("加载内嵌图片")
        self.btn_inline.setObjectName("Ghost")
        self.btn_inline.clicked.connect(self._request_inline)
        self.btn_inline.hide()
        actions.addWidget(self.btn_inline)

        actions.addStretch(1)
        dl.addLayout(actions)

        dl.addWidget(_divider())

        # ---- 正文
        self.body = SafeTextBrowser()
        # 邮件正文里的链接一律不自动打开：先弹确认框并显示**完整真实 URL**，
        # 用户确认后才交给系统浏览器（此前 setOpenExternalLinks(True) 等于
        # 把「点一下就打开」交给邮件作者的显示文本去欺骗）。
        self.body.setOpenExternalLinks(False)
        self.body.setOpenLinks(False)
        self.body.anchorClicked.connect(self._on_anchor_clicked)
        dl.addWidget(self.body, 1)

        # ---- 附件
        self.attach_title = QLabel("附件")
        self.attach_title.setObjectName("SectionTitle")
        dl.addWidget(self.attach_title)

        self.attach_area = QScrollArea()
        self.attach_area.setWidgetResizable(True)
        self.attach_area.setFrameShape(QFrame.NoFrame)
        self.attach_area.setMaximumHeight(190)
        holder = QWidget()
        self.attach_grid = QGridLayout(holder)
        self.attach_grid.setContentsMargins(0, 0, 0, 0)
        self.attach_grid.setSpacing(6)
        self.attach_area.setWidget(holder)
        dl.addWidget(self.attach_area)

        self.attach_hint = QLabel("")
        self.attach_hint.setObjectName("Hint")
        self.attach_hint.setWordWrap(True)
        dl.addWidget(self.attach_hint)

        for w in (self.attach_title, self.attach_area, self.attach_hint):
            w.hide()
        return detail

    # ------------------------------------------------------------ 主题
    def apply_theme(self, palette: dict) -> None:
        self._theme = dict(palette)
        if self._mail is not None:
            self.show_mail(self._mail)

    # ------------------------------------------------------------ 渲染
    def _wipe(self) -> None:
        """把面板上所有与邮件内容有关的控件清空（锁屏、退出时调用）。"""
        self._mail = None
        self.subject.clear()
        self.sender_label.clear()
        self.recipient_label.clear()
        self.time_label.clear()
        self.chips.clear()
        self.body.clear()
        self.body.set_inline_resolver(None)
        self.body.blocked = 0
        self.body.resolved = 0
        self.avatar.clear()
        self.avatar.setStyleSheet("")
        self.btn_inline.hide()
        self.attach_hint.clear()
        self._clear_attachments()
        for w in (self.attach_title, self.attach_area, self.attach_hint):
            w.hide()

    def show_mail(self, mail: Mail | None) -> None:
        self._mail = mail
        if mail is None:
            # 锁屏 / 退出时调用。不能只切回空态页：QLabel 与浏览器控件里
            # 上一封的主题、发件人、正文仍留在控件与 DWM 缩略图缓存里，
            # 「遮住了但数据还在」不是真的收起来。
            self._wipe()
            self.stack.setCurrentIndex(0)
            return
        self.stack.setCurrentIndex(1)

        self.subject.setText(mail.subject or "(无主题)")

        name = mail.sender_display
        self.avatar.setText(initials(name))
        color = avatar_color(mail.from_addr or name)
        self.avatar.setStyleSheet(
            f"background:{color};border-radius:19px;color:#ffffff;"
            f"font-size:16px;font-weight:600;")

        self.sender_label.setText(
            f"<b>{_esc(name)}</b> &nbsp;<span style='color:"
            f"{self._theme.get('text_faint', '#5d6b7d')}'>&lt;{_esc(mail.from_addr)}&gt;</span>"
        )
        to_line = ", ".join(mail.to_addrs[:4]) if mail.to_addrs else "-"
        extra = f" 等 {len(mail.to_addrs)} 人" if len(mail.to_addrs) > 4 else ""
        self.recipient_label.setText(f"收件人：{to_line}{extra}")

        when = mail.date.astimezone().strftime("%Y-%m-%d %H:%M") if mail.date else "-"
        self.time_label.setText(f"{when}<br>{humanize_time(mail.date)}")

        self.chips.setText(self._chips_html(mail))
        self.btn_star.setText("取消星标" if mail.is_starred else "星标")

        self._render_body(mail)
        self._render_attachments(mail)

    def _chips_html(self, mail: Mail) -> str:
        p = self._theme
        color = platform_color(mail.platform)
        parts = [
            f"<span style='color:{color}'>● {_esc(platform_name(mail.platform))}</span>"
        ]
        if mail.is_starred:
            parts.append(f"<span style='color:{p.get('warning', '#d29922')}'>★ 已星标</span>")
        if mail.folder and mail.folder.upper() != "INBOX":
            parts.append(f"<span>{_esc(mail.folder)}</span>")
        if mail.raw_size:
            parts.append(f"<span>{fmt_size(mail.raw_size)}</span>")
        sep = f" &nbsp;<span style='color:{p.get('border', '#2a3242')}'>|</span>&nbsp; "
        return sep.join(parts)

    def _render_body(self, mail: Mail) -> None:
        self.body.set_inline_resolver(self._resolver)
        self.body.blocked = 0
        self.body.resolved = 0
        if mail.body_html:
            self.body.setHtml(self._wrap_html(mail.body_html))
        else:
            self.body.setPlainText(mail.body_text or "（无正文内容，可能尚未同步）")

        # 内嵌图片：只提示「有但没缓存」，是否拉取交给用户
        missing = self._inline_missing(mail.id)
        if missing and self.auto_inline:
            self._request_inline()
        elif missing:
            self.btn_inline.setText(f"加载内嵌图片（{len(missing)}）")
            self.btn_inline.show()
        else:
            self.btn_inline.hide()

    def _render_attachments(self, mail: Mail) -> None:
        self._clear_attachments()

        visible = [a for a in mail.attachments if not a.content_id]
        if not visible:
            for w in (self.attach_title, self.attach_area, self.attach_hint):
                w.hide()
            return

        for i, att in enumerate(visible):
            card = AttachmentCard(att, self)
            if self._theme:
                card.apply_theme(self._theme)
            card.preview_requested.connect(self.preview_requested.emit)
            card.download_requested.connect(self.attachment_requested.emit)
            self.attach_grid.addWidget(card, i, 0)

        risky = sum(1 for a in visible if is_dangerous(a.filename))
        if risky:
            self.attach_hint.setObjectName("Danger")
            self.attach_hint.setText(
                f"⚠️ {risky} 个附件属于可执行类型：下载后保留 .download 后缀，"
                "不会自动变成可运行文件。")
        else:
            self.attach_hint.setObjectName("Hint")
            self.attach_hint.setText(f"共 {len(visible)} 个附件")
        self.attach_title.setText(f"附件（{len(visible)}）")
        for w in (self.attach_title, self.attach_area, self.attach_hint):
            w.show()

    def _clear_attachments(self) -> None:
        while self.attach_grid.count():
            item = self.attach_grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _resolver(self, content_id: str) -> bytes | None:
        if self.inline_resolver is None or self._mail is None:
            return None
        return self.inline_resolver(self._mail.id, content_id)

    def _inline_missing(self, mail_id: str) -> list[Attachment]:
        if self.inline_missing is None:
            return []
        try:
            return self.inline_missing(mail_id)
        except Exception:
            log.debug("查询内嵌图片失败", exc_info=True)
            return []

    def _request_inline(self) -> None:
        if self._mail is not None:
            self.inline_download_requested.emit(self._mail.id)

    def _toggle_star(self) -> None:
        if self._mail is not None:
            self.star_requested.emit(self._mail.id)

    def clear(self) -> None:
        self.show_mail(None)

    # ------------------------------------------------------------ 预览
    def show_preview(self, kind: str, payload, title: str = "") -> None:
        """在面板内呈现预览结果（由主窗口在服务层取到数据后调用）。"""
        if kind == "image":
            image = QImage()
            if not image.loadFromData(payload):
                QMessageBox.warning(self, "无法预览", "该图片格式无法解析。")
                return
            ImagePreviewDialog(title, image, self).exec()
        elif kind == "text":
            dialog = QDialog(self)
            dialog.setWindowTitle(title or "预览")
            dialog.resize(720, 560)
            layout = QVBoxLayout(dialog)
            view = QTextBrowser()
            view.setPlainText(str(payload))
            layout.addWidget(view)
            row = QHBoxLayout()
            row.addStretch(1)
            close = QPushButton("关闭")
            close.setObjectName("Primary")
            close.clicked.connect(dialog.accept)
            row.addWidget(close)
            layout.addLayout(row)
            dialog.exec()
        else:
            QMessageBox.information(
                self, "无法内联预览",
                "该类型的附件不支持内嵌预览（例如 PDF / 压缩包 / 文档）。\n"
                "请先下载到本地，再用系统默认程序打开。",
            )

    def notify_inline_blocked(self) -> None:
        if self.body.blocked:
            self.body.setPlainText(
                (self.body.toPlainText() or "")
                + f"\n\n[已拦截 {self.body.blocked} 个远程资源请求]"
            )

    # ------------------------------------------------------------ 交互
    def _on_anchor_clicked(self, url: QUrl) -> None:
        """外链二次确认：显示完整真实 URL，而不是邮件里可任意伪造的显示文本。"""
        target = url.toString()
        scheme = target.split(":", 1)[0].lower() if ":" in target else ""
        if scheme not in ("http", "https", "mailto"):
            QMessageBox.warning(
                self, "已阻止",
                f"该链接使用的协议（{scheme or '未知'}）不被允许打开。\n\n{target[:300]}",
            )
            return
        ret = QMessageBox.question(
            self, "打开外部链接",
            "即将用系统默认程序打开下面的地址。\n"
            "请确认它与邮件里显示的文本一致（钓鱼链接常用不同文字掩盖真实地址）：\n\n"
            f"{target[:500]}\n\n是否继续？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if ret == QMessageBox.Yes:
            QDesktopServices.openUrl(QUrl(target))
            self.open_external_requested.emit(target)

    def _wrap_html(self, html: str) -> str:
        p = self._theme
        return (
            "<style>"
            f"body{{color:{p.get('text', '#e6edf3')};font-size:14px;line-height:1.7;"
            "margin:0;padding:0;word-wrap:break-word;}"
            f"a{{color:{p.get('accent', '#4c8dff')};}}"
            f"blockquote{{border-left:3px solid {p.get('border', '#2a3242')};"
            f"margin-left:0;padding-left:12px;color:{p.get('text_dim', '#8b98a9')};}}"
            "table{border-collapse:collapse;max-width:100%;}"
            "td,th{padding:4px 8px;}"
            "img{max-width:100%;height:auto;}"
            "pre,code{white-space:pre-wrap;word-break:break-all;"
            f"background:{p.get('bg_elev', '#1c2230')};border-radius:4px;padding:2px 4px;}}"
            f"hr{{border:none;border-top:1px solid {p.get('border', '#2a3242')};}}"
            "</style>" + html
        )


def _divider() -> QFrame:
    line = QFrame()
    line.setObjectName("Divider")
    line.setFrameShape(QFrame.HLine)
    line.setFixedHeight(1)
    return line


def _esc(text: str | None) -> str:
    import html
    return html.escape(str(text or ""))


__all__ = [
    "AttachmentCard",
    "DetailPanel",
    "ImagePreviewDialog",
    "SafeTextBrowser",
    "attachment_kind",
    "fmt_size",
]

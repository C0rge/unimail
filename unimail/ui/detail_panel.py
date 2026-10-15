"""右侧栏：邮件详情（正文 + 附件）。"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedLayout,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from ..config import platform_color, platform_name
from ..core.models import Mail
from ..core.services import humanize_time


def fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


class DetailPanel(QFrame):
    """显示选中邮件的完整内容。"""

    attachment_requested = Signal(str)   # attachment_id
    open_external_requested = Signal(str)  # url (占位)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("DetailPane")
        self.setMinimumWidth(340)
        self._mail: Mail | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.stack = QStackedLayout()
        root.addLayout(self.stack, 1)

        # 空状态
        empty = QWidget()
        el = QVBoxLayout(empty)
        el.setAlignment(Qt.AlignCenter)
        el.setSpacing(8)
        t = QLabel("未选择邮件")
        t.setObjectName("EmptyTitle")
        t.setAlignment(Qt.AlignCenter)
        h = QLabel("从左侧列表中选择一封邮件查看详情")
        h.setObjectName("EmptyHint")
        h.setAlignment(Qt.AlignCenter)
        el.addWidget(t)
        el.addWidget(h)
        self.stack.addWidget(empty)

        # 详情
        detail = QWidget()
        dl = QVBoxLayout(detail)
        dl.setContentsMargins(18, 16, 18, 12)
        dl.setSpacing(10)

        self.subject = QLabel("")
        self.subject.setObjectName("DetailSubject")
        self.subject.setWordWrap(True)
        dl.addWidget(self.subject)

        self.meta = QLabel("")
        self.meta.setObjectName("DetailMeta")
        self.meta.setWordWrap(True)
        dl.addWidget(self.meta)

        self.tags = QLabel("")
        self.tags.setObjectName("Badge")
        self.tags.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
        dl.addWidget(self.tags, 0, Qt.AlignLeft)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("color: #2a3242;")
        dl.addWidget(sep)

        self.body = QTextBrowser()
        self.body.setOpenExternalLinks(True)
        self.body.setOpenLinks(True)
        dl.addWidget(self.body, 1)

        # 附件区
        self.attach_title = QLabel("附件")
        self.attach_title.setObjectName("SectionTitle")
        dl.addWidget(self.attach_title)

        self.attach_list = QListWidget()
        self.attach_list.setMaximumHeight(132)
        self.attach_list.itemDoubleClicked.connect(self._on_attach_activated)
        dl.addWidget(self.attach_list)

        self.attach_hint = QLabel("双击附件可下载到本地附件目录")
        self.attach_hint.setObjectName("Hint")
        dl.addWidget(self.attach_hint)

        self.attach_title.hide()
        self.attach_list.hide()
        self.attach_hint.hide()

        self.stack.addWidget(detail)
        self.stack.setCurrentIndex(0)

    # ------------------------------------------------------------ 渲染
    def show_mail(self, mail: Mail | None) -> None:
        self._mail = mail
        if mail is None:
            self.stack.setCurrentIndex(0)
            return
        self.stack.setCurrentIndex(1)

        self.subject.setText(mail.subject or "(无主题)")

        when = mail.date.astimezone().strftime("%Y-%m-%d %H:%M") if mail.date else "-"
        to_line = ", ".join(mail.to_addrs[:3]) if mail.to_addrs else "-"
        self.meta.setText(
            f"<b>发件人：</b>{mail.sender_display} &lt;{mail.from_addr}&gt;<br>"
            f"<b>收件人：</b>{to_line}<br>"
            f"<b>时间：</b>{when} &nbsp;·&nbsp; {humanize_time(mail.date)}"
        )

        color = platform_color(mail.platform)
        badge = f"<span style='color:{color}'>● {platform_name(mail.platform)}</span>"
        if mail.is_starred:
            badge += " &nbsp;★ 已星标"
        if mail.has_attachments:
            badge += " &nbsp;📎 含附件"
        self.tags.setText(badge)

        if mail.body_html:
            self.body.setHtml(self._wrap_html(mail.body_html))
        else:
            self.body.setPlainText(mail.body_text or "（无正文内容，可能尚未同步）")

        # 附件
        if mail.attachments:
            self.attach_title.show()
            self.attach_list.show()
            self.attach_hint.show()
            self.attach_list.clear()
            for att in mail.attachments:
                item = QListWidgetItem(
                    f"📎  {att.filename}    ({fmt_size(att.size)})"
                )
                item.setData(Qt.UserRole, att.id)
                item.setToolTip(f"{att.content_type}\n{fmt_size(att.size)}")
                self.attach_list.addItem(item)
        else:
            self.attach_title.hide()
            self.attach_list.hide()
            self.attach_hint.hide()

    def clear(self) -> None:
        self.show_mail(None)

    @staticmethod
    def _wrap_html(html: str) -> str:
        return (
            "<style>"
            "body{color:#e6edf3;font-size:14px;line-height:1.65;}"
            "a{color:#4c8dff;}"
            "blockquote{border-left:3px solid #2a3242;margin-left:0;padding-left:12px;color:#8b98a9;}"
            "table{border-collapse:collapse;}"
            "td,th{padding:4px 8px;}"
            "img{max-width:100%;}"
            "</style>" + html
        )

    def _on_attach_activated(self, item: QListWidgetItem) -> None:
        att_id = item.data(Qt.UserRole)
        if att_id:
            self.attachment_requested.emit(att_id)

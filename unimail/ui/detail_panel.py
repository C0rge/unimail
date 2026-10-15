"""右侧栏：邮件详情（正文 + 附件）。"""
from __future__ import annotations

import logging

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QSizePolicy,
    QStackedLayout,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from ..config import DANGEROUS_EXTENSIONS, platform_color, platform_name
from ..core.models import Mail
from ..core.services import humanize_time

log = logging.getLogger(__name__)


def fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


class SafeTextBrowser(QTextBrowser):
    """阻断一切远程资源加载的正文视图。

    这是防跟踪像素/CSS 侧信道**唯一彻底**的办法：不管邮件里出现什么新奇的
    加载向量（`srcset`、`background:url()`、`poster`、未来新增的标签属性），
    只要 QTextBrowser 想取资源，就会走到 `loadResource()`，而这里一律拒绝。
    相比之下继续给正则打补丁永远只能覆盖已知写法。
    """

    def loadResource(self, resource_type, url: QUrl | str):
        target = url.toString() if isinstance(url, QUrl) else str(url)
        scheme = target.split(":", 1)[0].lower() if ":" in target else ""
        if scheme in ("data",) or not scheme:
            # data: 只可能来自我们自己的内联内容（当前并不生成），保守放行空串
            return b""
        log.debug("已阻断正文中的远程资源请求：%s", target[:120])
        return b""


class DetailPanel(QFrame):
    """显示选中邮件的完整内容。"""

    attachment_requested = Signal(str)   # attachment_id
    open_external_requested = Signal(str)  # url

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

        self.body = SafeTextBrowser()
        # 邮件正文里的链接一律不自动打开：先弹确认框并显示**完整真实 URL**，
        # 用户确认后才交给系统浏览器（此前 setOpenExternalLinks(True) 等于
        # 把「点一下就打开」交给邮件作者的显示文本去欺骗）。
        self.body.setOpenExternalLinks(False)
        self.body.setOpenLinks(False)
        self.body.anchorClicked.connect(self._on_anchor_clicked)
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
            risky = 0
            for att in mail.attachments:
                dangerous = self._is_dangerous(att.filename)
                risky += 1 if dangerous else 0
                prefix = "⚠️ " if dangerous else "📎  "
                item = QListWidgetItem(f"{prefix}{att.filename}    ({fmt_size(att.size)})")
                item.setData(Qt.UserRole, att.id)
                tip = f"{att.content_type}\n{fmt_size(att.size)}"
                if dangerous:
                    tip += ("\n\n⚠️ 该类型可能包含可执行代码。\n"
                            "下载后会保存为 .download 后缀，不会自动变成可运行文件。")
                item.setToolTip(tip)
                self.attach_list.addItem(item)
            if risky:
                self.attach_hint.setText(
                    f"⚠️ 有 {risky} 个可执行类型附件：下载后保存为 .download，"
                    "不会自动还原为可运行后缀"
                )
            else:
                self.attach_hint.setText("双击附件可下载到本地附件目录")
        else:
            self.attach_title.hide()
            self.attach_list.hide()
            self.attach_hint.hide()

    @staticmethod
    def _is_dangerous(filename: str | None) -> bool:
        if not filename or "." not in filename:
            return False
        return filename.rsplit(".", 1)[-1].strip().lower() in DANGEROUS_EXTENSIONS

    def clear(self) -> None:
        self.show_mail(None)

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
        if not att_id:
            return
        name = item.text()
        if name.startswith("⚠️"):
            ret = QMessageBox.warning(
                self, "可疑附件",
                f"{name.split('    ')[0]}\n\n"
                "该附件类型可能包含可执行代码。\n"
                "下载后会被保存为 .download 后缀，不会自动变成可运行文件。\n\n"
                "确定要继续下载吗？",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            )
            if ret != QMessageBox.Yes:
                return
        self.attachment_requested.emit(att_id)

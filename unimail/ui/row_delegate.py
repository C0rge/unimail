"""收件箱行绘制委托：头像、未读点、星标、附件、会话折叠箭头 + 命中高亮。

为什么把绘制集中在一个委托里
----------------------------
改造前「未读」靠 ForegroundRole 换个颜色，「有附件」只在 tooltip 里说，
星标在列表里完全不可见——用户必须点开每一封才知道有没有附件、自己标没标星。
把这些信息补到行上需要一个能自由布局的绘制器，而不是继续加 role。

委托只做「画」，不做「判定」：所有语义（是否星标、是否附件、展开与否）
都由模型通过自定义 role 给出，因此同一份委托在列表视图和会话视图里
表现完全一致——会话视图不需要任何额外分支。
"""
from __future__ import annotations

import contextlib

from PySide6.QtCore import QPointF, QRectF, QSize, Qt
from PySide6.QtGui import QColor, QFont, QFontMetrics, QPainter, QTextDocument
from PySide6.QtWidgets import QStyle, QStyledItemDelegate, QStyleOptionViewItem

from . import icons
from .mail_model import (
    CHILD_ROW_HEIGHT,
    COL_PLATFORM,
    COL_SENDER,
    COL_SUBJECT,
    COL_TIME,
    COL_UNREAD,
    DEFAULT_ROW_HEIGHT,
    ROLE_AVATAR,
    ROLE_AVATAR_COLOR,
    ROLE_DEPTH,
    ROLE_EXPANDED,
    ROLE_HAS_ATTACH,
    ROLE_IS_THREAD,
    ROLE_KEYWORD,
    ROLE_SENDER,
    ROLE_STARRED,
    ROLE_SUBJECT,
    ROLE_THREAD_TOTAL,
    highlight_html,
)

AVATAR_SIZE = 26
AVATAR_SIZE_CHILD = 20


class MailRowDelegate(QStyledItemDelegate):
    """统一的收件箱行绘制。"""

    def __init__(self, parent=None, palette: dict | None = None) -> None:
        super().__init__(parent)
        self.pal = dict(palette or {})
        self.keyword = ""

    # ------------------------------------------------------------ 配置
    def set_palette(self, palette: dict) -> None:
        """换色。重绘由视图负责——委托的 parent 不一定是视图，
        在这里猜一个 `viewport()` 会在 parent 是容器时直接抛错。"""
        self.pal = dict(palette)

    def set_keyword(self, keyword: str) -> None:
        self.keyword = keyword or ""

    def color(self, token: str, fallback: str = "#e6edf3") -> QColor:
        return QColor(self.pal.get(token, fallback))

    # ------------------------------------------------------------ 绘制
    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index) -> None:
        # 先让样式引擎画好行背景（悬停/选中/交替色），再在其上自绘内容。
        # 这一步不能省：自己填背景会丢掉 QSS 里的 border-bottom 与悬停态。
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        opt.text = ""
        widget = option.widget
        style = widget.style() if widget is not None else None
        if style is not None:
            style.drawControl(QStyle.CE_ItemViewItem, opt, painter, widget)

        painter.save()
        painter.setRenderHint(QPainter.Antialiasing, True)
        try:
            col = index.column()
            if col == COL_UNREAD:
                self._paint_marker(painter, option, index)
            elif col == COL_SENDER:
                self._paint_sender(painter, option, index)
            elif col == COL_SUBJECT:
                self._paint_subject(painter, option, index)
            elif col in (COL_PLATFORM, COL_TIME):
                self._paint_text(painter, option, index)
        finally:
            painter.restore()

    # -------------------------------------------------- 未读点 / 星标
    def _paint_marker(self, painter, option, index) -> None:
        rect = option.rect
        starred = index.data(ROLE_STARRED)
        if starred:
            pm = icons.pixmap("star-filled", self.pal.get("warning", "#d29922"), 14,
                              _dpr(option))
            painter.drawPixmap(
                int(rect.center().x() - 7), int(rect.center().y() - 7), pm)
            return

        is_read = True
        mail = None
        model = index.model()
        if hasattr(model, "mail_at"):
            mail = model.mail_at(index.row())
        if mail is not None:
            is_read = bool(mail.is_read)

        painter.setPen(Qt.NoPen)
        if not is_read:
            painter.setBrush(self.color("unread", "#4c8dff"))
            painter.drawEllipse(QPointF(rect.center()), 3.4, 3.4)
        else:
            # 已读且未星标：留一个几乎不可见的占位点，让整列宽度稳定
            painter.setBrush(self.color("border", "#2a3242"))
            painter.drawEllipse(QPointF(rect.center()), 1.4, 1.4)

    # -------------------------------------------------- 发件人（头像）
    def _paint_sender(self, painter, option, index) -> None:
        rect = option.rect
        depth = index.data(ROLE_DEPTH) or 0
        indent = 22 if depth else 0
        size = AVATAR_SIZE_CHILD if depth else AVATAR_SIZE
        cy = rect.center().y()

        avatar_rect = QRectF(rect.left() + 6 + indent, cy - size / 2, size, size)
        bg = QColor(index.data(ROLE_AVATAR_COLOR) or self.pal.get("accent", "#4c8dff"))
        if not bg.isValid():
            bg = self.color("accent")
        painter.setPen(Qt.NoPen)
        painter.setBrush(bg)
        painter.drawEllipse(avatar_rect)

        letters = index.data(ROLE_AVATAR) or "?"
        font = QFont(option.font)
        font.setPointSizeF(max(7.0, size * 0.42))
        font.setBold(True)
        painter.setFont(font)
        painter.setPen(QColor("#ffffff"))
        painter.drawText(avatar_rect, Qt.AlignCenter, letters)

        # 文本区：关键字命中时走富文本
        text_rect = QRectF(avatar_rect.right() + 8, rect.top(),
                           max(10.0, rect.right() - avatar_rect.right() - 12),
                           rect.height())
        text = index.data(ROLE_SENDER) or ""
        font2 = QFont(option.font)
        bold = index.data(Qt.FontRole)
        if isinstance(bold, QFont):
            font2.setBold(bold.bold())
        self._draw_maybe_rich(painter, text_rect, text, index, font2,
                              self.color("text" if not index.data(ROLE_DEPTH)
                                         else "text_dim"))

    # -------------------------------------------------- 主题（+ 附件/箭头）
    def _paint_subject(self, painter, option, index) -> None:
        rect = option.rect
        left = rect.left() + 6
        right = rect.right() - 6

        is_thread = bool(index.data(ROLE_IS_THREAD))
        total = index.data(ROLE_THREAD_TOTAL) or 1
        chevron_w = 0.0
        if is_thread and total > 1:
            chevron_w = 14.0
            icon_name = ("chevron-down" if index.data(ROLE_EXPANDED)
                         else "chevron-right")
            pm = icons.pixmap(icon_name, self.pal.get("text_dim", "#8b98a9"), 14,
                              _dpr(option))
            painter.drawPixmap(
                int(left), int(rect.center().y() - 7), pm)

        attach_w = 0.0
        if index.data(ROLE_HAS_ATTACH):
            attach_w = 16.0
            pm = icons.pixmap("paperclip", self.pal.get("text_faint", "#5d6b7d"), 14,
                              _dpr(option))
            painter.drawPixmap(
                int(right - 14), int(rect.center().y() - 7), pm)

        font = QFont(option.font)
        bold = index.data(Qt.FontRole)
        if isinstance(bold, QFont):
            font.setBold(bold.bold())
        text_rect = QRectF(left + chevron_w, rect.top(),
                           max(10.0, right - attach_w - left - chevron_w),
                           rect.height())
        text = index.data(ROLE_SUBJECT) or ""
        self._draw_maybe_rich(painter, text_rect, text, index, font,
                              self.color("text"))

    # -------------------------------------------------- 纯文本列
    def _paint_text(self, painter, option, index) -> None:
        text = index.data(Qt.DisplayRole) or ""
        if index.column() == COL_PLATFORM:
            color = index.data(Qt.ForegroundRole) or self.color("text_dim")
        else:
            color = self.color("text_dim")
        painter.setFont(option.font)
        painter.setPen(QColor(color) if not isinstance(color, QColor) else color)
        align = Qt.AlignVCenter | (Qt.AlignRight if index.column() == COL_TIME
                                   else Qt.AlignLeft)
        painter.drawText(option.rect.adjusted(6, 0, -6, 0), int(align), text)

    # -------------------------------------------------- 富文本 or 省略号
    def _draw_maybe_rich(self, painter, rect: QRectF, text: str, index,
                         font: QFont, color: QColor) -> None:
        keyword = index.data(ROLE_KEYWORD) or self.keyword
        if keyword and keyword.lower() in (text or "").lower():
            doc = QTextDocument()
            doc.setDefaultFont(font)
            doc.setDocumentMargin(0)
            doc.setHtml(
                f'<span style="color:{color.name()};">'
                + highlight_html(text, keyword, self.pal.get("highlight", "#7a6520"))
                + "</span>"
            )
            doc.setTextWidth(rect.width())
            painter.save()
            painter.translate(rect.left(),
                              rect.top() + max(0.0, (rect.height() - doc.size().height()) / 2))
            doc.drawContents(painter)
            painter.restore()
            return

        painter.setFont(font)
        painter.setPen(color)
        metrics = QFontMetrics(font)
        painter.drawText(rect, int(Qt.AlignVCenter | Qt.AlignLeft),
                         metrics.elidedText(text, Qt.ElideRight, int(rect.width())))

    # -------------------------------------------------- 尺寸
    def sizeHint(self, option, index) -> QSize:
        return QSize(0, CHILD_ROW_HEIGHT if index.data(ROLE_DEPTH)
                     else DEFAULT_ROW_HEIGHT)


def _dpr(option) -> int:
    """取当前绘制目标的分辨率倍率。

    委托里拿不到窗口的 `devicePixelRatio`，退而求其次用样式选项里的字体
    度量做近似：字体的 pixelSize 在 HiDPI 下已经被 Qt 放大过。
    取整并夹到 1–4，够用且不会因为异常值渲染出超大位图。
    """
    with contextlib.suppress(Exception):
        px = option.font.pixelSize()
        if px > 0:
            return max(1, min(4, round(px / 13.0) or 1))
    return 1


__all__ = ["AVATAR_SIZE", "AVATAR_SIZE_CHILD", "MailRowDelegate"]

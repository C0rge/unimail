"""收件箱表格模型：虚拟化渲染，支持万级邮件。"""
from __future__ import annotations

from datetime import datetime, timezone

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor, QFont

from ..config import platform_color, platform_name
from ..core.models import Mail

COL_UNREAD = 0
COL_SENDER = 1
COL_SUBJECT = 2
COL_PLATFORM = 3
COL_TIME = 4

HEADERS = ["", "发件人", "主题", "平台", "时间"]


class MailTableModel(QAbstractTableModel):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._mails: list[Mail] = []

    # ------------------------------------------------------------ 数据
    def set_mails(self, mails: list[Mail]) -> None:
        self.beginResetModel()
        self._mails = mails
        self.endResetModel()

    def mail_at(self, row: int) -> Mail | None:
        if 0 <= row < len(self._mails):
            return self._mails[row]
        return None

    def row_of(self, mail_id: str) -> int:
        for i, m in enumerate(self._mails):
            if m.id == mail_id:
                return i
        return -1

    def replace_mail(self, mail: Mail) -> None:
        row = self.row_of(mail.id)
        if row >= 0:
            self._mails[row] = mail
            self.dataChanged.emit(self.index(row, 0),
                                  self.index(row, len(HEADERS) - 1))

    @property
    def mails(self) -> list[Mail]:
        return self._mails

    # ------------------------------------------------------------ Qt 接口
    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._mails)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return HEADERS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        mail = self._mails[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            if col == COL_UNREAD:
                return "" 
            if col == COL_SENDER:
                return mail.sender_display
            if col == COL_SUBJECT:
                return mail.subject
            if col == COL_PLATFORM:
                return platform_name(mail.platform)
            if col == COL_TIME:
                return fmt_time(mail.date)

        if role == Qt.ForegroundRole:
            if col == COL_UNREAD:
                return QColor("#4c8dff") if not mail.is_read else QColor("#2a3242")
            if col == COL_PLATFORM:
                return QColor(platform_color(mail.platform))
            if col == COL_TIME:
                return QColor("#8b98a9")
            return QColor("#e6edf3") if not mail.is_read else QColor("#8b98a9")

        if role == Qt.FontRole:
            f = QFont()
            if not mail.is_read:
                f.setBold(True)
            return f

        if role == Qt.TextAlignmentRole and col == COL_UNREAD:
            return int(Qt.AlignCenter)

        if role == Qt.ToolTipRole:
            return (f"发件人：{mail.sender_display} <{mail.from_addr}>\n"
                    f"主题：{mail.subject}\n"
                    f"平台：{platform_name(mail.platform)}\n"
                    f"时间：{mail.date.astimezone().strftime('%Y-%m-%d %H:%M') if mail.date else '-'}\n"
                    f"附件：{'有' if mail.has_attachments else '无'}")

        if role == Qt.UserRole:
            return mail.id

        return None


def fmt_time(dt: datetime | None) -> str:
    """列表时间列：今天显时间，本年内显月-日，跨年显完整日期。"""
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    local = dt.astimezone()
    now = datetime.now().astimezone()
    if local.date() == now.date():
        return local.strftime("%H:%M")
    if local.year == now.year:
        return local.strftime("%m-%d")
    return local.strftime("%Y-%m-%d")


class MailFilterProxy:
    """占位：筛选在服务层用 SQL 完成，此处保留扩展点。"""

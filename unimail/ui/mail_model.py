"""收件箱表格模型：虚拟化渲染，支持万级邮件 + **增量更新**。

模型只持有 `MailSummary`（列表投影），**不持有正文**——正文单封可达上百 KB，
300 行就是数十 MB 常驻内存；点开某封时再按 id 取完整 `Mail`。

v1.4.0 的两个关键变化
=====================

**一、增量更新取代整表 reset。**
改造前同步线程只发一个无负载的「有新邮件了」，UI 只能整表重查 + `beginResetModel`。
`beginResetModel` 会让选中项、滚动位置、展开状态**全部丢失**——用户正在看第 40 封，
后台收到一封新邮件，视图立刻跳回顶部。现在同步侧给出 `[mail_id, ...]`，
模型只需 `beginInsertRows/endInsertRows` 插入那几行，其余行原地不动。

**二、会话（线程）视图复用同一个模型。**
会话视图需要「线程头 + 可展开的成员行」两级结构。直觉方案是换一个
`QTreeView` + 树模型，但那意味着同步逻辑、右键菜单、快捷键要在两套视图里
各实现一遍。这里改为**扁平化 + 缩进**：线程头是一行，展开时把成员行
插入其后（`depth=1`），折叠时删掉。列表视图就是「全部 depth=0」的退化情形，
因此两套视图共用同一份增量代码、同一个委托、同一套快捷键。
"""
from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import ClassVar

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QRectF, QSize, Qt
from PySide6.QtGui import QColor, QFont, QTextDocument
from PySide6.QtWidgets import QStyle, QStyledItemDelegate, QStyleOptionViewItem

from ..config import platform_color, platform_name
from ..core.models import Mail, MailSummary, ThreadSummary

COL_UNREAD = 0
COL_SENDER = 1
COL_SUBJECT = 2
COL_PLATFORM = 3
COL_TIME = 4

HEADERS = ["", "发件人", "主题", "平台", "时间"]

Row = MailSummary | Mail

DEFAULT_ROW_HEIGHT = 40
CHILD_ROW_HEIGHT = 34

# 供委托读取的扩展角色
ROLE_DEPTH = Qt.UserRole + 1
ROLE_IS_THREAD = Qt.UserRole + 2
ROLE_EXPANDED = Qt.UserRole + 3
ROLE_THREAD_TOTAL = Qt.UserRole + 4
ROLE_THREAD_UNREAD = Qt.UserRole + 5
ROLE_AVATAR = Qt.UserRole + 6
ROLE_AVATAR_COLOR = Qt.UserRole + 7
ROLE_STARRED = Qt.UserRole + 8
ROLE_HAS_ATTACH = Qt.UserRole + 9
ROLE_PLATFORM = Qt.UserRole + 10
ROLE_SUBJECT = Qt.UserRole + 11
ROLE_SENDER = Qt.UserRole + 12
ROLE_KEYWORD = Qt.UserRole + 13

# 列表渲染默认色（视图会用当前主题覆盖；保留默认值是为了模型可独立测试）
DEFAULT_PALETTE: dict[str, str] = {
    "bg": "#0f1216",
    "bg_panel": "#161b22",
    "bg_hover": "#232b3a",
    "border": "#2a3242",
    "text": "#e6edf3",
    "text_dim": "#8b98a9",
    "text_faint": "#5d6b7d",
    "accent": "#4c8dff",
    "unread": "#4c8dff",
    "selection_bg": "#2d5aa8",
    "selection_fg": "#ffffff",
    "highlight": "#7a6520",
    "_dark": "1",
}

SORT_KEYS = ("time", "sender", "subject", "platform", "read", "starred")


@dataclass
class RowMeta:
    """行元数据：与数据分开存。

    `MailSummary` 是 core 层的领域对象，不该为了「这一行是否缩进」
    而多出 UI 专有字段。
    """
    depth: int = 0
    is_thread: bool = False           # 会话头（可折叠）
    thread_key: str = ""
    total: int = 1
    unread: int = 0
    expanded: bool = False


def avatar_color(seed: str) -> str:
    """由发件人标识推出一个稳定的头像底色。

    用稳定的字符串哈希而不是内置 `hash()`——后者带进程随机化 salt，
    同一个人每次启动都会换颜色。
    """
    palette = (
        "#4c8dff", "#12b7f5", "#d93a37", "#ea4335", "#0078d4",
        "#7a5af8", "#e0883b", "#2ea043", "#b3569b", "#0f9b8e",
    )
    if not seed:
        return palette[0]
    acc = 0
    for ch in seed:
        acc = (acc * 131 + ord(ch)) & 0xFFFFFFFF
    return palette[acc % len(palette)]


def initials(name: str) -> str:
    """取头像上的 1–2 个字符。

    中文/日文/韩文取首字（「张三」取「张」——两个字在 32px 圆里会挤成一团）；
    西文取首尾缩写（「John Smith」→「JS」）。
    """
    text = (name or "").strip()
    if not text:
        return "?"
    for ch in text:
        if "\u3400" <= ch <= "\u9fff" or "\uac00" <= ch <= "\ud7af" \
                or "\u3040" <= ch <= "\u30ff":
            return ch
    parts = [p for p in text.replace(".", " ").replace("_", " ").split() if p]
    if not parts:
        return text[0].upper()
    if len(parts) == 1:
        return parts[0][:1].upper()
    return (parts[0][:1] + parts[-1][:1]).upper()


def palette_foreground(color: str, pal: dict[str, str]) -> str:
    """让平台色在两种主题下都有足够对比度。

    做法是缩放明度而不是换色：保持色相不变，「红色的那个是 163」
    这种用户记忆才不会被破坏。
    """
    try:
        r, g, b = (int(color[i:i + 2], 16) for i in (1, 3, 5))
    except (ValueError, IndexError):
        return color
    if pal.get("_dark") == "1":
        r, g, b = (min(255, int(v * 1.12) + 14) for v in (r, g, b))
    else:
        r, g, b = (int(v * 0.80) for v in (r, g, b))
    return f"#{r:02x}{g:02x}{b:02x}"


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


def highlight_html(text: str, keyword: str, color: str) -> str:
    """把命中片段包上背景色，其余部分转义。

    必须**先转义再插入标签**：直接把用户输入拼进 HTML 会形成注入
    （主题里带 `<b>` 就会被渲染），而 `&` 这类字符会让整段解析错位。
    实现顺序是：转义整段文本 → 在被转义后的文本里定位被转义后的关键词。
    """
    escaped = html.escape(text or "")
    needle = (keyword or "").strip()
    if not needle:
        return escaped
    esc_needle = html.escape(needle)
    lower_text, lower_needle = escaped.lower(), esc_needle.lower()
    out: list[str] = []
    pos = 0
    span = len(esc_needle)
    while True:
        hit = lower_text.find(lower_needle, pos)
        if hit < 0:
            out.append(escaped[pos:])
            break
        out.append(escaped[pos:hit])
        out.append(
            f'<span style="background:{color};">'
            f"{escaped[hit:hit + span]}</span>"
        )
        pos = hit + span
    return "".join(out)


class MailTableModel(QAbstractTableModel):
    """收件箱列表模型：支持列表 / 会话两种形态与增量更新。"""

    _SORT_KEYS: ClassVar[dict] = {
        "time": lambda m: (m.date is None,
                           m.date or datetime.min.replace(tzinfo=timezone.utc)),
        "sender": lambda m: (m.sender_display or "").lower(),
        "subject": lambda m: (m.subject or "").lower(),
        "platform": lambda m: m.platform,
        "read": lambda m: bool(m.is_read),
        "starred": lambda m: bool(getattr(m, "is_starred", False)),
    }

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[Row] = []
        self._meta: list[RowMeta] = []
        self._row_index: dict[str, int] = {}     # id -> row，替代 O(n) 线性查找
        self._thread_index: dict[str, int] = {}  # thread_key -> 线程头所在行
        self._keyword = ""
        self._thread_mode = False
        # 折叠状态跨刷新保留：用户展开了某个会话，刷新后不该自动折回去
        self._expanded: set[str] = set()
        self._palette: dict[str, str] = dict(DEFAULT_PALETTE)
        self._sort_key = "time"
        self._sort_desc = True

    # ------------------------------------------------------------ 读取
    @property
    def mails(self) -> list[Row]:
        return self._rows

    @property
    def thread_mode(self) -> bool:
        return self._thread_mode

    @property
    def keyword(self) -> str:
        return self._keyword

    @property
    def sort_state(self) -> tuple[str, bool]:
        return self._sort_key, self._sort_desc

    def row_count(self) -> int:
        return len(self._rows)

    def mail_at(self, row: int) -> Row | None:
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None

    def meta_at(self, row: int) -> RowMeta | None:
        if 0 <= row < len(self._meta):
            return self._meta[row]
        return None

    def row_of(self, mail_id: str) -> int:
        """O(1) 命中（此前是每次 O(n) 扫描整表）。"""
        return self._row_index.get(mail_id, -1)

    def id_at(self, row: int) -> str | None:
        mail = self.mail_at(row)
        return mail.id if mail is not None else None

    def mail_ids(self) -> list[str]:
        return [m.id for m in self._rows]

    def ids_at(self, rows: list[int]) -> list[str]:
        out = []
        for row in rows:
            mail = self.mail_at(row)
            if mail is not None:
                out.append(mail.id)
        return out

    def is_thread_head(self, row: int) -> bool:
        meta = self.meta_at(row)
        return bool(meta and meta.is_thread)

    def thread_key_at(self, row: int) -> str | None:
        meta = self.meta_at(row)
        return meta.thread_key if meta else None

    def row_of_thread(self, thread_key: str) -> int:
        """线程头的行号；-1 表示该会话当前不在表里。

        展开状态是按 `thread_key` 记住的，但成员行只在展开时插入，
        刷新后需要用这个反查把用户此前展开的会话重新摊开。
        """
        return self._thread_index.get(thread_key, -1)

    # ------------------------------------------------------------ 主题
    def set_palette(self, values: dict[str, str]) -> None:
        """注入当前调色板。

        模型不主动去查全局单例：同一进程里可能存在多个不同主题的模型
        （例如设置对话框里的预览），全局单例会让它们互相串色。
        """
        self._palette = {**DEFAULT_PALETTE, **values}
        if self._rows:
            self.dataChanged.emit(self.index(0, 0),
                                  self.index(len(self._rows) - 1, len(HEADERS) - 1))

    # ------------------------------------------------------------ 高亮
    def set_keyword(self, keyword: str) -> None:
        keyword = (keyword or "").strip()
        if keyword == self._keyword:
            return
        self._keyword = keyword
        if self._rows:
            self.dataChanged.emit(self.index(0, 0),
                                  self.index(len(self._rows) - 1, len(HEADERS) - 1))

    # ------------------------------------------------------------ 整体设置
    def set_mails(self, mails: list[Row]) -> None:
        """列表视图：整体替换（筛选条件变化时使用）。"""
        self._thread_mode = False
        rows, metas = list(mails), [RowMeta() for _ in mails]
        if self._sort_key != "time" or not self._sort_desc:
            order = self._order(rows)
            rows = [rows[i] for i in order]
            metas = [metas[i] for i in order]
        self._apply(rows, metas)

    def set_threads(self, threads: list[ThreadSummary]) -> None:
        """会话视图：整体替换，并保留用户此前的展开状态。"""
        self._thread_mode = True
        rows: list[Row] = []
        metas: list[RowMeta] = []
        for thread in threads:
            key = thread.thread_key
            rows.append(thread.latest)
            metas.append(RowMeta(
                depth=0, is_thread=True, thread_key=key,
                total=thread.total, unread=thread.unread,
                expanded=key in self._expanded,
            ))
        self._apply(rows, metas)

    def set_thread_members(self, thread_key: str, members: list[MailSummary],
                           head_row: int) -> int:
        """把某个会话的成员行展开插入线程头之后。返回插入行数。"""
        head = self.mail_at(head_row)
        if head is None:
            return 0
        fresh = [m for m in members if m.id != head.id and m.id not in self._row_index]
        self._expanded.add(thread_key)
        if self.meta_at(head_row):
            self._meta[head_row].expanded = True
        if not fresh:
            self.dataChanged.emit(self.index(head_row, 0),
                                  self.index(head_row, len(HEADERS) - 1))
            return 0
        start = head_row + 1
        self.beginInsertRows(QModelIndex(), start, start + len(fresh) - 1)
        self._rows[start:start] = list(fresh)
        self._meta[start:start] = [RowMeta(depth=1, thread_key=thread_key)
                                   for _ in fresh]
        self.endInsertRows()
        self._reindex()
        return len(fresh)

    def collapse_thread(self, thread_key: str, head_row: int) -> int:
        """折叠会话，返回被移除的成员行数。"""
        self._expanded.discard(thread_key)
        meta = self.meta_at(head_row)
        if meta:
            meta.expanded = False
        end = head_row + 1
        while end < len(self._rows) and self._meta[end].depth > 0:
            end += 1
        count = end - (head_row + 1)
        if count <= 0:
            if meta:
                self.dataChanged.emit(self.index(head_row, 0),
                                      self.index(head_row, len(HEADERS) - 1))
            return 0
        self.beginRemoveRows(QModelIndex(), head_row + 1, end - 1)
        del self._rows[head_row + 1:end]
        del self._meta[head_row + 1:end]
        self.endRemoveRows()
        self._reindex()
        return count

    def is_expanded(self, thread_key: str) -> bool:
        return thread_key in self._expanded

    @property
    def expanded_threads(self) -> set[str]:
        return set(self._expanded)

    def set_expanded_threads(self, keys) -> None:
        self._expanded = set(keys)

    def _apply(self, rows: list[Row], metas: list[RowMeta]) -> None:
        self.beginResetModel()
        self._rows = list(rows)
        self._meta = list(metas)
        self._reindex()
        self.endResetModel()

    def _reindex(self) -> None:
        self._row_index = {m.id: i for i, m in enumerate(self._rows)}
        self._thread_index = {meta.thread_key: i
                              for i, meta in enumerate(self._meta)
                              if meta.is_thread}

    # ------------------------------------------------------------ 增量
    def insert_rows(self, mails: list[Row], front: bool = True) -> int:
        """增量插入（同步线程报来新邮件时使用），**不触发整表 reset**。

        返回实际插入的行数。已存在的 id 会被跳过——同步侧给的 id 列表
        在一次会话里可能重复（同一页被重试），重复插入会在表里出现两行同 id。
        """
        fresh: list[tuple[Row, RowMeta]] = []
        for mail in mails:
            if mail.id in self._row_index:
                continue
            if self._thread_mode:
                key = getattr(mail, "thread_key", "") or mail.id
                # 该会话已在表里 → 不新增行，只把统计量 +1 并把线程头更新为这封
                row = self._row_index.get(key)
                if row >= 0 and self._meta[row].is_thread:
                    self._rows[row] = mail
                    self._meta[row].total += 1
                    if not mail.is_read:
                        self._meta[row].unread += 1
                    self.dataChanged.emit(self.index(row, 0),
                                          self.index(row, len(HEADERS) - 1))
                    continue
                meta = RowMeta(depth=0, is_thread=True, thread_key=key,
                               total=1, unread=0 if mail.is_read else 1)
            else:
                meta = RowMeta()
            fresh.append((mail, meta))
        if not fresh:
            return 0

        if front:
            self.beginInsertRows(QModelIndex(), 0, len(fresh) - 1)
            payload = list(reversed(fresh))
            self._rows[0:0] = [m for m, _ in payload]
            self._meta[0:0] = [mt for _, mt in payload]
        else:
            start = len(self._rows)
            self.beginInsertRows(QModelIndex(), start, start + len(fresh) - 1)
            self._rows.extend(m for m, _ in fresh)
            self._meta.extend(mt for _, mt in fresh)
        self.endInsertRows()
        self._reindex()
        return len(fresh)

    def remove_ids(self, mail_ids: list[str]) -> int:
        """按 id 批量删除行。返回删除行数。

        从后往前删：每次删除都会让后续行号左移，正序删除会越删越偏。
        """
        victims = sorted({self._row_index[i] for i in mail_ids if i in self._row_index},
                         reverse=True)
        if not victims:
            return 0
        for row in victims:
            self.beginRemoveRows(QModelIndex(), row, row)
            del self._rows[row]
            del self._meta[row]
        self.endRemoveRows()
        self._reindex()
        return len(victims)

    def replace_row(self, mail: Row) -> bool:
        """就地替换一行，只重绘该行（不再整表 reset）。"""
        row = self.row_of(mail.id)
        if row < 0:
            return False
        self._rows[row] = mail
        self.dataChanged.emit(self.index(row, 0),
                              self.index(row, len(HEADERS) - 1))
        return True

    def replace_mail(self, mail: Row) -> None:
        """兼容旧调用名。"""
        self.replace_row(mail)

    def replace_rows(self, mails: list[Row]) -> int:
        """批量就地替换（批量已读/星标后使用），一次 dataChanged 覆盖整段。"""
        rows = [self._row_index[m.id] for m in mails if m.id in self._row_index]
        if not rows:
            return 0
        for mail in mails:
            row = self._row_index.get(mail.id)
            if row is not None:
                self._rows[row] = mail
        self.dataChanged.emit(self.index(min(rows), 0),
                              self.index(max(rows), len(HEADERS) - 1))
        return len(rows)

    # ------------------------------------------------------------ 排序
    def _order(self, rows: list[Row]) -> list[int]:
        keyfunc = self._SORT_KEYS.get(self._sort_key)
        if keyfunc is None:
            return list(range(len(rows)))
        return sorted(range(len(rows)), key=lambda i: keyfunc(rows[i]),
                      reverse=self._sort_desc)

    def sort_by(self, key: str, descending: bool | None = None) -> bool:
        """原地排序并**保留选中项**。

        直接 `beginResetModel` 也能排序，但会把选中和滚动位置清掉。
        这里走 Qt 的「移动行」协议：`layoutAboutToBeChanged` → 重排 →
        `changePersistentIndexList` 把旧的持久索引映射到新的行号 →
        `layoutChanged`。选中项因此会跟着它对应的邮件一起移动。
        """
        if key not in self._SORT_KEYS:
            return False
        if descending is None:
            descending = not self._sort_desc if key == self._sort_key else key == "time"
        self._sort_key, self._sort_desc = key, descending
        if len(self._rows) < 2:
            return True

        order = self._order(self._rows)
        if order == list(range(len(self._rows))):
            return True

        old_indexes = list(self.persistentIndexList())
        old_ids = [self._rows[idx.row()].id for idx in old_indexes
                   if 0 <= idx.row() < len(self._rows)]

        self.layoutAboutToBeChanged.emit()
        self._rows = [self._rows[i] for i in order]
        self._meta = [self._meta[i] for i in order]
        self._reindex()
        remapped = [self.index(self._row_index[mid], idx.column())
                    if mid in self._row_index else self.index(-1, 0)
                    for mid, idx in zip(old_ids, old_indexes, strict=False)]
        if len(remapped) == len(old_indexes):
            self.changePersistentIndexList(old_indexes, remapped)
        self.layoutChanged.emit()
        return True

    def sort_default(self) -> None:
        """恢复默认排序（时间倒序）。"""
        self._sort_key, self._sort_desc = "time", True
        self.sort_by("time", True)

    # ------------------------------------------------------------ Qt 接口
    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if (orientation == Qt.Horizontal and role == Qt.DisplayRole
                and 0 <= section < len(HEADERS)):
            return HEADERS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid() or index.row() >= len(self._rows):
            return None
        mail = self._rows[index.row()]
        meta = self._meta[index.row()]
        col = index.column()
        pal = self._palette

        if role == Qt.DisplayRole:
            if col == COL_UNREAD:
                return ""
            if col == COL_SENDER:
                return mail.sender_display
            if col == COL_SUBJECT:
                return self._subject_text(mail, meta)
            if col == COL_PLATFORM:
                return platform_name(mail.platform)
            if col == COL_TIME:
                return fmt_time(mail.date)

        if role == Qt.ForegroundRole:
            if col == COL_UNREAD:
                return QColor(pal["unread"] if not mail.is_read else pal["border"])
            if col == COL_PLATFORM:
                return QColor(palette_foreground(platform_color(mail.platform), pal))
            if col == COL_TIME:
                return QColor(pal["text_dim"])
            if meta.depth:
                return QColor(pal["text_dim"])
            return QColor(pal["text"] if not mail.is_read else pal["text_dim"])

        if role == Qt.FontRole:
            f = QFont()
            if not mail.is_read or meta.unread:
                f.setBold(True)
            return f

        if role == Qt.TextAlignmentRole and col == COL_UNREAD:
            return int(Qt.AlignCenter)

        if role == Qt.SizeHintRole:
            return QSize(0, CHILD_ROW_HEIGHT if meta.depth else DEFAULT_ROW_HEIGHT)

        if role == Qt.ToolTipRole:
            lines = [
                f"发件人：{mail.sender_display} <{getattr(mail, 'from_addr', '')}>",
                f"主题：{mail.subject}",
                f"平台：{platform_name(mail.platform)}",
                "时间：" + (mail.date.astimezone().strftime("%Y-%m-%d %H:%M")
                            if mail.date else "-"),
                f"附件：{'有' if mail.has_attachments else '无'}",
            ]
            if meta.is_thread:
                lines.append(f"会话：共 {meta.total} 封，其中 {meta.unread} 封未读")
            if self._keyword:
                lines.append(f"命中关键词：{self._keyword}")
            return "\n".join(lines)

        if role == Qt.UserRole:
            return mail.id

        if role == ROLE_DEPTH:
            return meta.depth
        if role == ROLE_IS_THREAD:
            return meta.is_thread
        if role == ROLE_EXPANDED:
            return meta.expanded
        if role == ROLE_THREAD_TOTAL:
            return meta.total
        if role == ROLE_THREAD_UNREAD:
            return meta.unread
        if role == ROLE_AVATAR:
            return initials(mail.sender_display)
        if role == ROLE_AVATAR_COLOR:
            return avatar_color(getattr(mail, "from_addr", "") or mail.sender_display)
        if role == ROLE_STARRED:
            return bool(getattr(mail, "is_starred", False))
        if role == ROLE_HAS_ATTACH:
            return bool(getattr(mail, "has_attachments", False))
        if role == ROLE_PLATFORM:
            return mail.platform
        if role == ROLE_SUBJECT:
            return mail.subject
        if role == ROLE_SENDER:
            return mail.sender_display
        if role == ROLE_KEYWORD:
            return self._keyword

        return None

    def _subject_text(self, mail: Row, meta: RowMeta) -> str:
        subject = mail.subject or "(无主题)"
        if meta.is_thread and meta.total > 1:
            return f"{subject}  ({meta.total})"
        return subject


class HighlightDelegate(QStyledItemDelegate):
    """按关键词高亮命中的绘制委托。

    为什么用委托而不是让 `data()` 返回 HTML：`QTableView` 默认把
    DisplayRole 当**纯文本**画，返回 `<b>` 会原样显示成字面量。
    要渲染富文本必须自己接管绘制（`QTextDocument`），这正是委托的职责。
    """

    def __init__(self, parent=None, keyword: str = "", color: str = "#7a6520") -> None:
        super().__init__(parent)
        self.keyword = keyword or ""
        self.color = color
        self.text_color = "#e6edf3"

    def configure(self, keyword: str, color: str | None = None,
                  text_color: str | None = None) -> None:
        self.keyword = keyword or ""
        if color:
            self.color = color
        if text_color:
            self.text_color = text_color

    def paint(self, painter, option, index) -> None:
        keyword = index.data(ROLE_KEYWORD) or self.keyword
        col = index.column()
        if not keyword or col not in (COL_SUBJECT, COL_SENDER):
            super().paint(painter, option, index)
            return
        text = (index.data(ROLE_SUBJECT) if col == COL_SUBJECT
                else index.data(ROLE_SENDER)) or ""
        if keyword.lower() not in text.lower():
            super().paint(painter, option, index)
            return

        widget = option.widget
        # 先用「空文本」让样式引擎把背景/选中态画好，再叠上富文本；
        # 否则富文本会覆盖掉选中背景，选中行看不出被选。
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        opt.text = ""
        style = widget.style() if widget is not None else None
        if style is not None:
            style.drawControl(QStyle.CE_ItemViewItem, opt, painter, widget)

        doc = QTextDocument()
        doc.setDefaultFont(option.font)
        doc.setDocumentMargin(0)
        doc.setHtml(
            f'<span style="color:{self.text_color};">'
            + highlight_html(text, keyword, self.color) + "</span>"
        )
        painter.save()
        rect = QRectF(option.rect.adjusted(6, 0, -6, 0))
        doc.setTextWidth(rect.width())
        top = rect.top() + max(0.0, (rect.height() - doc.size().height()) / 2.0)
        painter.translate(rect.left(), top)
        doc.drawContents(painter)
        painter.restore()

    def sizeHint(self, option, index) -> QSize:
        height = CHILD_ROW_HEIGHT if index.data(ROLE_DEPTH) else DEFAULT_ROW_HEIGHT
        # 覆盖掉基类按列内容算出的宽度（否则「主题」列会被撑得很宽，
        # 列宽策略交给 header，不由内容决定）
        return QSize(0, height)


class MailFilterProxy:
    """占位：筛选在服务层用 SQL 完成，此处保留扩展点。"""


__all__ = [
    "CHILD_ROW_HEIGHT",
    "COL_PLATFORM",
    "COL_SENDER",
    "COL_SUBJECT",
    "COL_TIME",
    "COL_UNREAD",
    "DEFAULT_PALETTE",
    "DEFAULT_ROW_HEIGHT",
    "HEADERS",
    "ROLE_AVATAR",
    "ROLE_AVATAR_COLOR",
    "ROLE_DEPTH",
    "ROLE_EXPANDED",
    "ROLE_HAS_ATTACH",
    "ROLE_IS_THREAD",
    "ROLE_KEYWORD",
    "ROLE_PLATFORM",
    "ROLE_SENDER",
    "ROLE_STARRED",
    "ROLE_SUBJECT",
    "ROLE_THREAD_TOTAL",
    "ROLE_THREAD_UNREAD",
    "SORT_KEYS",
    "HighlightDelegate",
    "MailFilterProxy",
    "MailTableModel",
    "RowMeta",
    "avatar_color",
    "fmt_time",
    "highlight_html",
    "initials",
    "palette_foreground",
]

"""中间栏：统一收件箱（表格 + 工具栏 + 空状态）。

v1.4.0 的变化
=============
* **多选。** `SingleSelection` → `ExtendedSelection`。批量已读/星标/删除是
  邮件客户端里最常用的动作，一次一封地处理二十封是对用户的折磨。
* **`J/K` 导航。** Vim 风格的上下移动，配合多选可以「`J J J Space`」式操作；
  `Shift+J/K` 扩展选择。
* **命中数。** 搜索时在工具栏显示「命中 N 封」，让用户知道当前结果是
  「只有 3 封」还是「有 300 封被截断」，而不是靠猜。
* **会话视图。** 同一个表 + 同一个模型，展开/折叠在行内完成。
* **导出。** 右键可导出 `.eml` / `.mbox` / CSV ——此前只有「下载附件」，
  用户拿到的东西没法离开本程序。

关于「批量」的信号设计
----------------------
批量动作统一发 `list[str]`。保留单封版本的信号（`mark_read_requested` 等）
是为了不破坏既有的快捷键路径；面板内部会把「当前选中集合」规约成一个
统一的入口，避免出现「右键菜单走批量、快捷键走单封」这种不一致。
"""
from __future__ import annotations

from PySide6.QtCore import QItemSelectionModel, QModelIndex, Qt, Signal
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QPushButton,
    QStackedLayout,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from ..core.models import Mail, MailSummary, ThreadSummary
from . import icons
from .mail_model import (
    COL_PLATFORM,
    COL_SENDER,
    COL_SUBJECT,
    COL_TIME,
    COL_UNREAD,
    ROLE_THREAD_TOTAL,
    MailTableModel,
)
from .row_delegate import MailRowDelegate


class EmptyState(QWidget):
    def __init__(self, title: str, hint: str, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(8)
        t = QLabel(title)
        t.setObjectName("EmptyTitle")
        t.setAlignment(Qt.AlignCenter)
        h = QLabel(hint)
        h.setObjectName("EmptyHint")
        h.setAlignment(Qt.AlignCenter)
        h.setWordWrap(True)
        layout.addWidget(t)
        layout.addWidget(h)

    def set_hint(self, hint: str) -> None:
        item = self.layout().itemAt(1)
        if item and item.widget():
            item.widget().setText(hint)


class InboxToolbar(QFrame):
    """列表上方的一条轻量工具栏：计数 + 视图切换 + 排序 + 批量入口。"""

    view_mode_requested = Signal(str)      # "list" | "thread"
    sort_requested = Signal(str, bool)     # field, descending
    batch_requested = Signal(str)          # read | unread | star | unstar | delete
    select_all_requested = Signal(bool)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("Panel")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 7, 12, 7)
        layout.setSpacing(8)

        self.count = QLabel("")
        self.count.setObjectName("Hint")
        layout.addWidget(self.count)
        layout.addStretch(1)

        self.selection_label = QLabel("")
        self.selection_label.setObjectName("Badge")
        self.selection_label.hide()
        layout.addWidget(self.selection_label)

        self.btn_batch = QPushButton("批量操作")
        self.btn_batch.setObjectName("Ghost")
        self.btn_batch.clicked.connect(self._show_batch_menu)
        layout.addWidget(self.btn_batch)

        self.btn_sort = QPushButton("排序")
        self.btn_sort.setObjectName("Ghost")
        self.btn_sort.clicked.connect(self._show_sort_menu)
        layout.addWidget(self.btn_sort)

        self.btn_view = QPushButton("会话")
        self.btn_view.setObjectName("Ghost")
        self.btn_view.setToolTip("在「列表」与「会话」之间切换（Ctrl+G）")
        self.btn_view.clicked.connect(self._toggle_view)
        layout.addWidget(self.btn_view)

        self._view_mode = "list"
        self._theme = None

    # ------------------------------------------------------------ 主题
    def apply_theme(self, palette: dict) -> None:
        self._theme = palette
        self.btn_sort.setIcon(icons.icon("sort", palette.get("text_dim", "#8b98a9"), 14))
        self.btn_view.setIcon(
            icons.icon("layout-thread", palette.get("text_dim", "#8b98a9"), 14))
        self.btn_batch.setIcon(
            icons.icon("check", palette.get("text_dim", "#8b98a9"), 14))

    # ------------------------------------------------------------ 文案
    def set_count(self, total: int, hits: int | None, keyword: str) -> None:
        if keyword and hits is not None:
            self.count.setText(f"「{keyword}」命中 {hits} 封 · 显示 {total} 封")
        elif keyword:
            self.count.setText(f"「{keyword}」· 显示 {total} 封")
        else:
            self.count.setText(f"共 {total} 封")

    def set_selection(self, n: int) -> None:
        if n > 1:
            self.selection_label.setText(f"已选 {n} 封")
            self.selection_label.show()
        else:
            self.selection_label.hide()

    def set_view_mode(self, mode: str) -> None:
        self._view_mode = mode
        self.btn_view.setText("列表" if mode == "thread" else "会话")

    # ------------------------------------------------------------ 菜单
    def _show_batch_menu(self) -> None:
        menu = QMenu(self)
        act_read = menu.addAction("标记为已读")
        act_unread = menu.addAction("标记为未读")
        menu.addSeparator()
        act_star = menu.addAction("加星标")
        act_unstar = menu.addAction("取消星标")
        menu.addSeparator()
        act_all = menu.addAction("全选当前列表")
        act_none = menu.addAction("取消选择")
        menu.addSeparator()
        act_delete = menu.addAction("删除本地副本")

        chosen = menu.exec(self.btn_batch.mapToGlobal(self.btn_batch.rect().bottomLeft()))
        mapping = {
            act_read: ("read", "batch_requested"),
            act_unread: ("unread", "batch_requested"),
            act_star: ("star", "batch_requested"),
            act_unstar: ("unstar", "batch_requested"),
            act_delete: ("delete", "batch_requested"),
        }
        if chosen in mapping:
            self.batch_requested.emit(mapping[chosen][0])
        elif chosen == act_all:
            self.select_all_requested.emit(True)
        elif chosen == act_none:
            self.select_all_requested.emit(False)

    def _show_sort_menu(self) -> None:
        menu = QMenu(self)
        entries = [
            ("按时间（新→旧）", "time", True),
            ("按时间（旧→新）", "time", False),
            ("按发件人", "sender", False),
            ("按主题", "subject", False),
            ("按平台", "platform", False),
            ("未读优先", "read", False),
            ("星标优先", "starred", True),
        ]
        actions = {}
        for label, field, desc in entries:
            act = menu.addAction(label)
            actions[act] = (field, desc)
        chosen = menu.exec(self.btn_sort.mapToGlobal(self.btn_sort.rect().bottomLeft()))
        if chosen in actions:
            field, desc = actions[chosen]
            self.sort_requested.emit(field, desc)

    def _toggle_view(self) -> None:
        self._view_mode = "thread" if self._view_mode == "list" else "list"
        self.set_view_mode(self._view_mode)
        self.view_mode_requested.emit(self._view_mode)


class InboxPanel(QFrame):
    """统一收件箱视图。"""

    mail_selected = Signal(str)              # mail_id
    mail_double_clicked = Signal(str)
    mail_activated = Signal(str)             # Enter / 双击（含会话成员）

    # 单封（兼容既有接线）
    mark_read_requested = Signal(str, bool)
    star_requested = Signal(str)
    delete_requested = Signal(str)

    # 批量
    mark_read_many_requested = Signal(list, bool)
    star_many_requested = Signal(list, bool)
    delete_many_requested = Signal(list)

    export_requested = Signal(str, list)     # kind(eml|mbox|csv), mail_ids
    thread_toggle_requested = Signal(str, int)   # thread_key, row
    notice = Signal(str)                     # 需要提示用户的短消息

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("Panel")
        self.model = MailTableModel(self)
        self.delegate = MailRowDelegate(self)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.toolbar = InboxToolbar()
        root.addWidget(self.toolbar)

        self.stack = QStackedLayout()
        root.addLayout(self.stack, 1)

        self._build_table()
        self.empty = EmptyState("收件箱为空",
                                "点击左侧「添加邮箱账号」开始，\n或在筛选栏调整搜索条件。")
        self.stack.addWidget(self.table)
        self.stack.addWidget(self.empty)

        self._wire()
        self._install_shortcuts()

    # ------------------------------------------------------------ 构建
    def _build_table(self) -> None:
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setItemDelegate(self.delegate)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        # 多选：批量操作的前提。`ExtendedSelection` 支持 Ctrl 点选与 Shift 连选。
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(False)
        self.table.setWordWrap(False)
        self.table.setMouseTracking(True)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(40)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        # 键盘驱动：方向键/J/K 在视图上原生处理，交给 isKeyboardSelectable
        self.table.setFocusPolicy(Qt.StrongFocus)

        header = self.table.horizontalHeader()
        header.setHighlightSections(False)
        header.setSectionsClickable(True)
        header.sectionClicked.connect(self._on_header_clicked)
        header.setSectionResizeMode(COL_UNREAD, QHeaderView.Fixed)
        header.setSectionResizeMode(COL_SENDER, QHeaderView.Interactive)
        header.setSectionResizeMode(COL_SUBJECT, QHeaderView.Stretch)
        header.setSectionResizeMode(COL_PLATFORM, QHeaderView.Fixed)
        header.setSectionResizeMode(COL_TIME, QHeaderView.Fixed)
        self.table.setColumnWidth(COL_UNREAD, 30)
        self.table.setColumnWidth(COL_SENDER, 176)
        self.table.setColumnWidth(COL_PLATFORM, 92)
        self.table.setColumnWidth(COL_TIME, 74)
        self.table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)

    def _wire(self) -> None:
        # 选中驱动的更新必须挂在 `currentRowChanged` 上：键盘 J/K、
        # 程序化 `selectRow`、Ctrl 点选都会走这里；而 `clicked` 只覆盖鼠标。
        sm = self.table.selectionModel()
        sm.currentRowChanged.connect(self._on_current_row_changed)
        self.table.clicked.connect(self._on_clicked)
        self.table.doubleClicked.connect(self._on_double_clicked)
        self.table.customContextMenuRequested.connect(self._on_context_menu)
        self.toolbar.view_mode_requested.connect(self._on_view_mode)
        self.toolbar.sort_requested.connect(self._on_sort)
        self.toolbar.batch_requested.connect(self._on_batch)
        self.toolbar.select_all_requested.connect(self.select_all)

    def _install_shortcuts(self) -> None:
        """快捷键挂在表格上（用 `WidgetShortcut` 上下文）。

        不挂在主窗口：`Delete` 这类键在搜索框里是「删除字符」，
        全局注册会把输入框的行为抢走。
        """
        bindings = [
            ("J", lambda: self.move_cursor(1)),
            ("K", lambda: self.move_cursor(-1)),
            ("Shift+J", lambda: self.extend_selection(1)),
            ("Shift+K", lambda: self.extend_selection(-1)),
            ("U", self._toggle_read_current),
            ("S", self._toggle_star_current),
            ("Delete", self._delete_selected),
            ("Backspace", self._delete_selected),
            ("Return", self._activate_current),
            ("Ctrl+A", lambda: self.select_all(True)),
            ("Space", self._toggle_thread_current),
            ("Ctrl+Shift+E", lambda: self._export("eml")),
            ("Ctrl+Shift+M", lambda: self._export("mbox")),
            ("Ctrl+Shift+C", lambda: self._export("csv")),
        ]
        self._shortcuts = []
        for seq, slot in bindings:
            sc = QShortcut(QKeySequence(seq), self.table)
            sc.setContext(Qt.WidgetShortcut)
            sc.activated.connect(slot)
            self._shortcuts.append(sc)

    # ------------------------------------------------------------ 主题
    def apply_theme(self, palette: dict) -> None:
        self.model.set_palette(palette)
        self.delegate.set_palette(palette)
        self.toolbar.apply_theme(palette)
        self.table.viewport().update()

    # ------------------------------------------------------------ 数据
    def set_mails(self, mails: list[MailSummary], empty_hint: str | None = None,
                  *, hit_count: int | None = None, keyword: str = "",
                  thread_mode: bool = False,
                  threads: list[ThreadSummary] | None = None) -> None:
        selected = self.selected_ids()
        expanded = self.model.expanded_threads

        self.model.set_keyword(keyword)
        self.delegate.set_keyword(keyword)
        self.toolbar.set_view_mode("thread" if thread_mode else "list")

        if thread_mode and threads is not None:
            self.model.set_expanded_threads(expanded)
            self.model.set_threads(threads)
            total = len(threads)
        else:
            self.model.set_mails(mails)
            total = len(mails)

        self.toolbar.set_count(total, hit_count, keyword)
        self.toolbar.set_selection(0)

        if self.model.row_count():
            self.stack.setCurrentWidget(self.table)
            self._restore_selection(selected)
        else:
            if empty_hint:
                self.empty.set_hint(empty_hint)
            self.stack.setCurrentWidget(self.empty)

    def _restore_selection(self, ids: list[str]) -> None:
        rows = [self.model.row_of(i) for i in ids]
        rows = [r for r in rows if r >= 0]
        if not rows:
            return
        sm = self.table.selectionModel()
        for i, row in enumerate(rows):
            flag = (QItemSelectionModel.Select if i else QItemSelectionModel.ClearAndSelect)
            sm.select(self.model.index(row, 0),
                      flag | QItemSelectionModel.Rows)
        # 必须用 `NoUpdate` 设当前项：`QTableView.setCurrentIndex` 会用
        # `selectionCommand()` 的返回值（ExtendedSelection 下是 ClearAndSelect）
        # 去改选中集，把刚恢复的多选整个清掉。
        sm.setCurrentIndex(self.model.index(rows[0], 0), QItemSelectionModel.NoUpdate)

    def current_mail_id(self) -> str | None:
        idx = self.table.currentIndex()
        return self.model.data(idx, Qt.UserRole) if idx.isValid() else None

    def selected_ids(self) -> list[str]:
        """当前选中的邮件 id。

        会话头行也返回自身的 id（它是该会话的最新一封），这样「对选中项
        标已读」在会话视图下语义仍然自然：至少把最新那封标掉。
        """
        rows = sorted({i.row() for i in self.table.selectionModel().selectedRows()})
        if not rows:
            current = self.table.currentIndex()
            return [self.model.data(current, Qt.UserRole)] if current.isValid() else []
        return [mid for mid in (self.model.id_at(r) for r in rows) if mid]

    def selected_thread_keys(self) -> list[str]:
        return [self.model.thread_key_at(i.row())
                for i in self.table.selectionModel().selectedRows()
                if self.model.is_thread_head(i.row())]

    def expanded_thread_keys(self) -> set[str]:
        """用户展开过的会话 key（跨刷新保留，供主窗口重新摊开成员行）。"""
        return self.model.expanded_threads

    def row_of_thread(self, key: str) -> int:
        return self.model.row_of_thread(key)

    def select_mail(self, mail_id: str) -> None:
        row = self.model.row_of(mail_id)
        if row >= 0:
            self.table.selectRow(row)
            self.table.setCurrentIndex(self.model.index(row, 0))

    def refresh_row(self, mail: MailSummary | Mail) -> None:
        self.model.replace_row(mail)

    def refresh_rows(self, mails: list[MailSummary | Mail]) -> None:
        self.model.replace_rows(mails)

    def insert_mails(self, mails: list) -> int:
        """同步线程报来新邮件时的增量插入。"""
        n = self.model.insert_rows(mails)
        if n:
            self.toolbar.set_count(self.model.row_count(), None,
                                   self.model.keyword)
            self.stack.setCurrentWidget(self.table)
        return n

    def remove_mails(self, mail_ids: list[str]) -> int:
        n = self.model.remove_ids(mail_ids)
        if n:
            self.toolbar.set_count(self.model.row_count(), None, self.model.keyword)
            if not self.model.row_count():
                self.stack.setCurrentWidget(self.empty)
        return n

    # ------------------------------------------------------------ 导航
    def move_cursor(self, delta: int) -> None:
        row = self._current_row()
        target = max(0, min(self.model.row_count() - 1, row + delta))
        if target == row or self.model.row_count() == 0:
            return
        index = self.model.index(target, 0)
        self.table.setCurrentIndex(index)
        self.table.selectionModel().select(
            index, QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)
        self.table.scrollTo(index, QAbstractItemView.EnsureVisible)

    def extend_selection(self, delta: int) -> None:
        """`Shift+J/K`：把光标移动到的行**追加**进选中集。"""
        row = self._current_row()
        target = max(0, min(self.model.row_count() - 1, row + delta))
        if target == row or self.model.row_count() == 0:
            return
        index = self.model.index(target, 0)
        sm = self.table.selectionModel()
        # 先移动当前项（NoUpdate 不碰选中集），再追加选中——
        # 反过来的话 `Select` 加进去的行会被当前项变更清掉。
        sm.setCurrentIndex(index, QItemSelectionModel.NoUpdate)
        sm.select(index, QItemSelectionModel.Select | QItemSelectionModel.Rows)
        self.table.scrollTo(index, QAbstractItemView.EnsureVisible)

    def _current_row(self) -> int:
        idx = self.table.currentIndex()
        return idx.row() if idx.isValid() else -1

    def select_all(self, on: bool = True) -> None:
        if on:
            self.table.selectAll()
        else:
            self.table.clearSelection()
        self._sync_selection_label()

    # ------------------------------------------------------------ 交互
    def _sync_selection_label(self) -> None:
        self.toolbar.set_selection(len(self.selected_ids()))

    def _on_current_row_changed(self, current: QModelIndex, _previous) -> None:
        self._sync_selection_label()
        if not current.isValid():
            return
        mail_id = self.model.data(current, Qt.UserRole)
        if mail_id:
            self.mail_selected.emit(mail_id)

    def _on_clicked(self, index: QModelIndex) -> None:
        """鼠标单击：只负责刷新「已选 N 封」。

        `mail_selected` 已由 `currentRowChanged` 发过一次，这里再发会重复——
        详情面板会对同一封邮件做两次「标已读 + 排队服务器标记」。
        """
        self._sync_selection_label()

    def _on_double_clicked(self, index: QModelIndex) -> None:
        if not index.isValid():
            return
        if self.model.is_thread_head(index.row()):
            self._toggle_thread_row(index.row())
            return
        mail_id = self.model.data(index, Qt.UserRole)
        if mail_id:
            self.mail_double_clicked.emit(mail_id)
            self.mail_activated.emit(mail_id)

    def _toggle_thread_current(self) -> None:
        row = self._current_row()
        if row >= 0 and self.model.is_thread_head(row):
            self._toggle_thread_row(row)

    def _toggle_thread_row(self, row: int) -> None:
        key = self.model.thread_key_at(row)
        if not key:
            return
        self.thread_toggle_requested.emit(key, row)

    def toggle_thread(self, key: str, row: int, members: list[MailSummary]) -> None:
        """由主窗口提供成员后，真正执行展开/折叠。"""
        if self.model.is_expanded(key):
            self.model.collapse_thread(key, row)
        else:
            self.model.set_thread_members(key, members, row)
        self.toolbar.set_count(self.model.row_count(), None, self.model.keyword)

    def _activate_current(self) -> None:
        mail_id = self.current_mail_id()
        if mail_id:
            self.mail_double_clicked.emit(mail_id)
            self.mail_activated.emit(mail_id)

    def _toggle_read_current(self) -> None:
        ids = self.selected_ids()
        if not ids:
            return
        mail = self.model.mail_at(self._current_row())
        target = not (mail.is_read if mail else True)
        self._emit_read(ids, target)

    def _toggle_star_current(self) -> None:
        ids = self.selected_ids()
        if not ids:
            return
        mail = self.model.mail_at(self._current_row())
        target = not bool(getattr(mail, "is_starred", False))
        self._emit_star(ids, target)

    def _delete_selected(self) -> None:
        ids = self.selected_ids()
        if ids:
            self.delete_many_requested.emit(ids)

    def _on_header_clicked(self, section: int) -> None:
        field = {COL_SENDER: "sender", COL_SUBJECT: "subject",
                 COL_TIME: "time", COL_PLATFORM: "platform"}.get(section)
        if field:
            self._on_sort(field, field == "time", toggle=True)

    def _on_sort(self, field: str, descending: bool, *, toggle: bool = False) -> None:
        current_key, current_desc = self.model.sort_state
        if toggle and current_key == field:
            descending = not current_desc
        self.model.sort_by(field, descending)

    def _on_view_mode(self, mode: str) -> None:
        self.toolbar.set_view_mode(mode)

    # ------------------------------------------------------------ 批量
    def _emit_read(self, ids: list[str], is_read: bool) -> None:
        if ids:
            self.mark_read_many_requested.emit(ids, is_read)

    def _emit_star(self, ids: list[str], starred: bool) -> None:
        if ids:
            self.star_many_requested.emit(ids, starred)

    def _on_batch(self, action: str) -> None:
        ids = self.selected_ids()
        if not ids:
            self.notice.emit("请先选择邮件（点击行，或 Ctrl/Shift 多选）")
            return
        if action == "read":
            self._emit_read(ids, True)
        elif action == "unread":
            self._emit_read(ids, False)
        elif action == "star":
            self._emit_star(ids, True)
        elif action == "unstar":
            self._emit_star(ids, False)
        elif action == "delete":
            self.delete_many_requested.emit(ids)

    def _export(self, kind: str) -> None:
        ids = self.selected_ids()
        if not ids and kind != "csv":
            self.notice.emit("请先选择要导出的邮件")
            return
        self.export_requested.emit(kind, ids)

    # ------------------------------------------------------------ 右键
    def _on_context_menu(self, pos) -> None:
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        # 右键点未选中行 → 先把选中切到这一行（符合常见客户端的直觉）
        if index.row() not in {i.row() for i in self.table.selectionModel().selectedRows()}:
            self.table.selectRow(index.row())
            self.table.setCurrentIndex(index)
        self._sync_selection_label()

        ids = self.selected_ids()
        mail = self.model.mail_at(index.row())
        if mail is None:
            return
        is_thread = self.model.is_thread_head(index.row())
        total = index.data(ROLE_THREAD_TOTAL) or 1

        menu = QMenu(self)
        scope = f"{len(ids)} 封" if len(ids) > 1 else ""

        if is_thread and total > 1:
            key = self.model.thread_key_at(index.row())
            expanded = bool(key in self.model.expanded_threads)
            act_thread = menu.addAction("收起会话" if expanded else "展开会话")
            menu.addSeparator()
        else:
            act_thread = None

        act_toggle = menu.addAction(
            f"标为未读{scope}" if mail.is_read else f"标为已读{scope}")
        starred = bool(getattr(mail, "is_starred", False))
        act_star = menu.addAction(f"取消星标{scope}" if starred else f"加星标{scope}")
        menu.addSeparator()

        act_open = menu.addAction("在新窗口打开…")
        act_copy = menu.addAction("复制主题")
        menu.addSeparator()

        sub_export = menu.addMenu("导出")
        act_eml = sub_export.addAction("导出为 .eml（单封）")
        act_mbox = sub_export.addAction(".mbox 归档（多封）")
        act_csv = sub_export.addAction("CSV 清单（当前筛选）")

        menu.addSeparator()
        act_delete = menu.addAction(f"删除本地副本{scope}")

        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen is None:
            return
        if act_thread is not None and chosen == act_thread:
            self._toggle_thread_row(index.row())
        elif chosen == act_toggle:
            self._emit_read(ids, not mail.is_read)
        elif chosen == act_star:
            self._emit_star(ids, not starred)
        elif chosen == act_open:
            self.mail_activated.emit(mail.id)
        elif chosen == act_copy:
            from PySide6.QtWidgets import QApplication
            QApplication.clipboard().setText(mail.subject or "")
        elif chosen == act_eml:
            self.export_requested.emit("eml", ids[:1])
        elif chosen == act_mbox:
            self.export_requested.emit("mbox", ids)
        elif chosen == act_csv:
            self.export_requested.emit("csv", ids)
        elif chosen == act_delete:
            self.delete_many_requested.emit(ids)

    # ------------------------------------------------------------ 键盘兜底
    def keyPressEvent(self, event) -> None:
        """表格之外的区域（如工具栏）也响应 J/K。

        `QShortcut` 只在表格获得焦点时生效；用户点过工具栏后焦点会跑掉，
        此时 J/K 应当仍然可用——这是「肌肉记忆」是否被守住的分界线。
        """
        key = event.key()
        mods = event.modifiers()
        if mods in (Qt.NoModifier, Qt.ShiftModifier):
            if key == Qt.Key_J:
                (self.extend_selection if mods == Qt.ShiftModifier
                 else self.move_cursor)(1)
                return
            if key == Qt.Key_K:
                (self.extend_selection if mods == Qt.ShiftModifier
                 else self.move_cursor)(-1)
                return
        super().keyPressEvent(event)


__all__ = ["EmptyState", "InboxPanel", "InboxToolbar"]

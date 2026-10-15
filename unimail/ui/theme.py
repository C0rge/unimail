"""深色主题样式表与配色常量。"""
from __future__ import annotations

# 配色（深色主题）
BG = "#0f1216"
BG_PANEL = "#161b22"
BG_ELEV = "#1c2230"
BG_HOVER = "#232b3a"
BORDER = "#2a3242"
TEXT = "#e6edf3"
TEXT_DIM = "#8b98a9"
TEXT_FAINT = "#5d6b7d"
ACCENT = "#4c8dff"
ACCENT_DIM = "#2d5aa8"
UNREAD = "#4c8dff"
DANGER = "#f2545b"
SUCCESS = "#3fb950"

FONT_UI = '"Microsoft YaHei UI", "Segoe UI", "PingFang SC", sans-serif'


STYLESHEET = f"""
* {{
    font-family: {FONT_UI};
    font-size: 13px;
    color: {TEXT};
}}
QWidget {{
    background: {BG};
}}
QMainWindow, QDialog {{
    background: {BG};
}}

/* ---------------------------------------------------- 通用面板 */
QFrame#Panel {{
    background: {BG_PANEL};
    border: none;
}}
QFrame#Sidebar {{
    background: {BG_PANEL};
    border-right: 1px solid {BORDER};
}}
QFrame#DetailPane {{
    background: {BG_PANEL};
    border-left: 1px solid {BORDER};
}}

/* ---------------------------------------------------- 标题 */
QLabel#AppTitle {{
    font-size: 16px;
    font-weight: 600;
    padding: 14px 16px 6px 16px;
    color: {TEXT};
}}
QLabel#SectionTitle {{
    font-size: 12px;
    font-weight: 600;
    color: {TEXT_FAINT};
    padding: 14px 16px 6px 16px;
    letter-spacing: 0.5px;
}}
QLabel#DetailSubject {{
    font-size: 17px;
    font-weight: 600;
    color: {TEXT};
}}
QLabel#DetailMeta {{
    color: {TEXT_DIM};
    font-size: 12px;
}}
QLabel#StatusBar {{
    color: {TEXT_DIM};
    font-size: 12px;
    padding: 0 10px;
}}

/* ---------------------------------------------------- 按钮 */
QPushButton {{
    background: {BG_ELEV};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 7px 14px;
    color: {TEXT};
}}
QPushButton:hover {{
    background: {BG_HOVER};
    border-color: {ACCENT_DIM};
}}
QPushButton:pressed {{
    background: {ACCENT_DIM};
}}
QPushButton#Primary {{
    background: {ACCENT};
    border: none;
    color: #ffffff;
    font-weight: 600;
}}
QPushButton#Primary:hover {{
    background: #5d99ff;
}}
QPushButton#Primary:disabled {{
    background: {BG_ELEV};
    color: {TEXT_FAINT};
}}
QPushButton#Ghost {{
    background: transparent;
    border: 1px solid {BORDER};
    color: {TEXT_DIM};
    padding: 5px 10px;
}}
QPushButton#Ghost:hover {{
    color: {TEXT};
    border-color: {ACCENT_DIM};
}}
QPushButton#Danger {{
    background: transparent;
    border: 1px solid {DANGER};
    color: {DANGER};
}}
QPushButton#Danger:hover {{
    background: {DANGER};
    color: #ffffff;
}}

/* ---------------------------------------------------- 输入 */
QLineEdit, QComboBox, QSpinBox, QDateTimeEdit {{
    background: {BG_ELEV};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 7px 10px;
    selection-background-color: {ACCENT};
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDateTimeEdit:focus {{
    border-color: {ACCENT};
}}
QLineEdit#SearchBox {{
    padding-left: 10px;
}}
QComboBox::drop-down {{
    border: none;
    width: 22px;
}}
QComboBox QAbstractItemView {{
    background: {BG_ELEV};
    border: 1px solid {BORDER};
    selection-background-color: {ACCENT_DIM};
    outline: none;
}}

/* ---------------------------------------------------- 列表 / 树 */
QListWidget, QTreeWidget {{
    background: transparent;
    border: none;
    outline: none;
    padding: 4px 8px;
}}
QListWidget::item {{
    padding: 9px 12px;
    border-radius: 6px;
    margin: 1px 0;
    color: {TEXT};
}}
QListWidget::item:hover {{
    background: {BG_HOVER};
}}
QListWidget::item:selected {{
    background: {ACCENT_DIM};
    color: #ffffff;
}}

/* ---------------------------------------------------- 表格（收件箱） */
QTableView {{
    background: transparent;
    border: none;
    outline: none;
    gridline-color: transparent;
    selection-background-color: {BG_HOVER};
}}
QTableView::item {{
    padding: 8px 6px;
    border-bottom: 1px solid {BORDER};
}}
QTableView::item:hover {{
    background: {BG_HOVER};
}}
QTableView::item:selected {{
    background: {ACCENT_DIM};
    color: #ffffff;
}}
QHeaderView::section {{
    background: {BG_PANEL};
    color: {TEXT_FAINT};
    border: none;
    border-bottom: 1px solid {BORDER};
    padding: 8px 6px;
    font-size: 12px;
    font-weight: 600;
}}

/* ---------------------------------------------------- 滚动条 */
QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {BORDER};
    border-radius: 5px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{
    background: {TEXT_FAINT};
}}
QScrollBar::add-line, QScrollBar::sub-line {{
    height: 0; width: 0;
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
}}
QScrollBar::handle:horizontal {{
    background: {BORDER};
    border-radius: 5px;
    min-width: 30px;
}}

/* ---------------------------------------------------- 分割条 */
QSplitter::handle {{
    background: {BORDER};
}}
QSplitter::handle:hover {{
    background: {ACCENT_DIM};
}}

/* ---------------------------------------------------- 文本浏览区 */
QTextBrowser {{
    background: {BG_PANEL};
    border: none;
    padding: 4px 8px;
}}

/* ---------------------------------------------------- 标签 */
QTabWidget::pane {{
    border: none;
}}
QTabBar::tab {{
    background: transparent;
    color: {TEXT_DIM};
    padding: 7px 14px;
    border-bottom: 2px solid transparent;
}}
QTabBar::tab:selected {{
    color: {TEXT};
    border-bottom: 2px solid {ACCENT};
}}

/* ---------------------------------------------------- 其他 */
QCheckBox {{
    spacing: 7px;
    color: {TEXT_DIM};
}}
QCheckBox::indicator {{
    width: 15px; height: 15px;
    border: 1px solid {BORDER};
    border-radius: 3px;
    background: {BG_ELEV};
}}
QCheckBox::indicator:checked {{
    background: {ACCENT};
    border-color: {ACCENT};
}}
QToolTip {{
    background: {BG_ELEV};
    color: {TEXT};
    border: 1px solid {BORDER};
    padding: 6px 9px;
    border-radius: 4px;
}}
QLabel#Hint {{
    color: {TEXT_FAINT};
    font-size: 12px;
}}
QLabel#Badge {{
    color: {TEXT_DIM};
    background: {BG_ELEV};
    border-radius: 9px;
    padding: 1px 7px;
    font-size: 11px;
}}
QLabel#EmptyTitle {{
    color: {TEXT_DIM};
    font-size: 15px;
}}
QLabel#EmptyHint {{
    color: {TEXT_FAINT};
    font-size: 12px;
}}
"""

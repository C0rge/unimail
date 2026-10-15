"""界面设计基座：设计令牌（design token）+ 深浅双主题 + 跟随系统。

为什么要做「令牌化」而不是继续堆一坨字符串
------------------------------------------
改造前这里是一个 300 行的 `STYLESHEET` 常量，颜色是**直接写死**在规则里的
（`color: #e6edf3;`）。带来三个具体问题：

1. **加不了浅色主题。** 想换主题就得把整段样式复制一遍再逐个改色值，
   两份样式表必然随时间漂移（改了深色忘了浅色）。
2. **颜色散落在各处。** 模型层用 `QColor("#4c8dff")`、详情面板用
   `#2a3242`，主题一换就出现「浅色背景上的深色文字」这类看不见的 bug。
   现在所有颜色只有一个来源：`Palette`。
3. **换算不了字号。** 「字号 110%」在一份写死 px 的样式表里无法实现，
   只能正则替换，且 13→14.3px 这种非整数值会连带影响行高。

因此改成：**令牌定义 → 样式表由令牌生成**。`build_stylesheet(palette, scale)`
是纯函数（同样的输入永远给出同样的输出），可以直接在测试里断言。

主题解析
--------
用户设置里存的是 `theme_mode`（system / dark / light）三种意图之一。
`resolve_theme()` 负责把「跟随系统」解析成具体的调色板——**解析只在应用时做一次**，
不在样式表里做条件判断，这样样式表本身始终是一份确定性的产物。
"""
from __future__ import annotations

import logging
import sys
from dataclasses import dataclass

from PySide6.QtCore import QObject, Signal

log = logging.getLogger(__name__)

# ---------------------------------------------------------------- 尺寸令牌
# 间距用 4 的倍数：跨平台下 4px 网格不会出现半像素对齐导致的模糊边框。
SPACE = {"xs": 4, "sm": 8, "md": 12, "lg": 16, "xl": 24, "xxl": 32}
RADIUS = {"sm": 4, "md": 6, "lg": 10, "pill": 999}

# 字级（相对基准 13px 的比例）。列表正文 1.0，时间戳等次要信息 0.92。
FONT_STEPS = {
    "tiny": 0.85,
    "small": 0.92,
    "body": 1.0,
    "title": 1.23,
    "display": 1.45,
}
BASE_FONT_PX = 13

# 合法字号缩放档位（与 settings.FONT_SCALES 保持一致，这里再收口一次）
FONT_SCALES = (0.9, 1.0, 1.1, 1.25)


def font_px(step: str, scale: float = 1.0) -> int:
    """给出某字级在当前缩放下的整数像素值。

    必须取整：Qt 的样式表对 `13.0000001px` 这类值的处理是截断，
    不同 DPI 下截断方向可能不同，导致同一份样式在不同机器上看起来差一档。
    """
    ratio = FONT_STEPS.get(step, 1.0)
    return max(9, round(BASE_FONT_PX * ratio * scale))


# ---------------------------------------------------------------- 调色板
@dataclass(frozen=True)
class Palette:
    """一套完整的语义配色。

    字段是**语义**而非外观（`bg_elev` 而不是 `gray800`）：
    浅色主题下「抬升层」是更白而不是更黑，用外观命名会让映射关系错乱。
    """
    name: str
    bg: str                 # 窗口底色
    bg_panel: str           # 面板/侧栏底色
    bg_elev: str            # 输入框、按钮等抬升控件底色
    bg_hover: str           # 悬停态
    bg_active: str          # 按下/选中态
    border: str
    border_strong: str
    text: str
    text_dim: str
    text_faint: str
    accent: str
    accent_hover: str
    accent_dim: str
    on_accent: str          # 铺在 accent 上的文字颜色
    unread: str
    danger: str
    success: str
    warning: str
    selection_bg: str
    selection_fg: str
    scrollbar: str
    scrollbar_hover: str
    bubble_in: str = ""     # 会话气泡（收到的）
    bubble_out: str = ""    # 会话气泡（自己发的）
    overlay: str = "rgba(0, 0, 0, 255)"   # 锁屏遮罩：必须完全不透明

    def qcolor(self, field_name: str) -> str:
        """按字段名取色，供模型层（`QColor(...)`）使用，避免各处再写死色值。"""
        return str(getattr(self, field_name, self.text))

    def to_dict(self) -> dict[str, str]:
        """导出成字典给 UI 组件用（模型/委托/托盘都按名字取色）。

        额外补两个非字段键：
        * `highlight` —— 搜索命中高亮的底色。深色主题上不能用亮黄，
          否则整行看起来像被选中；浅色主题上又必须够亮才看得见。
        * `_dark` —— 供 `palette_foreground()` 判断该提亮还是压暗，
          而不必让每个调用方再去问一次「现在是哪个主题」。
        """
        data = {
            f: str(getattr(self, f))
            for f in self.__dataclass_fields__
            if isinstance(getattr(self, f), str)
        }
        data["highlight"] = "#7a6520" if self.name == "dark" else "#ffe08a"
        data["_dark"] = "1" if self.name == "dark" else "0"
        return data


DARK = Palette(
    name="dark",
    bg="#0f1216",
    bg_panel="#161b22",
    bg_elev="#1c2230",
    bg_hover="#232b3a",
    bg_active="#2b3446",
    border="#2a3242",
    border_strong="#3a4557",
    text="#e6edf3",
    text_dim="#8b98a9",
    text_faint="#5d6b7d",
    accent="#4c8dff",
    accent_hover="#6ba1ff",
    accent_dim="#2d5aa8",
    on_accent="#ffffff",
    unread="#4c8dff",
    danger="#f2545b",
    success="#3fb950",
    warning="#d29922",
    selection_bg="#2d5aa8",
    selection_fg="#ffffff",
    scrollbar="#2a3242",
    scrollbar_hover="#5d6b7d",
    bubble_in="#1c2230",
    bubble_out="#243a63",
    overlay="rgba(15, 18, 22, 255)",
)

LIGHT = Palette(
    name="light",
    bg="#f6f7f9",
    bg_panel="#ffffff",
    bg_elev="#ffffff",
    bg_hover="#eef1f6",
    bg_active="#e2e7f0",
    border="#dfe3ea",
    border_strong="#c3cad6",
    text="#1b2230",
    text_dim="#5a6478",
    text_faint="#8b93a3",
    accent="#2f6feb",
    accent_hover="#1f5fdc",
    accent_dim="#b9cdf7",
    on_accent="#ffffff",
    unread="#2f6feb",
    danger="#d1242f",
    success="#1a7f37",
    warning="#9a6700",
    selection_bg="#d7e4fd",
    selection_fg="#12203a",
    scrollbar="#ccd2dc",
    scrollbar_hover="#9aa4b5",
    bubble_in="#eef1f6",
    bubble_out="#d7e4fd",
    overlay="rgba(246, 247, 249, 255)",
)

PALETTES = {p.name: p for p in (DARK, LIGHT)}
DEFAULT_PALETTE = DARK


def palette_for(name: str) -> Palette:
    return PALETTES.get(name, DEFAULT_PALETTE)


# ---------------------------------------------------------------- 系统检测
def detect_system_theme() -> str:
    """判断操作系统当前是深色还是浅色。

    Windows：读注册表 `AppsUseLightTheme`（0 = 深色）。这是唯一可靠的来源——
    桌面环境的其它信号（`COLOR_WINDOW` 系统色）在 Windows 11 上仍返回浅色值，
    与实际设置无关。
    macOS：`defaults read -g AppleInterfaceStyle`，输出 `Dark` 表示深色。
    Linux：没有跨桌面统一接口，退化为「跟随应用的浅色」，并允许用户在设置里覆盖。
    """
    try:
        if sys.platform == "win32":
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            )
            try:
                value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            finally:
                winreg.CloseKey(key)
            return "light" if int(value) else "dark"
        if sys.platform == "darwin":
            import subprocess
            out = subprocess.run(
                ["defaults", "read", "-g", "AppleInterfaceStyle"],
                capture_output=True, text=True, timeout=2, check=False,
            )
            return "dark" if "dark" in (out.stdout or "").lower() else "light"
    except Exception:
        log.debug("系统主题检测失败，沿用默认主题", exc_info=True)
    return "dark"


def resolve_theme_mode(mode: str) -> str:
    """把用户意图（system/dark/light）解析为具体主题名。"""
    if mode in ("dark", "light"):
        return mode
    return detect_system_theme()


# ---------------------------------------------------------------- 样式生成
def build_stylesheet(palette: Palette | None = None, scale: float = 1.0) -> str:
    """由调色板 + 字号缩放生成完整 QSS。

    纯函数：不读全局状态、不碰 Qt，因此可以单测。
    """
    p = palette or DEFAULT_PALETTE
    if scale not in FONT_SCALES:
        scale = 1.0

    body = font_px("body", scale)
    small = font_px("small", scale)
    tiny = font_px("tiny", scale)
    title = font_px("title", scale)
    display = font_px("display", scale)

    ui_font = ('"Microsoft YaHei UI", "Segoe UI", "PingFang SC", '
               '"Noto Sans CJK SC", sans-serif')
    mono = '"Cascadia Mono", "Consolas", "SF Mono", monospace'

    return f"""
/* ============================================================ 全局 */
* {{
    font-family: {ui_font};
    font-size: {body}px;
    color: {p.text};
}}
QWidget {{
    background: {p.bg};
}}
QMainWindow, QDialog {{
    background: {p.bg};
}}
QToolTip {{
    background: {p.bg_elev};
    color: {p.text};
    border: 1px solid {p.border};
    padding: 6px 9px;
    border-radius: {RADIUS['sm']}px;
}}
QLabel {{
    background: transparent;
}}

/* ============================================================ 面板 */
QFrame#Panel {{
    background: {p.bg_panel};
    border: none;
}}
QFrame#Sidebar {{
    background: {p.bg_panel};
    border-right: 1px solid {p.border};
}}
QFrame#DetailPane {{
    background: {p.bg_panel};
    border-left: 1px solid {p.border};
}}
QFrame#Card {{
    background: {p.bg_elev};
    border: 1px solid {p.border};
    border-radius: {RADIUS['md']}px;
}}
QFrame#Divider {{
    background: {p.border};
    max-height: 1px;
    border: none;
}}

/* ============================================================ 文字层级 */
QLabel#AppTitle {{
    font-size: {title}px;
    font-weight: 600;
    padding: {SPACE['lg']}px {SPACE['lg']}px {SPACE['xs']}px {SPACE['lg']}px;
    color: {p.text};
}}
QLabel#SectionTitle {{
    font-size: {small}px;
    font-weight: 600;
    color: {p.text_faint};
    padding: {SPACE['lg']}px {SPACE['lg']}px {SPACE['xs']}px {SPACE['lg']}px;
    letter-spacing: 0.5px;
}}
QLabel#DetailSubject {{
    font-size: {title}px;
    font-weight: 600;
    color: {p.text};
}}
QLabel#DetailMeta {{
    color: {p.text_dim};
    font-size: {small}px;
}}
QLabel#StatusBar {{
    color: {p.text_dim};
    font-size: {small}px;
    padding: 0 10px;
}}
QLabel#Hint {{
    color: {p.text_faint};
    font-size: {small}px;
}}
QLabel#EmptyTitle {{
    color: {p.text_dim};
    font-size: {display}px;
}}
QLabel#EmptyHint {{
    color: {p.text_faint};
    font-size: {small}px;
}}
QLabel#Badge {{
    color: {p.text_dim};
    background: {p.bg_elev};
    border: 1px solid {p.border};
    border-radius: {RADIUS['pill']}px;
    padding: 1px 7px;
    font-size: {tiny}px;
}}
QLabel#Chip {{
    color: {p.text_dim};
    background: {p.bg_hover};
    border-radius: {RADIUS['sm']}px;
    padding: 2px 8px;
    font-size: {tiny}px;
}}
QLabel#Avatar {{
    color: {p.on_accent};
    background: {p.accent};
    border-radius: {RADIUS['pill']}px;
    font-size: {title}px;
    font-weight: 600;
}}
QLabel#CountBadge {{
    color: {p.on_accent};
    background: {p.accent};
    border-radius: {RADIUS['pill']}px;
    padding: 0 7px;
    font-size: {tiny}px;
    font-weight: 600;
}}
QLabel#Mono {{
    font-family: {mono};
    font-size: {small}px;
    color: {p.text_dim};
}}
QLabel#Danger {{
    color: {p.danger};
    font-size: {small}px;
}}
QLabel#Warning {{
    color: {p.warning};
    font-size: {small}px;
}}

/* ============================================================ 按钮 */
QPushButton {{
    background: {p.bg_elev};
    border: 1px solid {p.border};
    border-radius: {RADIUS['md']}px;
    padding: 7px 14px;
    color: {p.text};
}}
QPushButton:hover {{
    background: {p.bg_hover};
    border-color: {p.accent_dim};
}}
QPushButton:pressed {{
    background: {p.bg_active};
}}
QPushButton:disabled {{
    color: {p.text_faint};
    background: {p.bg_panel};
}}
QPushButton#Primary {{
    background: {p.accent};
    border: none;
    color: {p.on_accent};
    font-weight: 600;
}}
QPushButton#Primary:hover {{
    background: {p.accent_hover};
}}
QPushButton#Primary:disabled {{
    background: {p.bg_elev};
    color: {p.text_faint};
}}
QPushButton#Ghost {{
    background: transparent;
    border: 1px solid {p.border};
    color: {p.text_dim};
    padding: 5px 10px;
}}
QPushButton#Ghost:hover {{
    color: {p.text};
    border-color: {p.accent_dim};
}}
QPushButton#Danger {{
    background: transparent;
    border: 1px solid {p.danger};
    color: {p.danger};
}}
QPushButton#Danger:hover {{
    background: {p.danger};
    color: {p.on_accent};
}}
QPushButton#IconButton {{
    background: transparent;
    border: none;
    padding: 5px;
    border-radius: {RADIUS['sm']}px;
}}
QPushButton#IconButton:hover {{
    background: {p.bg_hover};
}}
QPushButton#LinkButton {{
    background: transparent;
    border: none;
    color: {p.accent};
    padding: 2px 4px;
    text-align: left;
}}
QPushButton#LinkButton:hover {{
    color: {p.accent_hover};
    text-decoration: underline;
}}

/* ============================================================ 输入 */
QLineEdit, QComboBox, QSpinBox, QDateTimeEdit, QPlainTextEdit, QTextEdit {{
    background: {p.bg_elev};
    border: 1px solid {p.border};
    border-radius: {RADIUS['md']}px;
    padding: 7px 10px;
    selection-background-color: {p.accent};
    selection-color: {p.on_accent};
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus,
QDateTimeEdit:focus, QPlainTextEdit:focus, QTextEdit:focus {{
    border-color: {p.accent};
}}
QLineEdit:disabled, QComboBox:disabled {{
    color: {p.text_faint};
}}
QLineEdit#SearchBox {{
    padding-left: 10px;
}}
QLineEdit#SearchBox[hit="true"] {{
    border-color: {p.accent};
}}
QComboBox::drop-down {{
    border: none;
    width: 22px;
}}
QComboBox QAbstractItemView {{
    background: {p.bg_elev};
    border: 1px solid {p.border};
    selection-background-color: {p.selection_bg};
    selection-color: {p.selection_fg};
    outline: none;
}}

/* ============================================================ 列表 */
QListWidget, QTreeWidget {{
    background: transparent;
    border: none;
    outline: none;
    padding: {SPACE['xs']}px {SPACE['sm']}px;
}}
QListWidget::item {{
    padding: 9px 12px;
    border-radius: {RADIUS['md']}px;
    margin: 1px 0;
    color: {p.text};
}}
QListWidget::item:hover {{
    background: {p.bg_hover};
}}
QListWidget::item:selected {{
    background: {p.selection_bg};
    color: {p.selection_fg};
}}

/* ============================================================ 表格 */
QTableView, QTreeView {{
    background: transparent;
    border: none;
    outline: none;
    gridline-color: transparent;
    selection-background-color: {p.selection_bg};
    selection-color: {p.selection_fg};
    alternate-background-color: {p.bg_panel};
}}
QTableView::item, QTreeView::item {{
    padding: 8px 6px;
    border-bottom: 1px solid {p.border};
}}
QTableView::item:hover, QTreeView::item:hover {{
    background: {p.bg_hover};
}}
QTableView::item:selected, QTreeView::item:selected {{
    background: {p.selection_bg};
    color: {p.selection_fg};
}}
QHeaderView::section {{
    background: {p.bg_panel};
    color: {p.text_faint};
    border: none;
    border-bottom: 1px solid {p.border};
    padding: 8px 6px;
    font-size: {small}px;
    font-weight: 600;
}}
QHeaderView::section:hover {{
    color: {p.text_dim};
}}
QTreeView::branch:has-children:closed {{
    background: transparent;
}}

/* ============================================================ 滚动条 */
QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {p.scrollbar};
    border-radius: 5px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{
    background: {p.scrollbar_hover};
}}
QScrollBar::add-line, QScrollBar::sub-line {{
    height: 0; width: 0;
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
}}
QScrollBar::handle:horizontal {{
    background: {p.scrollbar};
    border-radius: 5px;
    min-width: 30px;
}}
QScrollArea {{
    background: transparent;
    border: none;
}}

/* ============================================================ 分割条 */
QSplitter::handle {{
    background: {p.border};
}}
QSplitter::handle:hover {{
    background: {p.accent_dim};
}}

/* ============================================================ 正文 */
QTextBrowser {{
    background: {p.bg_panel};
    border: none;
    padding: 4px 8px;
    selection-background-color: {p.accent};
    selection-color: {p.on_accent};
}}

/* ============================================================ 标签页 */
QTabWidget::pane {{
    border: none;
    background: transparent;
}}
QTabBar::tab {{
    background: transparent;
    color: {p.text_dim};
    padding: 7px 14px;
    border-bottom: 2px solid transparent;
}}
QTabBar::tab:hover {{
    color: {p.text};
}}
QTabBar::tab:selected {{
    color: {p.text};
    border-bottom: 2px solid {p.accent};
}}

/* ============================================================ 勾选 */
QCheckBox, QRadioButton {{
    spacing: 7px;
    color: {p.text_dim};
    background: transparent;
}}
QCheckBox::indicator, QRadioButton::indicator {{
    width: 15px; height: 15px;
    border: 1px solid {p.border_strong};
    border-radius: 3px;
    background: {p.bg_elev};
}}
QRadioButton::indicator {{
    border-radius: 8px;
}}
QCheckBox::indicator:checked {{
    background: {p.accent};
    border-color: {p.accent};
}}
QRadioButton::indicator:checked {{
    background: {p.accent};
    border: 4px solid {p.bg_elev};
}}
QCheckBox::indicator:disabled, QRadioButton::indicator:disabled {{
    background: {p.bg_panel};
}}

/* ============================================================ 菜单 */
QMenu {{
    background: {p.bg_elev};
    border: 1px solid {p.border};
    border-radius: {RADIUS['md']}px;
    padding: 5px;
}}
QMenu::item {{
    padding: 7px 22px 7px 12px;
    border-radius: {RADIUS['sm']}px;
    color: {p.text};
}}
QMenu::item:selected {{
    background: {p.selection_bg};
    color: {p.selection_fg};
}}
QMenu::item:disabled {{
    color: {p.text_faint};
}}
QMenu::separator {{
    height: 1px;
    background: {p.border};
    margin: 4px 8px;
}}
QMenuBar {{
    background: {p.bg_panel};
    border-bottom: 1px solid {p.border};
}}
QMenuBar::item {{
    padding: 6px 11px;
    background: transparent;
}}
QMenuBar::item:selected {{
    background: {p.bg_hover};
    border-radius: {RADIUS['sm']}px;
}}
QMenuBar::item:pressed {{
    background: {p.bg_active};
}}

/* ============================================================ 状态栏 */
QStatusBar {{
    background: {p.bg_panel};
    border-top: 1px solid {p.border};
    color: {p.text_dim};
}}
QStatusBar::item {{
    border: none;
}}

/* ============================================================ 进度 */
QProgressBar {{
    background: {p.bg_elev};
    border: none;
    border-radius: 3px;
    height: 6px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background: {p.accent};
    border-radius: 3px;
}}
QProgressBar#Indeterminate::chunk {{
    background: {p.accent_dim};
}}

/* ============================================================ 遮罩 */
QWidget#LockOverlay {{
    background: {p.overlay};
}}
QFrame#LockCard {{
    background: {p.bg_panel};
    border: 1px solid {p.border};
    border-radius: {RADIUS['lg']}px;
}}
QFrame#Card#Toast {{
    background: {p.bg_elev};
    border: 1px solid {p.border_strong};
}}

/* ============================================================ 工具 */
QToolBar {{
    background: {p.bg_panel};
    border: none;
    spacing: 4px;
}}
QGroupBox {{
    border: 1px solid {p.border};
    border-radius: {RADIUS['md']}px;
    margin-top: 10px;
    padding-top: 8px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
    color: {p.text_dim};
}}
QSlider::groove:horizontal {{
    background: {p.border};
    height: 4px;
    border-radius: 2px;
}}
QSlider::handle:horizontal {{
    background: {p.accent};
    width: 14px;
    margin: -6px 0;
    border-radius: 7px;
}}
"""


# ---------------------------------------------------------------- 主题管理
class ThemeManager(QObject):
    """持有当前调色板，负责生成并下发样式表。

    为什么是一个对象而不是模块级函数：主题需要**在运行时变化**
    （设置里切换、系统主题改变），而收到变化的组件不止一个——主窗口要重绘
    已经按旧色值画好的自定义控件。集中在一处可以避免「样式表换了但
    模型里的 QColor 还是旧值」这种半新半旧的状态。
    """

    changed = Signal()

    def __init__(self, mode: str = "system", scale: float = 1.0) -> None:
        super().__init__()
        self._mode = mode
        self._scale = scale
        self._palette = palette_for(resolve_theme_mode(mode))

    # -------------------------------------------------------- 状态
    @property
    def mode(self) -> str:
        return self._mode

    @property
    def scale(self) -> float:
        return self._scale

    @property
    def palette(self) -> Palette:
        return self._palette

    @property
    def is_dark(self) -> bool:
        return self._palette.name == "dark"

    def color(self, token: str) -> str:
        return self._palette.qcolor(token)

    def palette_dict(self) -> dict[str, str]:
        return self._palette.to_dict()

    # -------------------------------------------------------- 变更
    def set_mode(self, mode: str) -> None:
        if mode == self._mode:
            return
        self._mode = mode
        self._refresh()

    def set_scale(self, scale: float) -> None:
        if scale == self._scale:
            return
        self._scale = scale
        self._refresh()

    def refresh_system(self) -> None:
        """系统主题变化时调用（`system` 模式下才真正改变）。"""
        if self._mode == "system":
            self._refresh()

    def _refresh(self) -> None:
        self._palette = palette_for(resolve_theme_mode(self._mode))
        # 图标位图是按旧色渲染的，必须一并丢弃；否则换主题后按钮上
        # 还是上一套配色的图标（样式表变了、图标没变，最容易被漏掉的一处）。
        from . import icons
        icons.clear_cache()
        self.changed.emit()

    # -------------------------------------------------------- 应用
    def stylesheet(self) -> str:
        return build_stylesheet(self._palette, self._scale)

    def apply(self, app) -> None:
        """把当前主题铺到整个 QApplication 上。"""
        app.setStyleSheet(self.stylesheet())


def apply_theme(app, settings=None) -> ThemeManager:
    """按用户偏好创建并应用主题，返回管理器供后续切换。

    兼容旧调用方式：没有 `settings` 时按默认（跟随系统）。
    """
    mode = getattr(settings, "theme_mode", "system") if settings else "system"
    scale = getattr(settings, "font_scale", 1.0) if settings else 1.0
    manager = ThemeManager(mode, scale)
    manager.apply(app)
    return manager


# ---------------------------------------------------------------- 兼容别名
# 历史代码（main.py）直接引用这两个名字。保留导出，避免为了改调用点而制造
# 一次无意义的全仓改动——真正的入口已经是 `apply_theme`。
BG = DARK.bg
TEXT = DARK.text
STYLESHEET = build_stylesheet(DARK, 1.0)


__all__ = [
    "BASE_FONT_PX",
    "BG",
    "DARK",
    "DEFAULT_PALETTE",
    "FONT_SCALES",
    "FONT_STEPS",
    "LIGHT",
    "PALETTES",
    "RADIUS",
    "SPACE",
    "STYLESHEET",
    "TEXT",
    "Palette",
    "ThemeManager",
    "apply_theme",
    "build_stylesheet",
    "detect_system_theme",
    "font_px",
    "palette_for",
    "resolve_theme_mode",
]

"""应用图标：窗口标题栏、任务栏与托盘共用的一枚标志。

为什么运行时也从 SVG 渲染，而不是直接读 assets/icon.png
-----------------------------------------------------
运行时资产要跟着 `dist/` 走，多一个文件就多一处「打包漏带」的风险
（本项目在 SQLCipher 上已经栽过一次：漏带的依赖不报错，只是静默少一块
能力，而界面上没有任何提示）。`icons.py` 里已经有整套内联 SVG 渲染与缓存
机制，应用标志放进同一套体系，就不存在第二个图标来源。

与 assets/icon.svg 的关系
------------------------
两者是**同一设计的两个载体**，不是两份设计：
  * `assets/icon.svg` —— 512 画布的源文件，由 `tools/make_icon.py` 转成
    `dist/icon.ico`，供 PyInstaller 打进 exe（任务栏 / Alt+Tab / 资源管理器
    用的是它，那是操作系统读 exe 资源，绕不过 Qt）；
  * 本模块 —— 同一造型在 Qt 侧的复用：窗口标题栏与托盘。两者几何完全一致，
    只是这里按 `icons.py` 的 24×24 视窗 + 主题取色重写，好让颜色跟随
    当前主题的 `accent`。

**改设计要同时改这两处**，否则会出现「窗口图标和任务栏图标不一样」的分裂。
`assets/README.md` 记录了设计依据。
"""
from __future__ import annotations

from PySide6.QtGui import QIcon

from . import icons

# 应用标志：层叠信封。按 icons.py 的 24×24 视窗与 1.8px 描边语言重画
# assets/icon.svg（512 画布 / 30px 描边）——等比缩放，几何关系保持一致。
#
# 顶层填充、下两层描边递减透明度：填充层在 16px 下仍是一块可辨的实体，
# 描边层提供「层叠」的层次感。三个圆点是「未读」语义，也让顶层不是死板的色块。
_APP_ICON_PATHS = (
    '<rect x="4.5" y="9.4" width="12" height="9" rx="2.4" fill="none" stroke="{c}" '
    'stroke-width="1.8" opacity="0.45"/>'
    '<rect x="5.25" y="8.25" width="12" height="9" rx="2.4" fill="none" stroke="{c}" '
    'stroke-width="1.8" opacity="0.7"/>'
    '<rect x="6" y="7.2" width="12" height="9" rx="2.4" fill="{c}"/>'
    '<circle cx="9" cy="10.2" r="0.85" fill="#ffffff" opacity="0.95"/>'
    '<circle cx="12" cy="10.2" r="0.85" fill="#ffffff" opacity="0.95"/>'
    '<circle cx="15" cy="10.2" r="0.85" fill="#ffffff" opacity="0.95"/>'
)


def _register() -> None:
    """把应用标志登记进 `icons.py` 的表（只做一次）。

    直接改 `icons._PATHS` 而不是在 `icons.py` 里加条目：那里是**界面控件**
    图标集（49 个，语义是操作而非身份），应用标志的身份不同。放进来会让
    「界面图标」与「应用身份」混为一谈，且该字典的键名空间会被应用标志占用。
    """
    if "app-logo" not in icons._PATHS:      # noqa: SLF001
        icons._PATHS["app-logo"] = _APP_ICON_PATHS   # noqa: SLF001


def app_icon(color: str, size: int = 32) -> QIcon:
    """取应用标志（按主题色渲染）。`size` 是逻辑像素，Qt 会自行按 DPR 放大。"""
    _register()
    return icons.icon("app-logo", color, size)


__all__ = ["app_icon"]

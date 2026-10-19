"""内联 SVG 图标集：不依赖字体、不依赖外部资源，单一来源可着色。

为什么自己画而不是用 emoji / 图标字体
-------------------------------------
1. **emoji 渲染不可控。** 项目里原有 `📎` `🔒` `⚠️` 这类字符，在 Windows 是
   Segoe UI Emoji（彩色、尺寸跳变、与 13px 正文对不齐），在 macOS 是
   Apple Color Emoji（又一套尺寸），Linux 上可能直接缺字形变成豆腐块。
   做主题化界面时它们还会无视文字颜色——浅色主题下 `🔒` 依然是白锁。
2. **图标字体要额外分发字体文件。** 打包体积 + 授权 + 首次渲染的字形回退延迟。
3. **SVG 可以跟随主题换色。** 这里所有图标都是单色路径，颜色在渲染时注入，
   深浅主题各自取自己的 `text_dim` / `text` / `accent`，永远协调。

缓存
----
`QIcon` 的构造有实打实的开销（解析 SVG + 光栅化）。列表每行都要画图标，
不缓存的话滚动会明显掉帧。缓存键是 `(名称, 颜色, 尺寸, DPR)`——
把 DPR 放进键里，才能在「用户把窗口拖到另一块缩放不同的显示器上」时
拿到正确分辨率的位图，而不是一直用第一块屏幕的低清版本。
"""
from __future__ import annotations

import contextlib

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

# 全部图标按 24×24 视窗绘制，线条统一 1.8px、圆头圆角，
# 这样在任何尺寸下缩放的观感一致（不会出现某个图标看起来更粗）。
_STROKE = (
    'fill="none" stroke="{c}" stroke-width="1.8" '
    'stroke-linecap="round" stroke-linejoin="round"'
)
_FILL = 'fill="{c}" stroke="none"'

_PATHS: dict[str, str] = {
    # ---------------------------------------------------------- 邮件
    "inbox": '<path d="M4 13h4l1.6 2.4h4.8L16 13h4" {s}/>'
             '<path d="M4 13 6.4 5.6A1.6 1.6 0 0 1 7.9 4.5h8.2a1.6 1.6 0 0 1 1.5 1.1L20 13v4.4'
             'A1.6 1.6 0 0 1 18.4 19H5.6A1.6 1.6 0 0 1 4 17.4Z" {s}/>',
    "mail": '<rect x="3" y="5" width="18" height="14" rx="2.2" {s}/>'
            '<path d="m3.8 7 7.1 5.2a2 2 0 0 0 2.2 0L20.2 7" {s}/>',
    "mail-open": '<path d="M3 10.4 12 4l9 6.4V19a1.6 1.6 0 0 1-1.6 1.6H4.6A1.6 1.6 0 0 1 3 19Z" {s}/>'
                 '<path d="M3 10.4V8.2L12 2l9 6.2v2.2" {s}/>',
    "reply": '<path d="M9 7 4 11.5 9 16" {s}/><path d="M4 11.5h9.5a6 6 0 0 1 6 6v1" {s}/>',
    "forward": '<path d="m15 7 5 4.5-5 4.5" {s}/><path d="M20 11.5h-9.5a6 6 0 0 0-6 6v1" {s}/>',
    "trash": '<path d="M4 7h16" {s}/><path d="M9.5 7V5.2A1.2 1.2 0 0 1 10.7 4h2.6a1.2 1.2 0 0 1 1.2 1.2V7" {s}/>'
             '<path d="M6.4 7 7.3 19a1.4 1.4 0 0 0 1.4 1.3h6.6A1.4 1.4 0 0 0 16.7 19L17.6 7" {s}/>'
             '<path d="M10.5 11v5.4M13.5 11v5.4" {s}/>',
    "archive": '<rect x="3" y="4.5" width="18" height="4.5" rx="1.4" {s}/>'
               '<path d="M4.8 9v9.4A1.6 1.6 0 0 0 6.4 20h11.2a1.6 1.6 0 0 0 1.6-1.6V9" {s}/>'
               '<path d="M10 13h4" {s}/>',
    "paperclip": '<path d="M19.5 11.2 12 18.7a4.6 4.6 0 0 1-6.5-6.5l8-8a3.1 3.1 0 0 1 4.4 4.4l-7.7 7.7'
                 'a1.6 1.6 0 0 1-2.2-2.2l6.6-6.6" {s}/>',
    "download": '<path d="M12 4v10.5" {s}/><path d="m7.8 10.5 4.2 4.2 4.2-4.2" {s}/>'
                '<path d="M4.5 18.5h15" {s}/>',
    "export": '<path d="M12 20V9.5" {s}/><path d="m7.8 13.7 4.2-4.2 4.2 4.2" {s}/>'
              '<path d="M4.5 5.5h15" {s}/>',
    "image": '<rect x="3" y="5" width="18" height="14" rx="2.2" {s}/>'
             '<circle cx="8.6" cy="10.2" r="1.6" {s}/>'
             '<path d="m4 17.5 4.6-4.3a1.6 1.6 0 0 1 2.2 0l3.4 3.2a1.6 1.6 0 0 0 2.2 0l3.4-3.1" {s}/>',
    "file": '<path d="M13.5 3.5H7a1.8 1.8 0 0 0-1.8 1.8v13.4A1.8 1.8 0 0 0 7 20.5h10a1.8 1.8 0 0 0 1.8-1.8V8.8Z" {s}/>'
            '<path d="M13.5 3.5v4.4a1 1 0 0 0 1 1h4.3" {s}/>',

    # ---------------------------------------------------------- 状态
    "star": '<path d="m12 3.6 2.6 5.3 5.9.86-4.25 4.14 1 5.86L12 17.1l-5.25 2.66 1-5.86L3.5 9.76l5.9-.86Z" {s}/>',
    "star-filled": '<path d="m12 3.6 2.6 5.3 5.9.86-4.25 4.14 1 5.86L12 17.1l-5.25 2.66 1-5.86L3.5 9.76l5.9-.86Z" {f}/>',
    "unread-dot": '<circle cx="12" cy="12" r="4.6" {f}/>',
    "read": '<path d="m5 12.6 4.4 4.4L19 7.4" {s}/>',
    "warning": '<path d="M12 4.2 21 19.4H3Z" {s}/><path d="M12 10v4" {s}/>'
               '<circle cx="12" cy="16.6" r=".9" {f}/>',
    "shield": '<path d="M12 3.5 5 6v6.2c0 4.2 2.9 7.3 7 8.3 4.1-1 7-4.1 7-8.3V6Z" {s}/>'
              '<path d="m9.2 12.2 2 2 3.6-3.9" {s}/>',
    "lock": '<rect x="4.8" y="10.4" width="14.4" height="9.6" rx="2.2" {s}/>'
            '<path d="M8.4 10.4V8a3.6 3.6 0 0 1 7.2 0v2.4" {s}/>'
            '<circle cx="12" cy="15.2" r="1.2" {f}/>',
    "unlock": '<rect x="4.8" y="10.4" width="14.4" height="9.6" rx="2.2" {s}/>'
              '<path d="M8.4 10.4V8a3.6 3.6 0 0 1 7.2 0" {s}/>',
    "key": '<circle cx="8.2" cy="12" r="3.4" {s}/><path d="M11.6 12h9" {s}/>'
           '<path d="M17.4 12v3M20 12v2.2" {s}/>',
    "spinner": '<path d="M12 3.8a8.2 8.2 0 1 0 8.2 8.2" {s}/>',
    "error": '<circle cx="12" cy="12" r="8.4" {s}/><path d="M12 7.8v5.4" {s}/>'
             '<circle cx="12" cy="16.4" r=".9" {f}/>',
    "info": '<circle cx="12" cy="12" r="8.4" {s}/><path d="M12 11v5.4" {s}/>'
            '<circle cx="12" cy="7.9" r=".9" {f}/>',

    # ---------------------------------------------------------- 操作
    "search": '<circle cx="10.8" cy="10.8" r="6.3" {s}/><path d="m15.6 15.6 4.2 4.2" {s}/>',
    "refresh": '<path d="M19.6 9.4A8 8 0 0 0 5.4 7.2" {s}/><path d="M5.4 3.6v3.9h3.9" {s}/>'
               '<path d="M4.4 14.6a8 8 0 0 0 14.2 2.2" {s}/><path d="M18.6 20.4v-3.9h-3.9" {s}/>',
    "settings": '<circle cx="12" cy="12" r="3" {s}/>'
                '<path d="M12 3.4v2M12 18.6v2M20.6 12h-2M5.4 12h-2'
                'M18.1 5.9l-1.5 1.5M7.4 16.6l-1.5 1.5M18.1 18.1l-1.5-1.5M7.4 7.4 5.9 5.9" {s}/>',
    "plus": '<path d="M12 5.5v13M5.5 12h13" {s}/>',
    "close": '<path d="M6.2 6.2 17.8 17.8M17.8 6.2 6.2 17.8" {s}/>',
    "check": '<path d="m5 12.6 4.6 4.6L19 7.6" {s}/>',
    "cancel": '<circle cx="12" cy="12" r="8.4" {s}/><path d="m9 9 6 6M15 9l-6 6" {s}/>',
    "filter": '<path d="M4 6h16M7 12h10M10 18h4" {s}/>',
    "sort": '<path d="M7 4.5v15M7 19.5 3.8 16" {s}/><path d="M17 19.5v-15M17 4.5 20.2 8" {s}/>',
    "more": '<circle cx="6" cy="12" r="1.5" {f}/><circle cx="12" cy="12" r="1.5" {f}/>'
            '<circle cx="18" cy="12" r="1.5" {f}/>',
    "chevron-down": '<path d="m6.5 9.5 5.5 5.5 5.5-5.5" {s}/>',
    "chevron-right": '<path d="m9.5 6.5 5.5 5.5-5.5 5.5" {s}/>',
    "chevron-left": '<path d="M14.5 6.5 9 12l5.5 5.5" {s}/>',
    "arrow-up": '<path d="M12 19V5" {s}/><path d="m6.5 10.5 5.5-5.5 5.5 5.5" {s}/>',
    "arrow-down": '<path d="M12 5v14" {s}/><path d="m6.5 13.5 5.5 5.5 5.5-5.5" {s}/>',
    "external": '<path d="M14 4.5h5.5V10" {s}/><path d="m19.5 4.5-7 7" {s}/>'
                '<path d="M18 14.4v4.1a1.6 1.6 0 0 1-1.6 1.6H5.6A1.6 1.6 0 0 1 4 18.5V7.6'
                'A1.6 1.6 0 0 1 5.6 6h4.1" {s}/>',
    "copy": '<rect x="8.4" y="8.4" width="11.2" height="11.2" rx="2" {s}/>'
            '<path d="M15.6 5.6A2 2 0 0 0 13.8 4H6.4a2 2 0 0 0-2 2v7.4a2 2 0 0 0 1.6 1.9" {s}/>',

    # ---------------------------------------------------------- 视图
    "layout-list": '<path d="M4 6.5h16M4 12h16M4 17.5h16" {s}/>',
    "layout-thread": '<path d="M4.5 5.5v3.2a2 2 0 0 0 2 2h11a2 2 0 0 1 2 2v1.5" {s}/>'
                     '<path d="M4.5 12.5v2.5a2 2 0 0 0 2 2H17" {s}/>'
                     '<circle cx="4.5" cy="5.5" r="1.4" {f}/>'
                     '<circle cx="19.5" cy="18.4" r="1.4" {f}/>',
    "sun": '<circle cx="12" cy="12" r="4" {s}/>'
           '<path d="M12 3v2M12 19v2M21 12h-2M5 12H3M18.4 5.6 17 7M7 17l-1.4 1.4'
           'M18.4 18.4 17 17M7 7 5.6 5.6" {s}/>',
    "moon": '<path d="M20 14.2A8.4 8.4 0 0 1 9.8 4a8.4 8.4 0 1 0 10.2 10.2Z" {s}/>',
    "monitor": '<rect x="3" y="4.5" width="18" height="12" rx="1.8" {s}/>'
               '<path d="M9 20h6M12 16.5V20" {s}/>',
    "tray": '<path d="M3.5 12.5h4.2l1.4 2.2h5.8l1.4-2.2h4.2" {s}/>'
            '<path d="M3.5 12.5V7.6A1.6 1.6 0 0 1 5.1 6h13.8a1.6 1.6 0 0 1 1.6 1.6v4.9'
            'v6a1.6 1.6 0 0 1-1.6 1.6H5.1a1.6 1.6 0 0 1-1.6-1.6Z" {s}/>',
    "users": '<circle cx="9.4" cy="9" r="3.1" {s}/>'
             '<path d="M3.8 19.2a5.6 5.6 0 0 1 11.2 0" {s}/>'
             '<path d="M16 6.4a3.1 3.1 0 0 1 0 6" {s}/>'
             '<path d="M17.4 14.6a5.6 5.6 0 0 1 3 4.6" {s}/>',
    "mailbox": '<path d="M3 18.5v-6.2a3.6 3.6 0 0 1 7.2 0v6.2" {s}/>'
               '<path d="M10.2 18.5V8.6a2.6 2.6 0 0 1 2.6-2.6h5.6A2.6 2.6 0 0 1 21 8.6v9.9" {s}/>'
               '<path d="M3 18.5h18" {s}/><path d="M14 6v3.4h7" {s}/>',

    # ---------------------------------------------------------- 通讯录
    "contacts": '<rect x="4" y="5" width="16" height="15" rx="2" {s}/>'
                '<circle cx="9.5" cy="10" r="1.8" {s}/>'
                '<path d="M6.6 15a3 3 0 0 1 5.8 0" {s}/>'
                '<path d="M15.5 8.2a1.3 1.3 0 0 1 0 2.6M14.8 12.4a2.4 2.4 0 0 1 2 2.6" {s}/>'
                '<path d="M4 8.2h.01M4 12.8h.01" {s}/>',
}


def _svg(name: str, color: str) -> str:
    body = _PATHS.get(name)
    if body is None:
        # 未知图标退化为一个中性圆点：宁可画个占位，也不要让调用方拿到 None
        # 后在各处写 if 判空。
        body = '<circle cx="12" cy="12" r="4.2" {s}/>'
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
        + body.replace("{s}", _STROKE.format(c=color)).replace("{f}", _FILL.format(c=color))
        + "</svg>"
    )


_cache: dict[tuple[str, str, int, int], QPixmap] = {}


def pixmap(name: str, color: str, size: int = 18, dpr: int = 0) -> QPixmap:
    """把图标渲染成位图（带缓存）。`dpr` 为 0 时自动取主屏缩放。"""
    if dpr <= 0:
        dpr = _screen_dpr()
    key = (name, color, size, dpr)
    cached = _cache.get(key)
    if cached is not None:
        return cached

    pm = QPixmap(size * dpr, size * dpr)
    pm.fill(Qt.transparent)
    pm.setDevicePixelRatio(dpr)
    renderer = QSvgRenderer(QByteArray(_svg(name, color).encode("utf-8")))
    painter = QPainter(pm)
    painter.setRenderHint(QPainter.Antialiasing, True)
    painter.setRenderHint(QPainter.SmoothPixmapTransform, True)
    renderer.render(painter, QRectF(0, 0, size * dpr, size * dpr))
    painter.end()

    if len(_cache) > 512:      # 主题切换会不断产生新键，加个上限防止无界增长
        _cache.clear()
    _cache[key] = pm
    return pm


def icon(name: str, color: str, size: int = 18) -> QIcon:
    """取一个图标（用于 `QAction.setIcon` / `QPushButton.setIcon`）。"""
    return QIcon(pixmap(name, color, size))


def _screen_dpr() -> int:
    from PySide6.QtWidgets import QApplication

    # 无 GUI 环境（测试 / headless CI）下拿不到屏幕，退化为 1x
    with contextlib.suppress(Exception):
        app = QApplication.instance()
        if app is not None:
            screen = app.primaryScreen()
            if screen is not None:
                return max(1, round(screen.devicePixelRatio()))
    return 1


def clear_cache() -> None:
    """主题切换后由 ThemeManager 调用，丢弃按旧色渲染的位图。"""
    _cache.clear()


def available() -> list[str]:
    return sorted(_PATHS)


__all__ = ["available", "clear_cache", "icon", "pixmap"]

"""界面与行为的持久化偏好（独立于加密数据库）。

为什么单独一个文件而不是塞进数据库：主题、字号这类设置必须**在解锁之前**
就能读到——登录对话框本身也要按当前主题着色。放进加密库就得先解锁再能读，
登录窗口只能硬编码深色，主题切换会显得很割裂。

文件里只有开关与枚举，不含任何机密，因此明文 JSON 是合适的。
写入沿用「临时文件 + 原子替换」，避免异常退出留下半截文件让设置全部丢失。
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..config import DATA_DIR

log = logging.getLogger(__name__)

SETTINGS_PATH = DATA_DIR / "ui.json"

# 主题模式："system" 跟随操作系统 / "dark" / "light"
THEME_MODES = ("system", "dark", "light")
VIEW_MODES = ("list", "thread")
FONT_SCALES = (0.9, 1.0, 1.1, 1.25)


@dataclass
class UiSettings:
    """全部可持久化的界面偏好。新增字段必须给出默认值。"""
    theme_mode: str = "system"
    font_scale: float = 1.0
    view_mode: str = "list"              # list | thread（会话视图）
    sync_server_flags: bool = True       # 已读/星标回写服务器
    minimize_to_tray: bool = True
    show_notifications: bool = True
    prefetch_bodies: bool = True         # 后台预取正文
    inline_images_auto: bool = False     # 自动加载内嵌图片（默认关，等同加载远程内容）
    device_unlock: bool = False          # 设备绑定免密解锁（显式开关，默认关）
    lock_on_minimize: bool = False
    window_geometry: str = ""            # base64 编码的 QByteArray
    extras: dict = field(default_factory=dict)

    # ------------------------------------------------------------ 读写
    @classmethod
    def load(cls, path: Path | None = None) -> UiSettings:
        target = Path(path) if path else SETTINGS_PATH
        try:
            data = json.loads(target.read_text("utf-8"))
        except (OSError, ValueError, TypeError):
            return cls()
        if not isinstance(data, dict):
            return cls()
        known = set(cls.__dataclass_fields__)
        clean = {k: v for k, v in data.items() if k in known}
        settings = cls(**clean)
        settings.sanitize()
        return settings

    def sanitize(self) -> None:
        """把越界/非法取值拉回合法范围。

        配置文件可能被手工改过或被旧版本写过，直接信任会让
        `theme_mode="neon"` 这类值一路传到样式表里。
        """
        if self.theme_mode not in THEME_MODES:
            self.theme_mode = "system"
        if self.view_mode not in VIEW_MODES:
            self.view_mode = "list"
        try:
            scale = float(self.font_scale)
        except (TypeError, ValueError):
            scale = 1.0
        if scale not in FONT_SCALES:
            scale = 1.0
        self.font_scale = scale

    def save(self, path: Path | None = None) -> None:
        target = Path(path) if path else SETTINGS_PATH
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_name(target.name + ".tmp")
            tmp.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False),
                           encoding="utf-8")
            os.replace(tmp, target)
        except OSError as exc:      # 设置存不下来不该影响使用
            log.warning("保存界面设置失败：%s", exc)

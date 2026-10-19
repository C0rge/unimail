#!/usr/bin/env python3
"""把 SVG 图标转成 Windows .ico（多尺寸合成），并生成 Qt 用的 PNG。

用法：
    python tools/make_icon.py                 # 用默认源生成 dist/icon.ico + assets/icon_*.png
    python tools/make_icon.py --svg assets/icon.svg --out dist/icon.ico

为什么需要这个脚本
-----------------
PyInstaller 的 `--icon` 只接受 `.ico`（Windows），而设计源文件是 SVG——
好处是可缩放、可跟随主题改色、可读可 diff。中间这层转换必须有个**确定性的**
产出过程：手工导出一遍就再也没法改，下次改图标只能重导，而「哪个 ico 对应
哪版 svg」很快就没人说得清。

因此这里把转换固化成脚本：图标源文件（assets/*.svg）进版本库，ico 与 png
是**构建产物**，随时可以从源文件重新生成。修改图标请改 SVG，不要改 ico。

尺寸选择
--------
ICO 里放 16 / 24 / 32 / 48 / 64 / 128 / 256 七档。理由：
  * 16 与 32：任务栏、Alt+Tab、窗口标题栏（Windows 会按 DPI 自动选档）；
  * 48：资源管理器「大图标」视图、文件属性对话框；
  * 256：安装程序、关于对话框、「设置为桌面快捷方式后右键查看大图标」。
只放 256 一档是不够的：Windows 对 ICO 的取图逻辑是按需选档，缺失小尺寸时
会把大图缩下来，任务栏上会出现明显的模糊与锯齿。

技术要点
--------
1. 光栅化用 `QSvgRenderer`，不引入 Pillow：本项目运行与构建环境都已经
   为了 PySide6 装了 Qt，再为一个图标转换加一个图像库不划算。
2. 用 `QT_QPA_PLATFORM=offscreen` 启动 QApplication——本脚本是纯离线的
   构建期工具，不应依赖（也不应弹出）任何窗口。
3. ICO 头部按 PNG 内嵌格式写入（Vista+ 支持 256×256 的 PNG 条目）。
   256×256 若写成 BMP，头部要 40+256*4 字节的「与掩码」，文件凭空多出
   256 KB；PNG 条目则只有实际压缩后的几千字节。
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
from pathlib import Path

# 必须在 import PySide6 之前设置：offscreen 让脚本在无显示环境（CI、
# 打包机、SSH 会话）里也能跑，且不会闪现窗口。放在模块顶部而不是
# 各函数内部，是为了让 PySide6 的 import 能提到模块级——函数内 import
# 会被 ruff 的 I001 当作独立块反复挑刺，而且同一个符号在两个函数里
# 各 import 一遍本来就是重复。
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, Qt
from PySide6.QtGui import QGuiApplication, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer

ROOT = Path(__file__).resolve().parent.parent

# ICO 内嵌的尺寸档。顺序即写入顺序；Windows 取图不依赖顺序，但按升序写
# 便于人肉检查文件头。
ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)

# 同时产出的 PNG（给 Qt 侧与文档用）。256 是上限，再大对桌面端无意义。
PNG_SIZES = (32, 64, 256)


def _svg_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    if not data.lstrip().startswith(b"<"):
        raise SystemExit(f"[x] {path} 不像 SVG 文件")
    return data


def render_png(svg: bytes, size: int, out: Path) -> None:
    """把 SVG 光栅化成一个正方形 PNG。"""
    # 必须有一个 QGuiApplication 实例才能建 QImage / QSvgRenderer。
    # 刻意不接收返回值：它是进程级的，这里只负责「确保它存在」，
    # 拿到引用反而会被 ruff 记 F841（赋值后未使用）。
    _ensure_app()

    # 先用 4 倍超采样渲染、再缩小：SVG 里全是直线与圆，超采样能让 16px
    # 这种极小尺寸的边缘保持干净，避免直接按 16px 渲染时出现的锯齿与
    # 「圆点丢一个」的量化误差。
    ss = 4
    big = QImage(size * ss, size * ss, QImage.Format.Format_ARGB32)
    big.fill(0)
    renderer = QSvgRenderer(QByteArray(svg))
    if not renderer.isValid():
        raise SystemExit("[x] SVG 无法被 QSvgRenderer 解析（检查 XML 语法）")
    painter = QPainter(big)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    renderer.render(painter)
    painter.end()

    final = big.scaled(size, size,
                       Qt.AspectRatioMode.IgnoreAspectRatio,
                       Qt.TransformationMode.SmoothTransformation)
    out.parent.mkdir(parents=True, exist_ok=True)
    if not final.save(str(out), "PNG"):
        raise SystemExit(f"[x] 写 PNG 失败：{out}")


def _ensure_app():
    """确保进程里有一个 QGuiApplication（Qt 离屏渲染的前置条件）。

    单独成函数而不是在两个渲染函数里各写一遍：`instance() or QGuiApplication(...)`
    这个惯用法出现两次就会漂移（比如一处忘了 `or` 分支，另一处忘了传 argv），
    而它失败时的症状是「QSvgRenderer 静默画不出东西」，极难排查。
    """
    return QGuiApplication.instance() or QGuiApplication(sys.argv)


def build_ico(svg: bytes, out: Path, sizes: tuple[int, ...] = ICO_SIZES) -> None:
    """把 SVG 渲染成各尺寸 PNG 后合成一个 ICO。"""
    _ensure_app()

    renderer = QSvgRenderer(QByteArray(svg))
    if not renderer.isValid():
        raise SystemExit("[x] SVG 无法被 QSvgRenderer 解析（检查 XML 语法）")

    entries: list[tuple[int, bytes]] = []
    for size in sizes:
        ss = 4
        big = QImage(size * ss, size * ss, QImage.Format.Format_ARGB32)
        big.fill(0)
        painter = QPainter(big)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        renderer.render(painter)
        painter.end()
        img = big.scaled(size, size,
                         Qt.AspectRatioMode.IgnoreAspectRatio,
                         Qt.TransformationMode.SmoothTransformation)
        buf = QBuffer()
        buf.open(QIODevice.OpenModeFlag.WriteOnly)
        if not img.save(buf, "PNG"):
            raise SystemExit(f"[x] 渲染 {size}px 失败")
        entries.append((size, bytes(buf.data())))

    # ICO 文件结构：ICONDIR + N×ICONDIRENTRY + N×图像数据。
    # ICONDIRENTRY 对 PNG 条目：宽高用 0 表示 256（字节装不下 256），
    # 颜色数 0，planes 1（被忽略），bpp 32，字节数=PNG 长度，偏移累加。
    count = len(entries)
    header = struct.pack("<HHH", 0, 1, count)
    offset = 6 + 16 * count
    directory = b""
    for size, blob in entries:
        dim = 0 if size >= 256 else size
        directory += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
    payload = b"".join(blob for _, blob in entries)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(header + directory + payload)
    # 刻意不用 ✓ / ✗ 这类符号：Windows 控制台默认 GBK，遇到非 ASCII 的
    # print 会抛 UnicodeEncodeError 让脚本「做完了事却以崩溃收场」。
    total_kb = len(header + directory + payload) / 1024
    print(f"[OK] 已生成 {out}（{count} 档：{'/'.join(str(s) for s in sizes)}，"
          f"{total_kb:.1f} KB）")


def main() -> int:
    ap = argparse.ArgumentParser(description="SVG → ICO/PNG 图标转换（构建期工具）")
    ap.add_argument("--svg", type=Path, default=ROOT / "assets" / "icon.svg",
                    help="主 SVG 源文件（默认 assets/icon.svg）")
    ap.add_argument("--light", type=Path, default=ROOT / "assets" / "icon_light.svg",
                    help="浅色主题 SVG 源文件（默认 assets/icon_light.svg）")
    ap.add_argument("--ico", type=Path, default=ROOT / "dist" / "icon.ico",
                    help="ICO 输出路径（默认 dist/icon.ico）")
    ap.add_argument("--png-dir", type=Path, default=ROOT / "assets",
                    help="PNG 输出目录（默认 assets/）")
    ap.add_argument("--no-png", action="store_true", help="只生成 ICO，不产 PNG")
    args = ap.parse_args()

    if not args.svg.exists():
        print(f"[x] 找不到 SVG 源文件：{args.svg}")
        return 1
    if not args.light.exists():
        print(f"[x] 找不到浅色 SVG 源文件：{args.light}")
        return 1

    svg = _svg_bytes(args.svg)
    build_ico(svg, args.ico)

    if not args.no_png:
        for name, source in (("icon_dark", args.svg), ("icon_light", args.light)):
            for size in PNG_SIZES:
                render_png(_svg_bytes(source), size,
                           args.png_dir / f"{name}_{size}.png")
        print(f"[OK] 已生成 PNG 到 {args.png_dir}")

    print("\n下一步：python build_exe.py（脚本会自动带上这个 ico）")
    return 0


if __name__ == "__main__":
    sys.exit(main())

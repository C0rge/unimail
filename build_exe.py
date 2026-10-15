#!/usr/bin/env python3
"""UniMail 打包脚本：用 PyInstaller 生成 Windows 可执行文件。

用法：
    python build_exe.py            # 默认 onefile
    python build_exe.py --onedir   # 目录模式（启动更快）
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"

# 明确排除：项目只用 QtCore/QtGui/QtWidgets，WebEngine 等会让体积暴涨
EXCLUDES = [
    "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineWidgets",
    "PySide6.QtWebEngineQuick",
    "PySide6.QtQml",
    "PySide6.QtQuick",
    "PySide6.QtQuick3D",
    "PySide6.QtQuickWidgets",
    "PySide6.Qt3DCore",
    "PySide6.QtMultimedia",
    "PySide6.QtMultimediaWidgets",
    "PySide6.QtCharts",
    "PySide6.QtDataVisualization",
    "PySide6.QtBluetooth",
    "PySide6.QtNfc",
    "PySide6.QtPositioning",
    "PySide6.QtSerialPort",
    "PySide6.QtSensors",
    "PySide6.QtSql",
    "PySide6.QtTest",
    "PySide6.QtDesigner",
    "PySide6.QtHelp",
    "PySide6.QtOpenGL",
    "PySide6.QtOpenGLWidgets",
    "PySide6.QtPdf",
    "PySide6.QtPdfWidgets",
    "PySide6.QtNetworkAuth",
    "PySide6.QtWebSockets",
    "PySide6.QtWebChannel",
    "PySide6.QtRemoteObjects",
    "PySide6.QtScxml",
    "PySide6.QtSpatialAudio",
    "PySide6.QtStateMachine",
    "PySide6.QtTextToSpeech",
    "PySide6.QtUiTools",
    "PySide6.QtHttpServer",
    "tkinter",
    "matplotlib",
    "numpy",
    "PIL",
    "pandas",
    "scipy",
    "pytest",
]

# 运行时必需：cryptography 的底层 cffi 与 Qt 插件
HIDDEN = [
    "PySide6.QtCore",
    "PySide6.QtGui",
    "PySide6.QtWidgets",
    "_cffi_backend",
    "cryptography.hazmat.bindings._rust",
    "cryptography.hazmat.bindings._rust.openssl",
    "unimail.demo",
]


def build(onedir: bool, clean: bool) -> Path:
    if clean:
        for d in (DIST, BUILD):
            if d.exists():
                shutil.rmtree(d)
        print(f"[i] 已清理 {DIST} 与 {BUILD}")

    pyi = Path(sys.executable).parent / "Scripts" / "pyinstaller.exe"
    if not pyi.exists():
        pyi = Path(sys.executable).parent / "pyinstaller.exe"
    if not pyi.exists():
        # 回退：用 python -m PyInstaller
        cmd = [sys.executable, "-m", "PyInstaller"]
    else:
        cmd = [str(pyi)]

    cmd += [
        "--name", "UniMail",
        "--noconfirm",
        "--clean" if clean else "--noreuse-build-instance",
        "--windowed",                    # 无控制台窗口（GUI 应用）
        "--onedir" if onedir else "--onefile",
        "--distpath", str(DIST),
        "--workpath", str(BUILD),
        "--specpath", str(ROOT),
    ]
    for mod in EXCLUDES:
        cmd += ["--exclude-module", mod]
    for mod in HIDDEN:
        cmd += ["--hidden-import", mod]
    cmd.append(str(ROOT / "main.py"))

    print("[i] 开始打包…")
    print("    " + " ".join(cmd[:8]) + " …")
    result = subprocess.run(cmd, cwd=str(ROOT))
    if result.returncode != 0:
        print("[x] 打包失败")
        sys.exit(1)

    target = DIST / "UniMail"
    exe = target / "UniMail.exe" if onedir else DIST / "UniMail.exe"
    if not exe.exists():
        print(f"[x] 未找到产物：{exe}")
        sys.exit(1)
    size_mb = exe.stat().st_size / (1024 * 1024)
    print(f"[✓] 打包完成：{exe}  ({size_mb:.1f} MB)")
    return exe


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--onedir", action="store_true", help="目录模式（启动更快）")
    ap.add_argument("--no-clean", action="store_true", help="不清理旧构建缓存")
    args = ap.parse_args()
    build(args.onedir, clean=not args.no_clean)
    return 0


if __name__ == "__main__":
    sys.exit(main())

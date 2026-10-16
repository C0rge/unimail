#!/usr/bin/env python3
"""UniMail 打包脚本：用 PyInstaller 生成 Windows 可执行文件，并可选做代码签名。

用法：
    python build_exe.py                        # 默认 onefile，不签名
    python build_exe.py --onedir               # 目录模式（启动更快）
    python build_exe.py --sign --cert-thumbprint <SHA1>     # 用证书存储里的证书签
    python build_exe.py --sign --pfx cert.pfx --pfx-password-env UNIMAIL_PFX_PW

为什么提供签名：未签名的 exe 会触发 SmartScreen 的「已阻止不安全的下载」，
用户必须点「仍要运行」才能装上——对一个要接管邮箱凭据的程序来说，这个提示
是不该出现的（它训练用户忽略安全警告）。签名解决的是可信度，不是功能。

证书从哪来见 `docs/代码签名.md`；本脚本只负责「拿到证书之后怎么签」。
"""
from __future__ import annotations

import argparse
import glob
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

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

DEFAULT_TSP = "http://timestamp.digicert.com"

# signtool 随 Windows SDK 分发，通常不在 PATH 里，因此按已知位置兜底查找。
SIGNTOOL_GLOBS = (
    r"C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe",
    r"C:\Program Files\Windows Kits\10\bin\*\x64\signtool.exe",
)


@dataclass
class SignConfig:
    """签名参数。`pfx` 与 `thumbprint` 二选一。"""
    pfx: Path | None = None
    pfx_password: str | None = None
    thumbprint: str | None = None
    timestamp_url: str = DEFAULT_TSP
    timestamp: bool = True
    verify: bool = True
    description: str = "UniMail"
    url: str = "https://github.com/C0rge/unimail"

    @property
    def ready(self) -> bool:
        return bool(self.pfx or self.thumbprint)


def sdk_version_key(path: str) -> tuple[int, ...]:
    """把 SDK 路径里的版本号拆成可比较的元组，用于挑最新的一套工具。

    这里必须用 `PureWindowsPath` 而不是 `Path`。`Path` 按**运行平台**的规则
    切分路径：在 Linux / macOS 上，`C:\\Kits\\10\\bin\\10.0.26100.0\\x64\\signtool.exe`
    整体被视为一个不含分隔符的文件名，`.parent.parent.name` 拿到空串，
    于是任何两个路径都退化成 `(0,)`，"取最新的一套"就静默失效了。
    `PureWindowsPath` 的切分规则与平台无关，三个平台上结果一致。
    """
    name = PureWindowsPath(path).parent.parent.name        # 形如 10.0.26100.0
    parts: list[int] = []
    for chunk in name.split("."):
        parts.append(int(chunk) if chunk.isdigit() else 0)
    return tuple(parts)


def find_signtool() -> str | None:
    """定位 signtool.exe：先 PATH，再 Windows SDK 目录里最新的一套。"""
    for name in ("signtool", "signtool.exe"):
        found = shutil.which(name)
        if found:
            return found
    if sys.platform != "win32":
        return None
    candidates: list[str] = []
    for pattern in SIGNTOOL_GLOBS:
        candidates.extend(glob.glob(pattern))
    if not candidates:
        return None
    return sorted(candidates, key=sdk_version_key)[-1]


def signature_status(exe: Path) -> str:
    """用 Get-AuthenticodeSignature 读取签名状态。

    路径通过**环境变量**传给 PowerShell，而不是拼进命令字符串——
    路径里的空格、中文、反斜杠都不会被当成语法，省掉一整类转义 bug。
    """
    if sys.platform != "win32":
        return "unsupported"
    env = dict(os.environ, UNIMAIL_SIGN_TARGET=str(exe))
    cmd = [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
        "(Get-AuthenticodeSignature -LiteralPath $env:UNIMAIL_SIGN_TARGET).Status.ToString()",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env,
                                timeout=60, check=False)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return (result.stdout or "").strip() or "unknown"


def sign_exe(exe: Path, cfg: SignConfig) -> bool:
    """对 exe 签名。返回是否成功（含签名后校验结论）。"""
    if not cfg.ready:
        print("[x] 需要 --pfx 或 --cert-thumbprint 之一才能签名")
        return False
    signtool = find_signtool()
    if signtool is None:
        print("[x] 未找到 signtool.exe。它随 Windows SDK 分发，"
              "请安装「Windows SDK Signing Tools」后重试。")
        return False
    print(f"[i] 使用 signtool：{signtool}")

    cmd = [signtool, "sign", "/fd", "sha256"]
    if cfg.pfx:
        cmd += ["/f", str(cfg.pfx)]
        if cfg.pfx_password:
            cmd += ["/p", cfg.pfx_password]
    else:
        # 用证书存储里的证书（/sha1）不需要在命令行传密码，是更安全的路径，
        # 因此优先推荐它而不是 PFX。
        cmd += ["/sha1", str(cfg.thumbprint).replace(" ", "")]
    if cfg.timestamp and cfg.timestamp_url:
        cmd += ["/tr", cfg.timestamp_url, "/td", "sha256"]
    cmd += ["/d", cfg.description, "/du", cfg.url, str(exe)]

    print("[i] 签名中…" + ("（含时间戳）" if cfg.timestamp else "（不含时间戳）"))
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print("[x] 签名失败：")
        print((result.stdout or "") + (result.stderr or ""))
        return False
    print("[✓] 签名完成")

    if cfg.verify:
        status = signature_status(exe)
        print(f"[i] 签名状态：{status}")
        if status in ("NotSigned", "unknown", "unsupported"):
            print("[x] 签名后校验未通过")
            return False
        if status != "Valid":
            # 自签名证书未进信任链时会落到 UnknownError / NotTrusted，
            # 此时签名**存在**但不被系统信任——这是自签名的预期表现。
            print(f"[!] 签名已附加，但系统不信任该证书（{status}）。"
                  "自签名证书属正常现象；正式发布需使用受信任 CA 签发的证书。")
    return True


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
        # `--clean` 会清掉 PyInstaller 的分析缓存，改一行代码也要全量重扫，
        # 本地迭代时用 --no-clean 跳过它（CI / 发版仍建议带 --clean）。
        "--clean" if clean else "--noconfirm",
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
    ap = argparse.ArgumentParser(description="UniMail 打包（可选代码签名）")
    ap.add_argument("--onedir", action="store_true", help="目录模式（启动更快）")
    ap.add_argument("--no-clean", action="store_true", help="不清理旧构建缓存")
    ap.add_argument("--sign", action="store_true", help="打包后对 exe 签名")
    ap.add_argument("--pfx", type=Path, help="PFX 证书文件路径")
    ap.add_argument("--pfx-password-env", metavar="VAR",
                    help="从该环境变量读取 PFX 密码（避免密码出现在命令行/进程列表）")
    ap.add_argument("--pfx-password", help="PFX 密码（明文，仅用于本地临时测试）")
    ap.add_argument("--cert-thumbprint", help="证书存储中的指纹（推荐，无需传密码）")
    ap.add_argument("--timestamp-url", default=DEFAULT_TSP, help="时间戳服务地址")
    ap.add_argument("--no-timestamp", action="store_true",
                    help="不打时间戳（离线或自签名测试时使用）")
    ap.add_argument("--skip-verify", action="store_true", help="跳过签名后校验")
    args = ap.parse_args()

    exe = build(args.onedir, clean=not args.no_clean)

    if not args.sign:
        return 0

    password = args.pfx_password
    if args.pfx_password_env:
        password = os.environ.get(args.pfx_password_env)
        if password is None:
            print(f"[x] 环境变量 {args.pfx_password_env} 未设置")
            return 1
    cfg = SignConfig(
        pfx=args.pfx,
        pfx_password=password,
        thumbprint=args.cert_thumbprint,
        timestamp_url=args.timestamp_url,
        timestamp=not args.no_timestamp,
        verify=not args.skip_verify,
    )
    if not sign_exe(exe, cfg):
        print("[x] 已在 --sign 下失败，不输出未签名的发布产物")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

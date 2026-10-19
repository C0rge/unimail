#!/usr/bin/env python3
"""UniMail 打包脚本：用 PyInstaller 生成 Windows 可执行文件，并可选做代码签名。

用法：
    python build_exe.py                        # 默认 onefile，不签名
    python build_exe.py --onedir               # 目录模式（启动更快）
    python build_exe.py --sign --cert-thumbprint <SHA1>     # 用证书存储里的证书签
    python build_exe.py --sign --pfx cert.pfx --pfx-password-env UNIMAIL_PFX_PW

    图标相关：
    python build_exe.py --make-icon            # 只从 assets/*.svg 重新生成 dist/icon.ico
    python build_exe.py --no-icon              # 不给 exe 带图标（调试用）

打包前会检查 `REQUIRED_RUNTIME` 里的依赖是否齐全（目前是 SQLCipher）——原因见该常量的注释：
缺了它 exe 照样能跑，只是永远降级为字段级加密，属于「静默少一块能力」，必须在构建期拦住。
确实要打降级包时显式加 `--allow-degraded`。

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
ICON = DIST / "icon.ico"

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
    "sqlcipher3",
    "sqlcipher3.dbapi2",
    "unimail.demo",
]

# 必须真正打进发行包的依赖：导入名 → 安装提示。
#
# `sqlcipher3` 是唯一一处「打包环境装了才有、没装也**不报任何错**」的依赖：缺失时
# exe 照样启动、功能看起来都正常，只是永远降级为字段级加密（整库明文），
# 而界面上的「数据库加密设置」迁移入口对绿色版用户会永久不可用。
# v1.0.0–v1.6.0 的发布包**全部**如此，构建日志里也没有任何提示——
# 这类「静默少一块能力」正是最该在构建期拦住的东西，所以改成硬性检查，
# 真要打降级包时必须显式加 --allow-degraded。
REQUIRED_RUNTIME = {
    "sqlcipher3": "sqlcipher3-wheels==0.5.6（已在 requirements.txt 中）",
}

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
    print("[OK] 签名完成")

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


def check_required_runtime() -> list[str]:
    """检查发行包必须具备的依赖，返回缺失项的人类可读描述。"""
    import importlib

    missing: list[str] = []
    for module, hint in REQUIRED_RUNTIME.items():
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(f"{module} —— {hint}")
    return missing


def ensure_icon(make: bool = False) -> Path | None:
    """确保 dist/icon.ico 存在，返回路径（或 None 表示本次不带图标）。

    图标源文件是 `assets/icon.svg`（设计依据见 assets/README.md），ico 是
    构建产物。这里的行为：

    * `--make-icon`：强制从 SVG 重新生成，然后直接退出（供改完图标单独跑）；
    * ico 已存在且比两个 SVG 都新：直接用（增量构建不该每次都重画图标）；
    * ico 缺失或比 SVG 旧：自动重新生成。

    自动生成失败时**不阻断打包**：图标是外观问题，缺了顶多是默认图标，
    而因为一张图就打不出包是本末倒置。但会明确警告——静默缺一块能力
    正是本项目在 SQLCipher 上栽过的跟头，这里不能再犯同样的错。
    """
    sources = [ROOT / "assets" / "icon.svg", ROOT / "assets" / "icon_light.svg"]
    have_sources = all(p.exists() for p in sources)

    if make:
        if not have_sources:
            print("[x] --make-icon 需要 assets/icon.svg 与 assets/icon_light.svg")
            sys.exit(1)
        print("[i] 从 assets/*.svg 重新生成图标…")
        _run_make_icon()
        return ICON if ICON.exists() else None

    if not ICON.exists():
        if not have_sources:
            print("[!] 未找到 dist/icon.ico，也没有 assets/*.svg 可自动生成；"
                  "本次打包不带图标（--no-icon 可显式跳过该检查）")
            return None
        print("[i] dist/icon.ico 不存在，自动从 assets/*.svg 生成…")
        if _run_make_icon():
            return ICON
        print("[!] 图标生成失败，本次打包不带图标")
        return None

    # 已存在：源文件比产物新才重画，否则直接用。
    if have_sources and any(p.stat().st_mtime > ICON.stat().st_mtime for p in sources):
        print("[i] assets/*.svg 有更新，重新生成图标…")
        _run_make_icon()
    return ICON


def _run_make_icon() -> bool:
    """调用 tools/make_icon.py。返回是否成功。"""
    script = ROOT / "tools" / "make_icon.py"
    if not script.exists():
        print(f"[!] 找不到 {script}")
        return False
    result = subprocess.run([sys.executable, str(script)], cwd=str(ROOT))
    if result.returncode != 0:
        print("[!] tools/make_icon.py 执行失败")
        return False
    return ICON.exists()


def build(onedir: bool, clean: bool, icon: Path | None = None) -> Path:
    if clean:
        for d in (DIST, BUILD):
            if d.exists():
                shutil.rmtree(d)
        print(f"[i] 已清理 {DIST} 与 {BUILD}")
        # `--clean` 清的是整个 dist，而 icon.ico 是我们放在那里的**输入**
        # 文件（由 assets/*.svg 生成），不是 PyInstaller 的产物。
        # 不清掉它，否则这次打包就变成「图标生成了、又被自己删了」。
        if icon is not None and icon.parent == DIST:
            ensure_icon()
            if not icon.exists():
                print("[!] 清理后图标未能重新生成，本次不带图标")
                icon = None

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
    # 图标放在 `--name` 之后、脚本路径之前。PyInstaller 对参数顺序不敏感，
    # 但图标要显式排除在 --clean 的清理范围外：--clean 清的是 BUILD 缓存，
    # 而 dist/icon.ico 是我们自己放的输入文件，不是它的产物。
    if icon is not None:
        cmd += ["--icon", str(icon)]
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
    print(f"[OK] 打包完成：{exe}  ({size_mb:.1f} MB)")
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
    ap.add_argument("--allow-degraded", action="store_true",
                    help="允许打出缺少 SQLCipher 的降级包（默认不允许，见 REQUIRED_RUNTIME）")
    ap.add_argument("--make-icon", action="store_true",
                    help="只从 assets/*.svg 重新生成 dist/icon.ico 后退出")
    ap.add_argument("--no-icon", action="store_true",
                    help="不给 exe 带图标（调试用；正常情况下会自动生成）")
    ap.add_argument("--icon", type=Path, default=None,
                    help="显式指定 .ico 文件（默认 dist/icon.ico，缺失时自动生成）")
    args = ap.parse_args()

    # 图标处理放在依赖检查之前：--make-icon 是个独立的快速命令，
    # 不该因为打包环境少个依赖就被拦住。
    if args.make_icon:
        ensure_icon(make=True)
        return 0

    if not args.allow_degraded:
        missing = check_required_runtime()
        if missing:
            print("[x] 打包环境缺少发行包必须具备的依赖，继续下去会打出一个"
                  "「能跑、但少了一块能力」的包：")
            for item in missing:
                print(f"    · {item}")
            print("    安装后重试；确实需要降级包请显式加 --allow-degraded。")
            return 1

    if args.no_icon:
        icon: Path | None = None
        print("[!] --no-icon：本次打包不带应用图标")
    elif args.icon is not None:
        icon = args.icon
        if not icon.exists():
            print(f"[x] 指定的图标文件不存在：{icon}")
            return 1
    else:
        icon = ensure_icon()

    exe = build(args.onedir, clean=not args.no_clean, icon=icon)

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

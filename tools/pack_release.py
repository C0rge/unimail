#!/usr/bin/env python3
"""把 PyInstaller 产物组装成发布 zip。

为什么要有这个脚本：`docs/发布规范.md` §5 规定发布 zip 内固定包含
`UniMail.exe` + `使用说明.md` + `README.md` + `CHANGELOG.md` + `LICENSE`，
但这一步此前是**手工**做的。后果已经发生过一次：v1.1.0 的 zip 里放着的
还是 **v1.0.0** 的 `使用说明.md`，而且那份说明根本不在版本控制里，
没有任何机制能发现它过期了。

所以这里不只是"打个包"，而是把三条校验固化下来（任一条不过就退出非 0）：

1. `dist/UniMail.exe` 必须存在（先跑 `python build_exe.py`）；
2. 随包的五个文件必须齐全；
3. `使用说明.md` 的标题里必须含当前 `APP_VERSION` —— 直接拦住
   「打出的包里装着上一版说明」这个具体故障。

用法：
    python build_exe.py            # 先产出 dist/UniMail.exe
    python tools/pack_release.py   # 再组装 dist/release/UniMail-vX.Y.Z-Windows-x64.zip
"""
from __future__ import annotations

import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from unimail.config import APP_VERSION  # noqa: E402

DIST = ROOT / "dist"
RELEASE = DIST / "release"
EXE = DIST / "UniMail.exe"

# zip 内固定的文件清单（平铺，不带顶层目录，与历史发布物一致）
DOCS = ["使用说明.md", "README.md", "CHANGELOG.md", "LICENSE"]
PAYLOAD = ["UniMail.exe", *DOCS]

# 说明文件里必须出现当前版本号，否则就是在打包上一版的说明。
VERSION_CHECK = "使用说明.md"


def main() -> int:
    if not EXE.exists():
        print(f"[x] 未找到产物 {EXE}，请先运行：python build_exe.py")
        return 1

    missing = [name for name in DOCS if not (ROOT / name).exists()]
    if missing:
        print(f"[x] 缺少要随包发布的文件：{', '.join(missing)}")
        return 1

    first_line = (ROOT / VERSION_CHECK).read_text("utf-8").splitlines()[0]
    if APP_VERSION not in first_line:
        print(f"[x] {VERSION_CHECK} 的标题是 {first_line!r}，"
              f"与 APP_VERSION={APP_VERSION} 不一致。")
        print("    这正是 v1.1.0 那个问题的复现：发布包里装的是上一版的说明。")
        return 1

    name = f"UniMail-v{APP_VERSION}-Windows-x64.zip"
    RELEASE.mkdir(parents=True, exist_ok=True)
    out = RELEASE / name

    print(f"[i] 组装 {name}")
    with zipfile.ZipFile(out, "w") as archive:
        for item in PAYLOAD:
            src = EXE if item == "UniMail.exe" else ROOT / item
            # exe 是 PyInstaller 的 onefile 产物，内部已经是压缩流，再 deflate
            # 一次只能省千分之几、却要多花十几秒，直接存储更合适。
            method = (zipfile.ZIP_STORED if src.suffix.lower() == ".exe"
                      else zipfile.ZIP_DEFLATED)
            archive.write(src, arcname=item, compress_type=method)
            print(f"    + {item}  ({src.stat().st_size / 1048576:.2f} MB)")

    print(f"[OK] {out}  ({out.stat().st_size / 1048576:.1f} MB)")

    # 回读复核：文件齐全，且中文文件名没有乱码（zipfile 写非 ASCII 名时会
    # 置 UTF-8 标志位，这里顺便验证一下确实如此）。
    with zipfile.ZipFile(out) as archive:
        got = archive.namelist()
    if sorted(got) != sorted(PAYLOAD):
        print(f"[x] zip 内容与预期不符：{got}")
        return 1
    print(f"[i] 回读校验通过，内含 {len(got)} 个文件：{', '.join(got)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

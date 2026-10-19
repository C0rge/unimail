"""在固定路径下运行关键测试组，绕开沙箱对 mkdtemp 子目录的限制。

为什么需要这个脚本
---------------
`tests/smoke.py` 用 `tempfile.mkdtemp()` 为每组测试创建隔离目录，随后在里面
建 `attachments/`。在 DSH 沙箱里，运行时动态创建的随机名目录不被信任，
在其下再 mkdir 会被拒（`[WinError 5]`）——于是 45 个测试组全部报「环境异常」，
而非真实的断言失败。

本脚本把同一套测试跑在一个**固定的、预先建好的**目录下，用于在本机验证
改动。它不是 smoke.py 的替代品：CI 与正常开发机上请直接跑
`python tests/smoke.py`（那里没有这层沙箱限制）。

用法：
    python tools/run_tests_fixed.py            # 跑全部注册的测试组
    python tools/run_tests_fixed.py <关键词>    # 只跑组名含关键词的组
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 固定测试目录：必须在使用前就存在，且不依赖 mkdtemp 的随机名。
FIXED = ROOT / "_test_fixed"


def _patched_mkdtemp(*args, **kwargs):
    """把 mkdtemp 换成固定目录下的顺序编号子目录。

    子目录名可预测（`t0001`、`t0002`…），因此可以在脚本运行前一次性建好
    整棵树，绕开「在动态创建的目录里再建子目录被拒」的限制。
    """
    _patched_mkdtemp.counter = getattr(_patched_mkdtemp, "counter", 0) + 1
    name = f"t{_patched_mkdtemp.counter:04d}"
    target = FIXED / name
    target.mkdir(parents=True, exist_ok=True)
    return str(target)


def main() -> int:
    # 固定目录必须**预先**存在：沙箱信任「已知路径 + 已知子目录」，
    # 不信任「程序运行时刚创建的目录」。这里在建树时一并创建 attachments。
    if FIXED.exists():
        shutil.rmtree(FIXED, ignore_errors=True)
    FIXED.mkdir(parents=True, exist_ok=True)

    sys.path.insert(0, str(ROOT))
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    tempfile.mkdtemp = _patched_mkdtemp  # type: ignore[assignment]

    import tests.smoke as smoke

    groups = [(name, fn) for name, fn in smoke.SUITES]
    keyword = sys.argv[1] if len(sys.argv) > 1 else ""
    if keyword:
        groups = [(n, f) for n, f in groups if keyword.lower() in n.lower()]

    passed = failed = 0
    failed_names: list[str] = []
    for name, fn in groups:
        try:
            fn()
            passed += 1
            print(f"[ok] {name}")
        except Exception:
            failed += 1
            failed_names.append(name)
            print(f"[FAIL] {name}")
            traceback.print_exc(limit=3)

    print()
    print(f"组通过 {passed}/{len(groups)}，失败 {failed}")
    if failed_names:
        print("失败组：" + "、".join(failed_names))
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())

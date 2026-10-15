#!/usr/bin/env python3
"""UniMail 入口：初始化 → 登录 → 主窗口。

用法：
    python main.py              # 正常启动
    python main.py --seed       # 注入演示数据后启动（无需真实邮箱即可看界面）
    python main.py --reset      # 清空本地数据库后启动（谨慎使用）
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

from unimail.config import APP_NAME, DB_PATH, LOG_PATH
from unimail.core.security import SecurityError
from unimail.ui.context import AppContext
from unimail.ui.dialogs import LoginDialog
from unimail.ui.main_window import MainWindow
from unimail.ui.theme import STYLESHEET


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(LOG_PATH, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    # Qt 相关噪音降级
    logging.getLogger("PySide6").setLevel(logging.WARNING)


def reset_data() -> None:
    for suffix in ("", ".meta.json", "-wal", "-shm"):
        p = Path(str(DB_PATH) + suffix)
        if p.exists():
            p.unlink()
    print(f"已清空数据目录：{DB_PATH.parent}")


def run_login(ctx: AppContext) -> bool:
    """弹出登录对话框并解锁数据库。返回是否成功。"""
    attempts = 0
    while attempts < 3:
        dlg = LoginDialog(ctx.is_first_run)
        if dlg.exec() != QDialog.Accepted:
            return False
        try:
            if ctx.is_first_run:
                ctx.bootstrap_new(dlg.password)
            else:
                ctx.unlock(dlg.password)
            return True
        except SecurityError as exc:
            attempts += 1
            ctx.is_first_run = False
            QMessageBox.warning(
                None, "解锁失败",
                f"{exc}\n\n还可以尝试 {3 - attempts} 次。",
            )
    QMessageBox.critical(None, "已锁定", "连续多次输入错误，程序退出。")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=f"{APP_NAME} 多平台邮箱统一管理")
    parser.add_argument("--seed", action="store_true", help="注入演示数据")
    parser.add_argument("--reset", action="store_true", help="清空本地数据库")
    parser.add_argument("--verbose", action="store_true", help="输出调试日志")
    args = parser.parse_args()

    if args.reset:
        reset_data()

    setup_logging(args.verbose)

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setStyleSheet(STYLESHEET)

    ctx = AppContext()

    if args.seed:
        # 演示模式：首次运行时用固定主密码，自动注入样例数据
        demo_password = "unimail-demo"
        if ctx.is_first_run:
            ctx.bootstrap_new(demo_password)
        else:
            try:
                ctx.unlock(demo_password)
            except SecurityError:
                QMessageBox.critical(
                    None, "演示模式",
                    "现有数据库的主密码不是演示密码。\n"
                    "请先运行：python main.py --reset --seed",
                )
                return 1
        from unimail.demo import seed_demo_data
        seed_demo_data(ctx)
    else:
        if not run_login(ctx):
            return 0

    window = MainWindow(ctx)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())

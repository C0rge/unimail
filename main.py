#!/usr/bin/env python3
"""UniMail 入口：初始化 → 登录 → 主窗口。

用法：
    python main.py              # 正常启动
    python main.py --seed       # 注入演示数据后启动（无需真实邮箱即可看界面）
    python main.py --reset      # 清空本地数据库后启动（谨慎使用）
    python main.py --export-recovery [路径]   # 导出恢复包后退出
"""
from __future__ import annotations

import argparse
import logging
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

from unimail.config import APP_NAME, ATTACHMENT_DIR, DB_PATH, LOG_PATH, data_file_paths
from unimail.core.security import SecurityError
from unimail.storage import DatabaseError, sqlcipher_available
from unimail.ui.context import AppContext
from unimail.ui.dialogs import LoginDialog
from unimail.ui.main_window import MainWindow
from unimail.ui.settings import UiSettings
from unimail.ui.theme import ThemeManager


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


def reset_data(db_path: Path | None = None, attachment_dir: Path | None = None) -> None:
    """清空数据库及其全部伴随文件（含 sidecar 与备份）。

    侧车文件名是 `unimail.meta.json`（由 `DB_PATH.with_suffix` 得到），
    而不是 `unimail.db.meta.json`；历史清理列表漏了它，导致 `--reset`
    之后旧 salt 残留、新旧库无法配对。
    """
    removed = 0
    for p in data_file_paths(db_path or DB_PATH):
        if p.exists():
            p.unlink()
            removed += 1
    att_dir = attachment_dir or ATTACHMENT_DIR
    if att_dir.exists():
        shutil.rmtree(att_dir, ignore_errors=True)
        att_dir.mkdir(parents=True, exist_ok=True)
        removed += 1
    print(f"已清空数据目录（删除 {removed} 项）：{(db_path or DB_PATH).parent}")


def _wait_with_ui(seconds: float) -> None:
    """在冷却期内等待，同时保持界面响应（sleep 会整窗口卡死）。"""
    deadline = time.monotonic() + max(0.0, seconds)
    while time.monotonic() < deadline:
        QApplication.processEvents()
        time.sleep(0.05)


def run_login(ctx: AppContext) -> bool:
    """弹出登录对话框并解锁数据库。返回是否成功。

    尝试次数用尽后不再通过重启绕过：退避状态由 `UnlockGuard` 持久化在
    数据目录里，「关掉再开」不会把计数清零。

    冷却期在这里**先等完再弹对话框**：否则用户会被提示「请等待 N 秒」，
    却又立刻拿到一次注定被拒的尝试机会，白扣一次尝试次数。
    """
    from unimail.config import UNLOCK_MAX_ATTEMPTS
    from unimail.core.security import UnlockGuard

    attempts = 0
    while attempts < UNLOCK_MAX_ATTEMPTS:
        wait = UnlockGuard().remaining_wait()
        if wait > 0:
            QMessageBox.information(
                None, "请稍候",
                f"由于多次输入错误，解锁已被暂时限制。\n\n请等待 {wait:.0f} 秒后自动继续。",
            )
            _wait_with_ui(wait)
            continue
        dlg = LoginDialog(ctx.is_first_run)
        if dlg.exec() != QDialog.Accepted:
            return False
        try:
            if ctx.is_first_run:
                ctx.bootstrap_new(dlg.password)
            else:
                ctx.unlock(dlg.password)
            return True
        except DatabaseError as exc:
            # 库文件/加密模式层面的问题，重试密码没有意义，直接给出可操作提示
            QMessageBox.critical(None, "无法打开数据库", str(exc))
            return False
        except SecurityError as exc:
            attempts += 1
            ctx.is_first_run = False
            left = UNLOCK_MAX_ATTEMPTS - attempts
            QMessageBox.warning(
                None, "解锁失败",
                f"{exc}\n\n本次运行还可以尝试 {left} 次。\n"
                "（连续失败会触发递增等待，重启程序不会重置该限制。）",
            )
    QMessageBox.critical(
        None, "已锁定",
        "连续多次输入错误，程序退出。\n\n"
        "请稍后重新启动再试；如果确实忘记了主密码，数据无法通过任何方式恢复。",
    )
    return False


def offer_encryption_upgrade(ctx: AppContext) -> None:
    """已安装 SQLCipher 但库仍为明文时，提供一次性迁移入口。"""
    if not sqlcipher_available() or ctx.db is None or ctx.db.encrypted:
        return
    ret = QMessageBox.question(
        None, "启用整库加密",
        "当前数据库为**明文**存储：邮件主题、正文、发件人等信息可被本机其它程序读取。\n\n"
        "检测到环境已具备 SQLCipher，是否现在把数据库迁移为整库加密？\n"
        "（原明文库会自动备份为 *.plaintext.bak，迁移失败不会改动原库）",
        QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes,
    )
    if ret != QMessageBox.Yes:
        return
    try:
        ctx.migrate_encryption("encrypted")
    except Exception as exc:  # noqa: BLE001
        QMessageBox.warning(None, "迁移失败", f"数据库保持原状。\n\n{exc}")
    else:
        QMessageBox.information(None, "迁移完成", "数据库已启用整库加密。")


def main() -> int:
    parser = argparse.ArgumentParser(description=f"{APP_NAME} 多平台邮箱统一管理")
    parser.add_argument("--seed", action="store_true", help="注入演示数据")
    parser.add_argument("--reset", action="store_true", help="清空本地数据库")
    parser.add_argument("--verbose", action="store_true", help="输出调试日志")
    parser.add_argument("--theme", choices=("system", "dark", "light"),
                        help="临时覆盖主题（不写入设置文件）")
    parser.add_argument("--export-recovery", nargs="?", const="", default=None,
                        metavar="路径", help="导出恢复包后退出（不含任何密文）")
    args = parser.parse_args()

    if args.reset:
        reset_data()

    setup_logging(args.verbose)

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setQuitOnLastWindowClosed(False)     # 托盘常驻：关掉窗口不等于退出

    # 主题必须在**登录框之前**就绪：登录框本身也要按当前主题着色。
    # 这正是界面偏好存在明文 JSON（而不是加密库）里的原因。
    settings = UiSettings.load()
    if args.theme:
        settings.theme_mode = args.theme
    theme = ThemeManager(settings.theme_mode, settings.font_scale)
    theme.apply(app)

    ctx = AppContext()

    if args.export_recovery is not None:
        if not run_login(ctx):
            return 0
        try:
            path = ctx.export_recovery_bundle(args.export_recovery or None)
        except (SecurityError, OSError) as exc:
            QMessageBox.warning(None, "导出失败", str(exc))
            ctx.shutdown()
            return 1
        QMessageBox.information(
            None, "恢复包已导出",
            f"已导出到：\n{path}\n\n"
            "该文件只包含 salt / 迭代次数 / 算法标识，不含密码或任何密文，可离线保存。",
        )
        ctx.shutdown()
        return 0

    if args.seed:
        # 演示模式：首次运行时用固定主密码，自动注入样例数据
        from unimail.demo import DEMO_PASSWORD, seed_demo_data
        if ctx.is_first_run:
            ctx.bootstrap_new(DEMO_PASSWORD)
        else:
            try:
                ctx.unlock(DEMO_PASSWORD)
            except DatabaseError as exc:
                QMessageBox.critical(None, "无法打开数据库", str(exc))
                return 1
            except SecurityError:
                QMessageBox.critical(
                    None, "演示模式",
                    "现有数据库的主密码不是演示密码。\n"
                    "请先运行：python main.py --reset --seed",
                )
                return 1
        seed_demo_data(ctx)
    else:
        if not run_login(ctx):
            return 0
        offer_encryption_upgrade(ctx)

    window = MainWindow(ctx, settings, theme)
    window.show()
    code = app.exec()

    # 事件循环退出后再兜一次底：托盘模式下 `quit_app()` 是唯一出口，
    # 但用户可能在别处（比如系统关机）走到这里。
    try:
        ctx.shutdown(stop_timeout_ms=3000)
    except Exception:
        logging.getLogger(__name__).exception("退出清理失败")
    return code


if __name__ == "__main__":
    sys.exit(main())

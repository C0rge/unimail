"""全局配置：路径、常量、平台默认服务器参数。"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

APP_NAME = "UniMail"
APP_VERSION = "1.3.0"

# ---------------------------------------------------------------- 数据目录
def _data_dir() -> Path:
    """跨平台用户数据目录。"""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    elif sys.platform == "darwin":
        base = str(Path.home() / "Library" / "Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    p = Path(base) / APP_NAME
    p.mkdir(parents=True, exist_ok=True)
    return p


DATA_DIR: Path = _data_dir()
DB_PATH: Path = DATA_DIR / "unimail.db"
ATTACHMENT_DIR: Path = DATA_DIR / "attachments"
LOG_PATH: Path = DATA_DIR / "unimail.log"
ATTACHMENT_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------- 安全参数
# 主密码派生：默认 Argon2id（内存硬，GPU 相对 CPU 的优势基本失效）。
# PBKDF2 的参数保留，用于「旧库仍以 PBKDF2 派生」时的兼容校验与渐进升级。
KDF_ALGORITHM = "argon2id"        # argon2id | pbkdf2
KDF_ITERATIONS = 600_000          # 仅 PBKDF2 使用
KDF_SALT_BYTES = 16
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 64 * 1024    # 64 MiB
ARGON2_PARALLELISM = 1
ARGON2_HASH_LEN = 32

# 主密码策略：下限 12 位。600k 次 PBKDF2 实测仅 0.069 s（单核 ~14 次/秒），
# 6 位密码在字典攻击下是分钟级；这是「弱口令 = 全量邮件泄露」最现实的入口。
PASSWORD_MIN_LENGTH = 12
UNLOCK_MAX_ATTEMPTS = 5               # 单次运行内的尝试次数上限（配合退避）
UNLOCK_BACKOFF_BASE = 1.0             # 退避基数（秒）：1,2,4,8… 上限见下
UNLOCK_BACKOFF_MAX = 30.0

DB_VERSION = 4                    # v4: 重建列表筛选相关索引
AUTO_LOCK_SECONDS = 15 * 60       # 空闲自动锁定

# TLS 证书校验：默认强制校验。仅在明确知晓风险时（如企业自建服务器使用自签证书），
# 通过环境变量 UNIMAIL_ALLOW_INVALID_CERT=1 显式关闭。
ALLOW_INVALID_TLS_CERT = (
    os.environ.get("UNIMAIL_ALLOW_INVALID_CERT", "").strip().lower()
    in {"1", "true", "yes", "on"}
)

# ---------------------------------------------------------------- 同步参数
DEFAULT_SYNC_INTERVAL = 300       # 秒，默认 5 分钟
SYNC_PAGE_SIZE = 200              # 增量同步每页拉取的邮件数
INITIAL_FETCH_LIMIT = 100         # 首次同步（游标为空）每页拉取的邮件数
MAX_FETCH_PER_RUN = 5000          # 首次同步单次运行入库上限，0 = 不限
SCHEDULER_TICK = 30               # 调度器心跳（秒）
FETCH_TIMEOUT = 30                # IMAP 超时

# ---------------------------------------------------------------- 附件
MAX_ATTACHMENT_BYTES = 50 * 1024 * 1024    # 单个附件下载上限，0 = 不限
# 危险扩展名：下载后不还原成可执行后缀，而是保留 .download 并在 UI 显式警示，
# 避免「双击附件即执行」这条最常见的诱导路径。
DANGEROUS_EXTENSIONS = frozenset({
    "exe", "com", "scr", "pif", "bat", "cmd", "ps1", "psm1", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "hta", "jar", "msi", "msp", "cpl", "dll",
    "lnk", "url", "iso", "img", "vhd", "reg", "apk", "app", "dmg", "sh",
    "run", "desktop", "scf", "chm",
})

# ---------------------------------------------------------------- 数据库
DB_BUSY_TIMEOUT_MS = 5000         # 并发写等待锁超时
DB_CACHE_KIB = 8000               # 每连接页缓存（负值语义：KiB）


def sqlcipher_pip_hint() -> str:
    """SQLCipher 安装命令。

    历史上这里按平台返回两个不同的包名，但 `sqlcipher3-binary` 实际只发布了
    **Linux x86_64** 轮子——macOS 和 Linux aarch64 用户照着提示装必然失败。
    `sqlcipher3-wheels` 是唯一在 Windows / macOS / Linux 三端都提供预编译轮子
    的发行线，因此全平台统一提示它。

    版本锁 0.5.6：0.5.7 与 `PRAGMA cipher_memory_security = ON` 组合在 Windows
    上会栈溢出崩溃进程（requirements.txt 里同样锁定）。
    """
    return 'pip install "sqlcipher3-wheels==0.5.6"'

# ---------------------------------------------------------------- 平台定义
@dataclass(frozen=True)
class PlatformConfig:
    """一个邮箱平台的连接与提示信息。"""
    key: str
    name: str
    imap_host: str
    imap_port: int
    use_ssl: bool
    auth_hint: str
    help_url: str = ""
    requires_oauth: bool = False


PLATFORMS: dict[str, PlatformConfig] = {
    "qq": PlatformConfig(
        key="qq",
        name="QQ 邮箱",
        imap_host="imap.qq.com",
        imap_port=993,
        use_ssl=True,
        auth_hint="需在「设置 → 账户 → POP3/IMAP/SMTP」开启 IMAP 服务，"
                  "并使用生成的 16 位「授权码」，不是 QQ 登录密码。",
        help_url="https://service.mail.qq.com/detail/0/75",
    ),
    "163": PlatformConfig(
        key="163",
        name="网易 163 邮箱",
        imap_host="imap.163.com",
        imap_port=993,
        use_ssl=True,
        auth_hint="需在「设置 → POP3/SMTP/IMAP」开启 IMAP 服务，"
                  "使用生成的「授权码」作为密码。",
        help_url="https://help.mail.163.com/faqDetail.do?code=d7a5dc8471cd0c0e8b4b8f4f8e49998b",
    ),
    "gmail": PlatformConfig(
        key="gmail",
        name="Gmail",
        imap_host="imap.gmail.com",
        imap_port=993,
        use_ssl=True,
        auth_hint="需先开启两步验证，然后在「应用专用密码」中生成 16 位密码。",
        help_url="https://support.google.com/accounts/answer/185833",
    ),
    "outlook": PlatformConfig(
        key="outlook",
        name="Outlook / Microsoft 365",
        imap_host="outlook.office365.com",
        imap_port=993,
        use_ssl=True,
        auth_hint="微软已停用基础认证，建议开启两步验证后在「安全 → 应用密码」生成密码；"
                  "企业租户需管理员开启 IMAP。",
        help_url="https://support.microsoft.com/account-billing/app-passwords",
    ),
    "custom": PlatformConfig(
        key="custom",
        name="自定义 IMAP",
        imap_host="",
        imap_port=993,
        use_ssl=True,
        auth_hint="手动填写 IMAP 服务器地址、端口与加密方式。",
    ),
}


def platform_name(key: str) -> str:
    cfg = PLATFORMS.get(key)
    return cfg.name if cfg else key


def sidecar_path(db_path: Path | None = None) -> Path:
    """安全元数据（salt/迭代次数/校验块/驱动）的侧车文件路径。"""
    return (db_path or DB_PATH).with_suffix(".meta.json")


def guard_path(db_path: Path | None = None) -> Path:
    """解锁失败退避的持久化文件路径。

    文件里只有「失败次数 + 下次可用时间」，不含任何密钥或密文，
    因此可以明文保存——它的作用是让退避**跨进程重启依然生效**
    （否则「关掉再打开」就等于把尝试次数清零）。
    """
    return (db_path or DB_PATH).with_suffix(".guard.json")


def data_file_paths(db_path: Path | None = None) -> list[Path]:
    """数据库相关的全部本地文件：主库、WAL/SHM/journal、侧车及其备份/临时文件。

    「重置数据」与「备份」都必须覆盖同一组文件——历史上清理列表漏掉了真正的
    侧车文件名，导致 `--reset` 之后旧 salt 残留、新旧库无法配对。
    """
    db = db_path or DB_PATH
    files = [
        db,
        Path(str(db) + "-wal"),
        Path(str(db) + "-shm"),
        Path(str(db) + "-journal"),
    ]
    meta = sidecar_path(db)
    files += [meta, meta.with_name(meta.name + ".bak"), meta.with_name(meta.name + ".tmp")]
    files.append(guard_path(db))
    return files


def platform_color(key: str) -> str:
    """每个平台一个主题色，用于 UI 标识。"""
    return {
        "qq": "#12b7f5",
        "163": "#d93a37",
        "gmail": "#ea4335",
        "outlook": "#0078d4",
        "custom": "#7a5af8",
    }.get(key, "#64748b")

"""全局配置：路径、常量、平台默认服务器参数。"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

APP_NAME = "UniMail"
APP_VERSION = "1.7.0"

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

DB_VERSION = 9                    # v9: contacts 通讯录（自动学习 + 手动管理）
AUTO_LOCK_SECONDS = 15 * 60       # 空闲自动锁定
IDLE_POLL_SECONDS = 20            # 空闲检查间隔（秒）

# 服务端标记双向同步：把「标已读 / 星标」写回 IMAP（UID STORE ±FLAGS）。
# 关闭后只在本地生效，多设备间状态会不一致。UI 提供开关，默认开启。
SYNC_SERVER_FLAGS = True
# 附件内联预览的单文件上限（超过则不预览，只允许下载）
MAX_PREVIEW_BYTES = 8 * 1024 * 1024

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


def _int_env(name: str, default: int) -> int:
    """从环境变量读一个整数；缺失或非法时回落到默认值。

    非法值**必须**回落到默认而不是当成 0：`0` 在本项目里表示「不限」，
    把打错的 `UNIMAIL_MAX_FETCH_PER_RUN=5O0`（字母 O）解释成「不限」，
    正好把用户想要的那个上限变成没有上限。
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        print(f"[warn] 环境变量 {name}={raw!r} 不是整数，已按默认值 {default} 处理",
              file=sys.stderr)
        return default
    if value < 0:
        print(f"[warn] 环境变量 {name}={value} 为负，已按默认值 {default} 处理",
              file=sys.stderr)
        return default
    return value


# 一次同步**最多入库多少封**（0 = 不限）。
#
# 为什么是 500 而不是 5000：这个数不是「能拉多少」的能力上限，而是
# 「一次同步愿意占用多久」的时间预算。它约束的是首次同步（或长时间离线后
# 的追平）这类突发场景 —— 在这些场景下，一次运行就把几万封灌进去会：
#   1. 长时间占着一条 IMAP 连接（服务器侧可能判定为异常并限速）；
#   2. 在 GUI 线程上连续触发多批增量插入与计数刷新，界面一阵阵地顿；
#   3. 让「失败重来」的代价变得极高（重跑一次要等几分钟）。
# 500 封配合 `SYNC_PAGE_SIZE` / `INITIAL_FETCH_LIMIT` 大约是 3–5 个往返批次，
# 单次耗时可控，且**剩余邮件会在下一次同步继续**（游标已按连续区间推进）。
#
# 调整方式（三选一，后者覆盖前者）：
#   · 改这里的默认值；
#   · 设环境变量 UNIMAIL_MAX_FETCH_PER_RUN=300（或 500）；
#   · 设 0 表示「不限」——只有在明确知道自己在做什么时才这么做。
MAX_FETCH_PER_RUN = _int_env("UNIMAIL_MAX_FETCH_PER_RUN", 500)


def _bool_env(name: str, default: bool) -> bool:
    """读一个布尔环境变量；缺失或无法识别时回落到默认值。"""
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    print(f"[warn] 环境变量 {name}={raw!r} 不是布尔值，已按默认值 {default} 处理",
          file=sys.stderr)
    return default


# 加密迁移成功后是否保留 `unimail.db.plaintext.bak`。
#
# 默认 False：那份文件是**全量明文**，同步盘、旧硬盘、任何能读数据目录的
# 进程都能直接拿到全部邮件；留着它，「整库加密」就只是给主文件加了把锁，
# 旁边却放着没锁的副本。迁移在这之前已经校验过新库可打开、行数一致，
# 所以正常路径下没有保留的必要。
#
# 仅在排查迁移问题时临时设为 1；设置后程序会在日志里持续告警。
KEEP_PLAINTEXT_BACKUP = _bool_env("UNIMAIL_KEEP_PLAINTEXT_BACKUP", False)

SCHEDULER_TICK = 30               # 调度器心跳（秒）
FETCH_TIMEOUT = 30                # IMAP 超时

# ---------------------------------------------------------------- 网络与代理
# 代理由环境变量 `UNIMAIL_PROXY` 配置，取值形如：
#     socks5://127.0.0.1:7890
#     http://user:pass@127.0.0.1:8080
#     auto                                  ← 读操作系统的「系统代理」设置
#     env                                   ← 读 ALL_PROXY / HTTPS_PROXY / HTTP_PROXY
# 留空 = 直连（默认）。
#
# 为什么必须显式配置、而不是「有系统代理就自动用」：imaplib 只做直连，
# 而系统代理通常意味着一个只转发 HTTP(S) 的代理；把它自动套到 IMAP 的
# 993 端口上，会让本来能直连的用户变成连不上。同理，`HTTP_PROXY` 这类被
# 工具链预置的变量也不被隐式参考 —— 要用就显式写 `env`。
#
# **这里刻意不定义 `PROXY` 常量**：代理在**连接时**由
# `platforms/proxy.py::resolve_proxy()` 直接读环境变量解析，不在模块导入时
# 快照。快照会带来两个真问题——测试里 patch 环境变量将不再生效，且
# `auto` 无法反映运行中途改过的系统设置。语义与全部取值见 proxy.py。

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
# 内存映射 I/O 窗口（字节）。列表滚动、会话展开全是随机读，走 mmap 可以省掉
# 一次内核到用户态的 copy。取值不宜超过可用地址空间；256 MB 对桌面端是安全的。
DB_MMAP_BYTES = 256 * 1024 * 1024


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
    # 垃圾箱文件夹的**候选名**，仅在前者缺失时使用的兜底。
    # 首选判据始终是 LIST 响应里的 `\Trash` 特殊用途属性（RFC 6154）：
    # 同一家邮箱的中文版 / 英文版界面给出的文件夹名并不一致
    # （Gmail 中文版是「废件箱」而不是 `[Gmail]/Trash`），靠名字匹配必然有漏网。
    # 这里只是「服务器不宣告 \Trash」时的第二道防线，因此允许写多个候选。
    trash_candidates: tuple[str, ...] = ()


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
        trash_candidates=("Deleted Messages", "已删除"),
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
        trash_candidates=("已删除", "Deleted Messages", "Trash"),
    ),
    "gmail": PlatformConfig(
        key="gmail",
        name="Gmail",
        imap_host="imap.gmail.com",
        imap_port=993,
        use_ssl=True,
        auth_hint="需先开启两步验证，然后在「应用专用密码」中生成 16 位密码。",
        help_url="https://support.google.com/accounts/answer/185833",
        trash_candidates=("[Gmail]/Trash", "[Gmail]/Bin", "[Gmail]/废件箱"),
    ),
    "outlook": PlatformConfig(
        key="outlook",
        name="Outlook / Microsoft 365",
        imap_host="outlook.office365.com",
        imap_port=993,
        use_ssl=True,
        # 微软已于 2024-09-16 停用个人 Outlook.com 的 IMAP/POP/SMTP 基础认证，
        # Exchange Online 更早；应用密码在这些协议上不再被接受。
        # 也就是说「用户名 + 应用密码」不是配置技巧问题，而是服务端取消了该能力。
        auth_hint="微软已停用 IMAP 基础认证（应用密码不再可用），必须使用 OAuth2 授权。"
                  "点击下方「OAuth2 授权」按钮，按提示在浏览器里完成登录；"
                  "企业租户还需管理员为账号开启 IMAP。",
        requires_oauth=True,
        help_url="https://support.microsoft.com/account-billing/app-passwords",
        trash_candidates=("Deleted Items", "已删除邮件", "Deleted"),
    ),
    "custom": PlatformConfig(
        key="custom",
        name="自定义 IMAP",
        imap_host="",
        imap_port=993,
        use_ssl=True,
        auth_hint="手动填写 IMAP 服务器地址、端口与加密方式。",
        trash_candidates=("Trash", "Deleted Items", "Deleted Messages", "已删除"),
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
    """数据目录里**全部**由本程序生成的文件。

    刻意把「看起来不像数据库」的那些也算进来：加密迁移留下的
    `*.plaintext.bak` / `*.encrypted.bak`、设备绑定密钥、UI 设置、日志、
    恢复包。`--reset` 承诺的是「彻底移除」，漏一个文件承诺就失效——
    历史上就漏过一次侧车文件名（写成 `unimail.db.meta.json` 而非
    `unimail.meta.json`），导致旧 salt 残留、新旧库无法配对。

    通配是在 `db.parent` 上做的，所以测试用临时目录时不会误伤真实数据目录。
    """
    db = db_path or DB_PATH
    data_dir = db.parent
    stem = db.name
    files = [
        db,
        Path(str(db) + "-wal"),
        Path(str(db) + "-shm"),
        Path(str(db) + "-journal"),
    ]
    meta = sidecar_path(db)
    files += [meta, meta.with_name(meta.name + ".bak"), meta.with_name(meta.name + ".tmp")]
    files.append(guard_path(db))

    # 迁移过程的中间态与整份副本：一份明文库就等于整库加密白做了
    for pattern in (
        f"{stem}.plaintext.bak",
        f"{stem}.encrypted.bak",
        f"{stem}.enc-tmp",
        f"{stem}.plain-tmp",
        f"{stem}.*.tmp",
        "device.key",
        "ui.json",
        "unimail-recovery.json",
        "unimail.log*",
    ):
        files.extend(sorted(data_dir.glob(pattern)))

    seen: set[Path] = set()
    ordered: list[Path] = []
    for p in files:
        if p not in seen:
            seen.add(p)
            ordered.append(p)
    return ordered


def plaintext_backup_paths(db_path: Path | None = None) -> list[Path]:
    """数据目录里所有**明文**数据库副本（迁移备份与半成品）。

    单独抽出来是因为它有一条独立的安全语义：只要这些文件还在，
    「整库加密」就没有真正兑现。启动时据此提示，迁移后据此清理。
    """
    db = db_path or DB_PATH
    stem = db.name
    found = [
        db.parent / f"{stem}.plaintext.bak",
        db.parent / f"{stem}.plain-tmp",
    ]
    return [p for p in found if p.exists()]


def platform_color(key: str) -> str:
    """每个平台一个主题色，用于 UI 标识。"""
    return {
        "qq": "#12b7f5",
        "163": "#d93a37",
        "gmail": "#ea4335",
        "outlook": "#0078d4",
        "custom": "#7a5af8",
    }.get(key, "#64748b")

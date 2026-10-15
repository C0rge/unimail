# UniMail — 多平台邮箱统一管理程序

统一管理 QQ 邮箱 / 163 / Gmail / Outlook / 自定义 IMAP 的本地桌面客户端（Python + PySide6）。

**完整架构设计见 [`docs/架构设计.md`](docs/架构设计.md)** —— 包含分层架构、模块划分、数据结构、业务流程时序图与安全方案。

## 功能

- ✉️ 多账号管理：添加（带凭据试连）/ 删除 / 切换，各平台差异全部由适配器吸收
- 📥 统一收件箱：聚合所有账号邮件，发件人 / 主题 / 时间 / 预览，未读加粗高亮
- 🔍 多维筛选：平台、关键词（防抖搜索）、时间范围（预设 + 自定义）、仅未读
- 📄 邮件详情：正文渲染（HTML 已清洗，屏蔽远程跟踪像素）+ 附件真实下载
- ⚡ 正文按需拉取：列表先同步头部快速呈现，点开邮件时后台补拉完整正文
- 🔄 自动同步：IMAP UID 增量拉取 + 按账号周期定时刷新 + 失败指数退避
- 🔐 本地加密：主密码经 **Argon2id**（内存硬性 64 MiB）派生主密钥，再经 HKDF 分出数据库密钥与凭据密钥；凭据 Fernet 加密；SQLCipher 整库 AES-256 加密（可选）。旧库的 PBKDF2 参数写入 sidecar 以便继续校验，改主密码时自动升级到当前默认算法
- 🔒 空闲 15 分钟自动锁定；主密码连续输错按 1/2/4/8… 秒退避（**跨进程持久化**，重启不清零）

## 更新日志

见 [`CHANGELOG.md`](CHANGELOG.md)。当前版本 **v1.3.0**。

## 许可证

[MIT](LICENSE)

## 快速开始

```bash
# 1. 安装依赖（Python 3.10+）
pip install -r requirements.txt

# 2a. 演示模式：注入示例数据，无需真实邮箱
python main.py --seed

# 2b. 正常使用：设置主密码后添加自己的邮箱
python main.py
```

> 演示模式主密码为 `unimail-demo`（**仅演示模式**；正常使用时首次设置的主密码要求至少 12 位，并会实时提示强度）。

**可选增强**：`pip install "sqlcipher3-wheels==0.5.6"` 可启用整库 AES-256 加密（未安装时自动降级为 SQLite + 字段级加密，启动时会明确提示当前加密等级）。库文件由哪种驱动创建会记在 sidecar 中，因此先降级运行、之后补装 SQLCipher 也能正常打开，并可在启动提示或「文件 → 数据库加密设置」中一键迁移。

> 为什么是 `sqlcipher3-wheels` 而不是 `sqlcipher3-binary`：后者只发布了 **Linux x86_64** 轮子，Windows / macOS / Linux aarch64 上都装不到预编译版本。`sqlcipher3-wheels` 是唯一在 Windows、macOS、Linux 三端都有轮子的发行线。版本锁在 0.5.6 是因为 0.5.7 在 Windows 上与 `PRAGMA cipher_memory_security = ON` 组合会栈溢出崩溃（详见 `requirements.txt` 注释）。

**备份与恢复**：`文件 → 导出恢复包`（或 `python main.py --export-recovery [路径]`）会导出 salt / 迭代次数 / 算法标识，**不含任何密文**。侧车文件 `unimail.meta.json` 损坏时，靠它可以重新派生数据库密钥，建议离线保存一份。

**TLS 证书校验**：客户端默认**强制校验** IMAP 服务器证书与主机名。仅在连接使用自签证书的自建服务器、且明确知晓风险时，才设置环境变量 `UNIMAIL_ALLOW_INVALID_CERT=1` 放行。

## 添加真实邮箱须知

| 平台 | 密码要求 |
|---|---|
| QQ 邮箱 | 设置 → 账户 → 开启 IMAP，使用 16 位**授权码**（不是 QQ 密码） |
| 163 | 设置 → 开启 IMAP/SMTP，使用**授权码** |
| Gmail | 开启两步验证后生成**应用专用密码** |
| Outlook | 微软已停用基础认证，需应用密码（完整方案应接 OAuth2） |

## 测试

```bash
# 核心层回归套件：24 组、246~249 项断言（差异取决于是否装了 SQLCipher）
python tests/smoke.py
```

两套环境都要跑一遍，因为 SQLCipher 是否存在会走两条不同的代码路径：

| 环境 | 覆盖的路径 |
|---|---|
| 未装 `sqlcipher3-wheels` | SQLite + 字段级加密（降级模式），迁移入口应被明确拒绝 |
| 已装 `sqlcipher3-wheels` | 整库 AES-256，含 v3→v4 迁移、迁移中断回滚 |

开发/CI 依赖（lint + 类型检查 + 漏洞扫描）见 `requirements-dev.txt`：

```bash
pip install -r requirements-dev.txt
ruff check .            # 静态检查
mypy                    # 类型检查
pip-audit -r requirements.txt   # 依赖漏洞扫描
```

## 目录结构

```text
unimail/
├── main.py                  # 入口（--seed / --reset / --export-recovery）
├── requirements.txt         # 运行依赖（含 SQLCipher 驱动）
├── requirements-dev.txt     # 开发/CI 依赖
├── requirements.lock        # 已验证的版本组合
├── pyproject.toml           # ruff / mypy / pytest 配置
├── .github/workflows/ci.yml # CI：lint + 类型检查 + 双环境测试 + 漏洞扫描
├── docs/架构设计.md          # 完整架构设计文档
├── tests/smoke.py           # 核心层回归套件
└── unimail/
    ├── config.py            # 平台配置 / 路径 / 安全参数
    ├── core/                # 领域模型 / 安全服务 / 用例服务 / 事件总线
    ├── storage/             # 加密数据库 + 仓储层
    ├── platforms/           # IMAP 适配器（QQ/163/Gmail/Outlook/自定义）+ MIME 解析
    ├── sync/                # QThread 同步工作单元 + 心跳调度器
    └── ui/                  # PySide6 三栏界面（主题/面板/对话框）
```

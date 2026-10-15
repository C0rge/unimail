# 更新日志

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.3.0] - 2026-10-15

第二批「性能与不可信输入加固」落地（对应《UniMail 代码架构与迭代升级分析报告》§五 第 2 批，G1–G5）。
本版同样不引入新功能：一半是把同步与列表的**算法/IO 复杂度**降下来，另一半是把
**来自第三方邮件的不受信数据**（MIME 结构、HTML、附件名、编码标注）关进笼子。

### ⚡ 性能

- **同步改为批量写入（G1）**：整页邮件头由「逐封 `insert` + 逐封事务」改为
  **一次 `executemany` + 单事务**，附件元数据同批落库；正文回填也改成批量
  `update`。5 万封邮箱首同步的写事务数从 O(N) 降到 O(N/页)。
  `insert_mails_batch()` 用 `total_changes` 增量做**精确记账**，冲突行不再
  污染统计；被 `OR IGNORE` 跳过的邮件其附件行会被一并剔除，
  避免留下指向不存在邮件的孤儿附件记录。
- **列表查询只取投影（G1）**：新增 `MailSummary` 与 `query_summaries()`。
  列表页不再把每封邮件的 `body_text` / `body_html` 搬进内存
  （此前 300 行列表要顺带加载整页正文），改用
  `MAIL_SUMMARY_COLUMNS` 显式列投影。
- **补齐复合索引（G2）**：新增 `(is_read, date DESC)` 与
  `(account_id, is_read, date DESC)`，覆盖「仅未读 + 按时间倒序」这条最常用
  的查询路径，消除 `TEMP B-TREE` 排序。测试用 `EXPLAIN QUERY PLAN`
  断言不再出现临时 B 树。
- **计数改为增量快照（G1）**：`counts_snapshot()` + 2 秒 TTL 缓存，
  未读数不再每次刷新都对全表 `COUNT(*)`；所有已知写入路径显式失效缓存，
  并有 TTL 兜底防止长期错下去。

### 🔒 安全与健壮性

- **HTML 白名单清洗（G3）**：`<script>` 等标签改用**白名单重建**替代原来的
  黑名单正则——黑名单永远漏（`<scr<script>ipt>`、`<svg onload>`、畸形嵌套、
  未闭合注释都能绕过）。现在只保留内容型标签与安全属性，
  `javascript:` / 远程 URL 一律剥离，`on*` 事件属性全丢。
- **详情面板阻断远程加载（G3）**：`SafeTextBrowser.loadResource()` 重写，
  拒绝一切远程 URL，从根上断掉 HTML 邮件里的跟踪像素；统计被拦次数供 UI 提示。
- **附件文件名净化（G5）**：新增 `safe_attachment_name()`，把第三方提供的
  文件名压成纯名字——去掉路径分隔符、`..`、控制字符、Windows 保留设备名
  （`CON`/`NUL`/`COM1`…）、结尾空白与点、超长串。落盘时仍叠加
  「`<附件 id 前 8 位>_` 前缀 + 只在本程序专属目录内拼接」这第二层。
- **编码回落的 mojibake 检测（G5）**：`_decode_best()` 先按声明的 charset
  严格解码；只有解出的结果带强乱码信号（私用区 / `U+FFFD` / C1 控制符）
  时才试 UTF-8 / GB18030，且**只有确实更干净**才替换。既不放过
  「声明 gb2312 实际是 UTF-8」的常见错误标注，也不会把正常的
  GB2312/Big5/Shift_JIS 邮件「救」成乱码。
- **危险扩展名不还原可执行后缀**：`.exe`/`.bat`/`.scr` 等落盘时保留
  `.download` 后缀并在 UI 带上 ⚠️ 警示；已下载复用时以**磁盘上的真实文件名**
  判断，不再对着旧版本落下的原后缀文件声称「已改写」。

### 🧪 测试

- 套件从 12 组 101 项扩充到 **24 组 246~249 项**（差异取决于是否装了 SQLCipher）。
  新增 12 组：批量写入与列表投影、索引与查询计划、HTML 白名单清洗、
  BODYSTRUCTURE 附件元数据、同步回填附件信息、附件落盘安全策略、
  孤儿附件清理、KDF 算法与密码策略、KDF 渐进升级、解锁退避持久化、
  **恶意 MIME 语料**、**关键路径中断注入**。
- 「恶意 MIME 语料」用 13 条真实世界的畸形报文（空报文、不做边界闭合的
  multipart、40 层深嵌套、charset 谎言、垃圾 base64、截断编码头、10 万字符
  主题、路径穿越式附件名、XSS/跟踪像素、CRLF）断言解析链路**不抛异常**。
- 「关键路径中断注入」在四个写入点注入故障：事务中途抛错、附件落盘 `fsync`
  失败、侧车 `os.replace` 失败、整库迁移校验失败，断言每次都**不留半成品**
  （无 `.part` / `.tmp` / `.enc-tmp` 残骸）、原数据未被改写、
  数据库对象被自动恢复为可用。
- 新增 `pyproject.toml`（ruff / mypy / pytest 配置）、`requirements-dev.txt`、
  `requirements.lock`，以及 `.github/workflows/ci.yml`
  （静态检查 + 类型检查 + 漏洞扫描 + 双平台 × 双 Python × 有无 SQLCipher 的测试矩阵）。

### 🗂 迁移说明

- 数据库版本 `v3 → v4`：新增 `(is_read, date DESC)` 与
  `(account_id, is_read, date DESC)` 两个复合索引，迁移幂等。
  从 v1.2.0 及更早版本升级会自动执行；无数据格式变更，可安全回退。
- **已知残留风险（未修）**：整库加/解密迁移用两次 `os.replace` 完成，
  若在两次替换之间掉电，会留下「主文件缺失、数据在 `.plaintext.bak` 里」
  的状态——数据没丢但需要手工改名恢复。已在 `database.py` 的 docstring 中
  写明。彻底修掉需要「同目录写新文件 + 单次 `os.replace` + 目录项 fsync」的
  重写，留到后续版本。

---

## [1.2.0] - 2026-10-15

第一批「安全止血 + 数据保全」落地（对应《UniMail 代码架构与迭代升级分析报告》§五 第 1 批）。
本版不引入新功能，只修「修复成本低、失效后果重」的缺陷。

### 🔒 安全

- **【严重】IMAP TLS 不校验服务器证书**
  `IMAP4_SSL` 未传 `ssl_context`，CPython 会退回 `ssl._create_stdlib_context()`
  （`verify_mode=CERT_NONE`、`check_hostname=False`），任何能劫持 DNS/网关的
  攻击者都可用自签证书冒充 `imap.qq.com` 直接拿到用户的 16 位授权码。
  现在统一传入加固上下文：`CERT_REQUIRED` + `check_hostname` + `TLSv1.2` 下限；
  证书校验失败会映射成可读提示而非裸 `ssl` 异常。
  如需连接使用自签证书的自建服务器，必须显式设置 `UNIMAIL_ALLOW_INVALID_CERT=1`。
- **取消静默降级**：143 端口 STARTTLS 握手失败时不再 `pass` 继续明文登录，
  而是中止连接并说明原因，避免「以为走的是加密」实际明文传凭据。

### 🛡 数据保全

- **【严重】首次同步静默丢失邮件**
  `search_new_uids()` 返回的是 `uids[-limit:]`（最新 200 条），游标又被直接推到
  邮箱末尾：5 万封的邮箱首同步只入库最新 200 封，其余永久不再拉取。
  现在改为**返回最旧的一批**并分页循环直到追平，游标只推进到
  「连续已抓取区间」的最大 UID；单封拉取失败时游标停在该封之前，下次续拉。
- **【严重】UIDVALIDITY 变化后新邮件被静默丢弃**
  服务器端邮箱重建后 UID 会复用，新邮件会撞上 `UNIQUE(account_id, folder, uid)`
  并被 `insert_mail()` 静默 `return None`。现在新增 `mails.uid_validity` 列
  （v3 迁移，按游标回填），检测到本地记录的 UIDVALIDITY 与服务端不一致时
  先清理该文件夹的过期本地副本、再重置游标重新同步。
- **【严重】侧车文件非原子写**
  `_write_security_meta()` 直接 `write_text` 覆盖：此时掉电/崩溃 → 半截 JSON →
  salt 丢失 → **加密数据库永久无法解密**。现在改为
  「临时文件 + `fsync` + 旧文件备份 `.bak` + `os.replace`」；
  读取时主文件损坏自动回退 `.bak` 并自愈。
- **`--reset` 清理路径错误**：删的是 `unimail.db.meta.json`，而真正的侧车是
  `unimail.meta.json`，导致重置后旧 salt 残留。现在统一由
  `config.data_file_paths()` 给出完整清单（主库 + WAL/SHM/journal + 侧车 + `.bak`/`.tmp`），
  并一并清空附件目录。
- **新增「导出恢复包」**（文件菜单 / `--export-recovery`）：导出 salt、迭代次数、
  算法标识与驱动，**不含任何密文**，用于侧车损坏时离线重建派生参数。

### 🧩 加密模式与并发

- **降级/升级路径打通**：库文件的创建驱动记录在 sidecar 与 `meta.driver` 两处，
  打开时以 sidecar 为准决定是否下发 `PRAGMA key`。明文库不会再被当成加密库打开
  （此前装上 SQLCipher 后会出现 `file is not a database`、应用彻底打不开、
  且没有自救入口）；旧版 sidecar（无 `driver` 字段）会自动双向探测并回写结论。
- **缺少 SQLCipher 时 fail-closed**：给出「请安装 sqlcipher3」的可操作提示，
  而不是抛底层错误。
- **新增迁移入口**：`Database.migrate_to_encrypted()` / `migrate_to_plaintext()`
  （官方 `sqlcipher_export` 配方 + 行数校验 + 原库备份 + 原子替换），
  首次以明文启动且环境具备 SQLCipher 时会询问是否立即启用整库加密。
- **数据库并发三件套**
  ① `transaction()` 现在持有写锁，避免与其它线程的 autocommit 写入交错、
  也避免事务内 `execute()` 提前 commit 破坏事务边界；
  ② 连接统一设置 `busy_timeout=5000` / `synchronous=NORMAL` / `temp_store=MEMORY` / `cache_size`；
  ③ 新增连接注册表，`close()` 回收**所有线程**的连接并执行 `wal_checkpoint(TRUNCATE)`。
- **改主密码与后台同步的竞态**：改密/迁移前后暂停并恢复调度器、排空同步线程，
  避免旧密钥建立的连接在 rekey 中途写入。

### 🧪 测试

- 新增 8 组、50 项断言（合计 **94 项**）：
  TLS 证书校验与传参、升级提示映射、`search_new_uids` 取最旧一批、
  分页追平、UIDVALIDITY 清理、单封失败游标不跳过、
  侧车原子写/`.bak` 回退/恢复包不含密文、`--reset` 清理路径、
  数据库并发（busy_timeout / 事务持锁 / 事务内 execute 不提前提交 / 连接回收）、
  加密模式 fail-closed、v1 → v3 迁移与历史行回填、旧版 sidecar 自动探测。
- 新增依赖：`PySide6`（测试与运行所需）、`cryptography`。

### 🗂 迁移说明

- 数据库版本 `v2 → v3`：新增 `mails.uid_validity`（`NOT NULL DEFAULT 0`）与
  索引 `idx_mails_validity`，历史行按 `sync_cursors` 回填。迁移在事务外幂等执行，
  索引在迁移完成后创建（避免老库缺列时建索引失败）。
- 侧车文件新增 `driver` / `app_version` / `updated_at` 字段，向后兼容旧文件。

---

## [1.1.0] - 2026-10-15

修复 v1.0.0 的重度缺陷，并补全附件与正文的完整链路。

### 🐛 修复

- **【严重】修改主密码导致所有邮箱凭据永久失效**
  v1.0.0 中改密码只重加密了数据库，未用新密钥重新加密 `credentials` 表，
  导致改完密码后所有账号的密码再也解不开、同步全部失败，只能删号重加。
  现在改为：先用旧密钥取出全部明文凭据 → 换密钥 → 重加密数据库 →
  用新密钥写回凭据，且任一步失败都会回滚，不产生中间态损坏。

- **【严重】附件下载返回的是占位文本**
  v1.0.0 的 `download_attachment()` 实际写入的是一段"占位内容"字符串，
  并非真实文件。现已实现完整的 IMAP 拉取链路：
  查附件所属邮件的 account/folder/uid/part → 取凭据 → 连接 IMAP →
  `FETCH BODY[part]` → 兼容解码 → 落盘，二次下载命中本地缓存。

- **【严重】IMAP 附件 part 编号错误**
  v1.0.0 用 `email.walk()` 的顺序序号当作 IMAP part 编号，两者规则完全不同
  （例如附件在 IMAP 中是 `2`，在 walk() 中可能是 `4`），会取到错误的部件内容。
  现按 RFC 3501 实现正确的 part 路径遍历，支持 `1.1`/`2.1` 等嵌套编号。

- **降级模式下 `rekey()` 静默改内存变量**
  未安装 SQLCipher 时 `rekey()` 只是改了个内存变量、磁盘毫无变化，行为与
  意图不符。现在会明确抛错，由调用方按 `rekey_supported` 判断并如实告知用户。

### ✨ 新增

- **正文按需拉取**：列表只同步邮件头（快速填充），点开邮件时后台自动补拉完整正文
- **数据库迁移机制**：支持 v1 → v2 自动升级表结构，幂等可重复执行
- **修改主密码结果如实反馈**：明确告知重新加密了几个凭据、数据库是否真的做了整库重加密

### 🧪 测试

- 测试套件从 11 项断言扩充到 **44 项**，新增：
  - 改主密码回归测试（含重启验证、失败回滚验证）
  - IMAP part 编号规则测试（嵌套 multipart）
  - 附件真实下载端到端测试（mock IMAP 服务器）
  - 数据库迁移测试（v1 → v2，含幂等性）

### 📄 其他

- 新增 `LICENSE`（MIT）
- 新增本 `CHANGELOG.md`

---

## [1.0.0] - 2026-10-15

首个正式版。

### 新增

- 多账号管理：QQ 邮箱、163、Gmail、Outlook、自定义 IMAP
- 统一收件箱：聚合全部账号，展示发件人 / 主题 / 时间 / 预览
- 多维筛选：平台、关键词、时间范围、仅未读
- 邮件详情：正文渲染（HTML 已清洗）+ 附件列表
- IMAP UID 增量同步 + 心跳调度器定时刷新
- 本地加密：PBKDF2 派生密钥、Fernet 凭据加密、可选 SQLCipher 整库加密
- PySide6 三栏深色主题界面
- PyInstaller 打包脚本与 Windows 单文件发行版

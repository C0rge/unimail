"""UniMail 回归测试套件。

覆盖：
    1. 安全层：密钥派生、加解密、错误密码拒绝
    2. 存储层：账号、邮件、附件、游标、级联删除
    3. 【回归】改主密码后凭据仍可解密（v1.0.0 严重 bug）
    4. 【回归】IMAP part 编号正确（v1.0.0 用 walk() 序号，取错附件）
    5. 【回归】附件下载返回真实字节流（v1.0.0 是占位文本）
    6. 数据库迁移：v1 → 当前版本自动补列 / 重建索引
    7. TLS 证书校验（v1.2.0：修复 IMAP 不校验证书）
    8. 【回归】同步游标语义与 UIDVALIDITY 清理（v1.2.0：修复静默丢邮件）
    9. 侧车原子写 / 备份回退 / 恢复包（v1.2.0）
   10. 数据清理路径（--reset 覆盖真正的侧车文件名）
   11. 数据库并发三件套 + 加密模式 fail-closed（v1.2.0）
   12. 批量写入 / 列投影 / LIKE 转义（v1.3.0）
   13. 列表索引与查询计划（v1.3.0）
   14. HTML 白名单清洗（v1.3.0：黑名单正则 → 白名单重建）
   15. BODYSTRUCTURE 附件元数据（v1.3.0）
   16. 【回归】同步回填附件信息（v1.3.0：修复附件永远进不了库）
   17. 附件落盘安全策略（v1.3.0）
   18. 孤儿附件清理（v1.3.0）
   19. KDF 算法与密码策略（v1.3.0）
   20. KDF 渐进升级（v1.3.0）
   21. 解锁退避持久化（v1.3.0）
   22. 恶意 MIME 语料：13 条畸形报文全部安全解析（v1.3.0）
   23. 关键路径中断注入：事务 / 附件落盘 / 侧车 / 加密迁移（v1.3.0）
   24. 全文检索：FTS5 + CJK 切分、触发器同步、LIKE 回退、注入安全（v1.4.0）
   25. 会话引用链：References / In-Reply-To 解析与归并键兜底（v1.4.0）
   26. 事件总线带负载：id 列表驱动增量插入（v1.4.0）
   27. 待回写标记队列：增删抵消 / 合并 / 开关生效（v1.5.0）
   28. 导出 eml / mbox / CSV：mboxo 转义、BOM、可被标准库解析（v1.5.0）
   29. 界面偏好持久化：白名单、越界回落、损坏文件容错（v1.4.0）
   30. 设备绑定免密解锁：DPAPI/Keychain 往返 + 密文损坏检测（v1.6.0）
   31. UI 层：设计令牌、图标、模型增量、多选 J/K、任务面板、锁屏遮罩（v1.4.0–v1.6.0）

运行：python tests/smoke.py
"""
from __future__ import annotations

import contextlib
import json
import os
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

TRUTH = []


def check(name: str, cond: bool, detail: str = "") -> None:
    mark = "ok" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail and not cond else ""))
    TRUTH.append((name, bool(cond)))
    if not cond:
        raise AssertionError(f"{name}: {detail}")


# ============================================================ 测试夹具
def setup_env(prefix: str):
    """创建隔离的临时数据目录，返回 (tmp, cfg, ctxmod, svcmod)。"""
    import unimail.config as cfg
    tmp = Path(tempfile.mkdtemp(prefix=prefix))
    cfg.DB_PATH = tmp / "t.db"
    cfg.ATTACHMENT_DIR = tmp / "attachments"
    cfg.ATTACHMENT_DIR.mkdir(parents=True, exist_ok=True)

    import unimail.core.services as svcmod
    import unimail.ui.context as ctxmod
    ctxmod.DB_PATH = cfg.DB_PATH
    svcmod.ATTACHMENT_DIR = cfg.ATTACHMENT_DIR
    return tmp, cfg, ctxmod, svcmod


@contextlib.contextmanager
def _fake_server(adapter, svcmod=None):
    """把服务层与会话池里的适配器**一起**替换为测试替身。

    v1.5.0 起附件下载 / 正文补拉走 `SessionPool` 的保活连接，而会话池在
    `unimail.sync.session` 里解析适配器（这是刻意的解耦：core 层不能
    反向依赖 sync 层）。因此只 patch 服务层已经不够——连接会照样真连出去。
    """
    from unittest.mock import patch as _patch

    import unimail.core.services as _svc
    import unimail.sync.session as sessmod
    import unimail.sync.worker as workermod
    with _patch.object(svcmod or _svc, "get_adapter", return_value=adapter), \
            _patch.object(sessmod, "get_adapter", return_value=adapter), \
            _patch.object(workermod, "get_adapter", return_value=adapter):
        yield adapter


# ============================================================ 1. 安全层
def test_security():
    from unimail.core.security import SecurityError, SecurityService

    sec = SecurityService()
    params = SecurityService.new_kdf_params()
    sec.setup("hunter2", params)
    verifier = SecurityService.make_verifier(sec._master_key)

    ct = sec.encrypt_secret("my-imap-password")
    check("凭据加解密", sec.decrypt_secret(ct) == "my-imap-password")

    sec.lock()
    check("锁定后状态清零", not sec.is_unlocked)

    sec2 = SecurityService()
    try:
        sec2.unlock("wrong-password", params, verifier)
        check("错误主密码被拒绝", False, "竟然通过了校验")
    except SecurityError:
        check("错误主密码被拒绝", True)

    sec2.unlock("hunter2", params, verifier)
    check("正确主密码解锁", sec2.is_unlocked)


# ============================================================ 2. 存储层
def test_storage():
    tmp, _cfg, _ctxmod, _svc = setup_env("store_")
    from unimail.core.models import AccountDraft, AttachmentMeta, MailFilter, NormalizedMail
    from unimail.core.security import SecurityService
    from unimail.storage import (
        AccountRepository,
        AttachmentRepository,
        CursorRepository,
        Database,
        MailRepository,
    )

    sec = SecurityService()
    params = SecurityService.new_kdf_params()
    db = Database(tmp / "test.db", sec.setup("pw123456", params))

    accounts = AccountRepository(db)
    mails = MailRepository(db)
    cursors = CursorRepository(db)
    attaches = AttachmentRepository(db)
    check("附件仓储可用", attaches is not None)

    acc = accounts.insert(AccountDraft(
        platform="qq", email="a@qq.com", password="x", display_name="测试"))
    accounts.put_credential(acc.id, sec.encrypt_secret("authorization-code-16"))
    stored = accounts.get_credential(acc.id)
    check("凭据密文存取", sec.decrypt_secret(stored) == "authorization-code-16")

    now = datetime.now(timezone.utc)
    for i in range(5):
        mails.insert_mail(acc.id, "qq", NormalizedMail(
            uid=str(100 + i), subject=f"测试邮件 {i}", from_name="发件人",
            from_addr=f"sender{i}@example.com", to_addrs=["a@qq.com"],
            date=now - timedelta(hours=i), body_text=f"这是第 {i} 封测试邮件的正文。",
            preview=f"第 {i} 封…",
            attachments=[AttachmentMeta("f.pdf", "application/pdf", 1024, part_index="2")]
            if i == 0 else [],
        ))
    dup = mails.insert_mail(acc.id, "qq", NormalizedMail(uid="100", subject="dup"))
    check("UID 去重", dup is None)

    found = mails.query(MailFilter(account_id=acc.id))
    check("查询邮件数", len(found) == 5, f"实际 {len(found)}")

    kw = mails.query(MailFilter(keyword="第 3 封"))
    check("关键词筛选", len(kw) == 1, f"实际 {len(kw)}")

    total, unread = mails.count_by_account()[acc.id]
    check("未读计数", total == 5 and unread == 5, f"total={total} unread={unread}")
    mails.set_read(found[0].id, True)
    check("标记已读", mails.count_by_account()[acc.id][1] == 4)

    with_att = next(m for m in found if m.has_attachments)
    atts = mails.attachments_of(with_att.id)
    check("附件关联", len(atts) == 1)
    check("附件 part_index 已持久化", atts[0].part_index == "2",
          f"实际 {atts[0].part_index!r}")

    cursors.upsert(acc.id, "INBOX", 104, 7)
    last_uid, validity = cursors.get(acc.id, "INBOX")
    check("同步游标", last_uid == 104 and validity == 7)

    ctx_row = mails.mail_context_of_attachment(atts[0].id)
    check("附件→邮件上下文查询", ctx_row is not None and ctx_row["uid"] == "100")

    accounts.delete(acc.id)
    check("级联删除", mails.query(MailFilter(account_id=acc.id)) == [])
    db.close()


# ============================================================ 3. 回归：改密码
def test_change_password_regression():
    """v1.0.0 的严重 bug：改主密码后凭据永久不可解。"""
    _tmp, _cfg, _ctxmod, _svc = setup_env("pwd_")
    from unimail.core.models import AccountDraft
    from unimail.core.security import SecurityError
    from unimail.ui.context import AppContext

    ctx = AppContext()
    ctx.bootstrap_new("old-password-123")
    a1 = ctx.accounts.add(AccountDraft(platform="qq", email="a@qq.com", password="SECRET-AAA"))
    a2 = ctx.accounts.add(AccountDraft(platform="163", email="b@163.com", password="SECRET-BBB"))

    res = ctx.change_password("old-password-123", "new-password-456")
    check("改密码后凭据重新加密计数", res.credentials_rotated == 2,
          f"实际 {res.credentials_rotated}")

    check("改密码后立即解密凭据1",
          ctx.accounts.reload_password(ctx.accounts.get(a1.id)) == "SECRET-AAA")
    check("改密码后立即解密凭据2",
          ctx.accounts.reload_password(ctx.accounts.get(a2.id)) == "SECRET-BBB")

    # 模拟重启
    ctx.db.close()
    ctx.security.lock()
    ctx2 = AppContext()
    ctx2.is_first_run = False
    ctx2.unlock("new-password-456")
    check("新密码可解锁", ctx2.security.is_unlocked)
    check("重启后凭据1仍可解",
          ctx2.accounts.reload_password(ctx2.accounts.get(a1.id)) == "SECRET-AAA")
    check("重启后凭据2仍可解",
          ctx2.accounts.reload_password(ctx2.accounts.get(a2.id)) == "SECRET-BBB")

    # 旧密码必须失效
    ctx3 = AppContext()
    try:
        ctx3.unlock("old-password-123")
        check("旧密码已失效", False, "旧密码仍能解锁")
    except SecurityError:
        check("旧密码已失效", True)

    # 错误旧密码不能改密码
    try:
        ctx2.change_password("wrong-old", "another-123456")
        check("错误旧密码被拒绝", False, "竟然改成功了")
    except SecurityError:
        check("错误旧密码被拒绝", True)

    # 新密码低于策略下限时必须在**动任何数据之前**被拒绝
    try:
        ctx2.change_password("new-password-456", "short")
        check("改密码时新密码受策略约束", False, "竟然改成功了")
    except SecurityError as exc:
        check("改密码时新密码受策略约束", "12" in str(exc), f"实际 {exc}")

    check("失败后凭据未损坏",
          ctx2.accounts.reload_password(ctx2.accounts.get(a1.id)) == "SECRET-AAA")
    check("改密码结果带回新的 KDF 描述", bool(res.kdf), f"实际 {res.kdf!r}")
    ctx2.db.close()


# ============================================================ 4. 回归：IMAP part 编号
def test_imap_part_numbering():
    """v1.0.0 用 msg.walk() 序号当 IMAP part 编号，会取错附件。"""
    from email import message_from_bytes

    from unimail.platforms.parser import _extract_attachments, iter_imap_parts, parse_message

    raw = b"""From: =?utf-8?B?5byg5LiJ?= <zs@example.com>
To: me@example.com
Subject: =?utf-8?B?5rWL6K+V6ZmE5Lu2?=
Date: Mon, 15 Oct 2026 10:00:00 +0800
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="OUTER"

--OUTER
Content-Type: multipart/alternative; boundary="INNER"

--INNER
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: base64

5L2g5aW977yM5q2j5paHCg==

--INNER
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: base64

PHA+5q2j5paHPC9wPgo=

--INNER--

--OUTER
Content-Type: application/pdf; name="report.pdf"
Content-Disposition: attachment; filename="report.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQgUkVBTCBQREY=

--OUTER
Content-Type: image/png; name="logo.png"
Content-Disposition: attachment; filename="logo.png"
Content-Transfer-Encoding: base64

iVBORw0KGgoAAAANSUhEUg==

--OUTER--
"""
    m = message_from_bytes(raw)
    parts = dict(iter_imap_parts(m))
    check("嵌套 multipart 生成 1.1/1.2 编号",
          "1.1" in parts and "1.2" in parts, f"实际 {sorted(parts)}")
    check("附件为顶层 2/3 编号", "2" in parts and "3" in parts)

    atts = _extract_attachments(m)
    check("识别 2 个附件", len(atts) == 2, f"实际 {len(atts)}")
    check("report.pdf 的 part_index=2", atts[0].part_index == "2",
          f"实际 {atts[0].part_index!r}")
    check("logo.png 的 part_index=3", atts[1].part_index == "3",
          f"实际 {atts[1].part_index!r}")

    nm = parse_message(raw, "101")
    check("中文主题解码", nm.subject == "测试附件", f"实际 {nm.subject!r}")
    check("中文发件人解码", nm.from_name == "张三", f"实际 {nm.from_name!r}")
    check("正文提取", "你好" in nm.body_text, f"实际 {nm.body_text!r}")
    check("HTML 正文提取", "<p>正文</p>" in nm.body_html)


# ============================================================ 5. 回归：真实附件下载
def test_attachment_download():
    """v1.0.0 下载的是占位文本，不是真实字节流。"""
    _tmp, _cfg, _ctxmod, svcmod = setup_env("dl_")
    from unimail.core.models import AccountDraft
    from unimail.platforms.parser import parse_message
    from unimail.ui.context import AppContext

    RAW = b"""From: a@b.com
To: me@x.com
Subject: with-attachment
Date: Mon, 15 Oct 2026 10:00:00 +0800
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="B"

--B
Content-Type: text/plain; charset="utf-8"

body
--B
Content-Type: application/pdf; name="doc.pdf"
Content-Disposition: attachment; filename="doc.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQgUkVBTCBQREYgQllURVM=
--B--
"""
    ctx = AppContext()
    ctx.bootstrap_new("pw1234567890")
    acc = ctx.accounts.add(AccountDraft(platform="qq", email="me@qq.com", password="code"))

    nm = parse_message(RAW, "200")
    mid = ctx.mails.mails.insert_mail(acc.id, "qq", nm)
    atts = ctx.mails.mails.attachments_of(mid)
    check("附件入库", len(atts) == 1)
    check("part_index 入库正确", atts[0].part_index == "2", f"实际 {atts[0].part_index!r}")

    FAKE_PDF = b"%PDF-1.4 REAL BYTES"

    class FakeImap:
        def select(self, *a, **k):
            return ("OK", [b""])
        def close(self):
            pass
        def logout(self):
            pass

    fake = MagicMock()
    fake.connect.return_value = FakeImap()
    fake.fetch_attachment.return_value = FAKE_PDF
    fake.disconnect = lambda x: None

    with _fake_server(fake, svcmod):
        result = ctx.mails.download_attachment(atts[0].id)

    path = result.path
    content = path.read_bytes()
    check("下载的是真实字节流", content == FAKE_PDF, f"实际 {content[:40]!r}")
    check("不再是占位内容", "占位".encode() not in content)
    check("普通附件不改名", not result.renamed and not result.danger)

    call = fake.fetch_attachment.call_args[0]
    check("FETCH 使用正确 part 编号", call[2] == "2", f"实际 {call[2]!r}")
    check("FETCH 使用正确 UID", str(call[1]) == "200", f"实际 {call[1]!r}")

    fake.fetch_attachment.reset_mock()
    with _fake_server(fake, svcmod):
        result2 = ctx.mails.download_attachment(atts[0].id)
    check("二次下载命中缓存", fake.fetch_attachment.call_count == 0)
    check("两次返回同一路径", result2.path == path)

    ctx.db.close()


# ============================================================ 6. 数据库迁移
def test_migration():
    """v1 库（无 part_index / uid_validity 列、旧索引定义）应能自动迁移到当前版本。"""
    import sqlite3
    _tmp, cfg, _ctxmod, _svc = setup_env("mig_")

    conn = sqlite3.connect(str(cfg.DB_PATH))
    conn.executescript("""
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE attachments (
            id TEXT PRIMARY KEY, mail_id TEXT NOT NULL, filename TEXT,
            content_type TEXT, size INTEGER, stored_path TEXT, content_id TEXT);
        CREATE TABLE accounts (id TEXT PRIMARY KEY, platform TEXT, email TEXT,
            display_name TEXT, imap_host TEXT, imap_port INTEGER, use_ssl INTEGER,
            username TEXT, sync_interval INTEGER, last_synced_at TEXT, status TEXT,
            created_at TEXT);
        CREATE TABLE credentials (id TEXT PRIMARY KEY, ciphertext BLOB,
            created_at TEXT, updated_at TEXT);
        CREATE TABLE sync_cursors (account_id TEXT, folder TEXT, last_uid INTEGER,
            uid_validity INTEGER, updated_at TEXT, PRIMARY KEY(account_id, folder));
        CREATE TABLE mails (id TEXT PRIMARY KEY, account_id TEXT, platform TEXT,
            folder TEXT, uid TEXT, message_id TEXT, subject TEXT, from_name TEXT,
            from_addr TEXT, to_addrs TEXT, date TEXT, preview TEXT, body_text TEXT,
            body_html TEXT, has_attachments INTEGER, is_read INTEGER,
            is_starred INTEGER, raw_size INTEGER, created_at TEXT);
    """)
    conn.execute("INSERT INTO sync_cursors(account_id, folder, last_uid, uid_validity) "
                 "VALUES('acc1','INBOX',104,77)")
    conn.execute("INSERT INTO mails(id, account_id, platform, folder, uid, subject, "
                 "date, created_at) VALUES('m1','acc1','qq','INBOX','100','hi',"
                 "'2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00')")
    conn.execute("INSERT INTO meta(key, value) VALUES('db_version', '1')")
    conn.commit()
    conn.close()

    from unimail.core.security import SecurityService
    from unimail.storage import Database

    sec = SecurityService()
    params = SecurityService.new_kdf_params()
    # 显式声明明文：本用例用裸 sqlite3 造的是 v1 时代的明文库。不显式指定时，
    # 装有 SQLCipher 的环境会把它推断为加密库 → `PRAGMA key` 打在明文库上 →
    # `file is not a database`。这是「驱动必须显式」的正面验证，不能靠环境推断。
    db = Database(cfg.DB_PATH, sec.setup("pw123456", params), encrypted=False)

    cols = {r["name"] for r in db.query_all("PRAGMA table_info(attachments)")}
    check("迁移后新增 part_index 列", "part_index" in cols, f"实际列: {sorted(cols)}")
    mail_cols = {r["name"] for r in db.query_all("PRAGMA table_info(mails)")}
    check("迁移后新增 uid_validity 列", "uid_validity" in mail_cols,
          f"实际列: {sorted(mail_cols)}")
    check("历史行按游标回填 uid_validity",
          int(db.query_one("SELECT uid_validity FROM mails WHERE id = 'm1'")["uid_validity"]) == 77)
    from unimail.config import DB_VERSION
    check(f"db_version 升到 {DB_VERSION}", db.get_meta("db_version") == str(DB_VERSION),
          f"实际 {db.get_meta('db_version')}")

    # ---- v5：会话引用链字段 + 全文索引
    for col in ("ref_ids", "in_reply_to", "thread_key"):
        check(f"迁移后新增 mails.{col} 列", col in mail_cols, f"实际列: {sorted(mail_cols)}")
    check("历史行的 thread_key 回填为自身 id（避免并成一个巨大会话）",
          db.query_one("SELECT thread_key FROM mails WHERE id = 'm1'")["thread_key"] == "m1")
    check("迁移后全文索引可用", db.fts_available)
    # 用占位符传参而不是把引号塞进 SQL 字符串里：f-string 里带反斜杠转义在
    # Python 3.10 上是语法错误（3.12 才放开），CI 的 py3.10 会直接编译失败。
    fts_hits = int(db.scalar(
        "SELECT COUNT(*) FROM mails_fts WHERE mails_fts MATCH ?", ('"hi"',)) or 0)
    check("迁移时已为历史邮件建好索引（能检索到迁移前的邮件）", fts_hits == 1,
          f"命中 {fts_hits}")
    check("索引行数与邮件行数一致", db.fts_stats() == (1, 1), f"实际 {db.fts_stats()}")

    # v4 重建了 idx_mails_read（单列 → (is_read, date DESC)）。`CREATE INDEX
    # IF NOT EXISTS` 对同名旧索引无效，必须 DROP 后再建，否则老库永远沿用旧定义。
    read_idx = db.query_one(
        "SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_mails_read'")
    check("v4 迁移重建了 idx_mails_read", read_idx is not None, "索引缺失")
    check("重建后的索引带 date DESC 排序",
          "date" in (read_idx or {}).get("sql", "").lower(),
          f"实际 {(read_idx or {}).get('sql')!r}")

    db.close()
    db2 = Database(cfg.DB_PATH, None)
    check("重复迁移幂等", "uid_validity" in
          {r["name"] for r in db2.query_all("PRAGMA table_info(mails)")})
    # 重复打开不应重复迁移，也不应破坏全文索引
    check("重复打开后版本不变且索引仍可用",
          db2.get_meta("db_version") == str(DB_VERSION) and db2.fts_available
          and db2.fts_stats() == (1, 1),
          f"实际 {db2.get_meta('db_version')} / {db2.fts_stats()}")
    db2.close()


# ============================================================ 7. TLS 证书校验
def test_tls_certificate_verification():
    """【回归】v1.1.0 的 IMAP4_SSL 未传 ssl_context → verify_mode=CERT_NONE。"""
    import imaplib
    import ssl

    from unimail.core.models import Account
    from unimail.platforms import get_adapter
    from unimail.platforms.base import tls_context

    ctx = tls_context()
    check("默认强制校验证书", ctx.verify_mode == ssl.CERT_REQUIRED, f"实际 {ctx.verify_mode}")
    check("默认校验主机名", ctx.check_hostname is True)
    check("最低 TLS 版本不低于 1.2",
          ctx.minimum_version >= ssl.TLSVersion.TLSv1_2)

    lax = tls_context(True)
    check("仅显式放行时才关闭校验",
          lax.verify_mode == ssl.CERT_NONE and not lax.check_hostname)

    captured: dict = {}

    class FakeSSL:
        def __init__(self, host, port, timeout=None, ssl_context=None):
            captured["ssl_context"] = ssl_context
            captured["host"] = host
            raise OSError("stop-here")

    acct = Account(id="x", platform="custom", email="a@b.c",
                   imap_host="imap.example.com", imap_port=993, username="a@b.c")
    original = imaplib.IMAP4_SSL
    imaplib.IMAP4_SSL = FakeSSL  # type: ignore[assignment]
    try:
        with contextlib.suppress(Exception):     # 只关心传参，连接必然失败
            get_adapter("custom").connect(acct, "pw")
    finally:
        imaplib.IMAP4_SSL = original  # type: ignore[assignment]

    got = captured.get("ssl_context")
    check("connect() 传入加固的 TLS 上下文", got is not None)
    check("connect() 的上下文强制校验证书",
          got is not None and got.verify_mode == ssl.CERT_REQUIRED)

    # 证书校验失败必须映射为可读的 ImapError，而不是裸 ssl 异常
    from unimail.platforms.base import ImapError

    class CertFailingSSL:
        def __init__(self, *a, **k):
            raise ssl.SSLCertVerificationError(1, "self-signed certificate")

    imaplib.IMAP4_SSL = CertFailingSSL  # type: ignore[assignment]
    try:
        try:
            get_adapter("custom").connect(acct, "pw")
            check("证书校验失败被拦截", False, "竟然没有抛错")
        except ImapError as exc:
            check("证书校验失败给出可读提示", "证书" in str(exc), f"实际 {exc}")
        except Exception as exc:  # noqa: BLE001
            check("证书校验失败给出可读提示", False, f"抛出了 {type(exc).__name__}")
    finally:
        imaplib.IMAP4_SSL = original  # type: ignore[assignment]


# ============================================================ 8. 同步语义
class _FakeImap:
    def select(self, *a, **k):
        return ("OK", [b""])

    def close(self):
        pass

    def logout(self):
        pass


class _FakeAdapter:
    """可编排的 IMAP 适配器：模拟分页、UIDVALIDITY 变化与单封失败。"""

    def __init__(self, uids, validity: int = 100):
        self.uids = sorted(int(u) for u in uids)
        self.validity = validity
        self.fail_uids: set[int] = set()
        self.searches: list[tuple[int, int]] = []
        self.body_fetches: list[int] = []
        self.meta_fetches: list[list[str]] = []

    def connect(self, account, password):
        return _FakeImap()

    def disconnect(self, imap):
        pass

    def uid_validity(self, imap):
        return self.validity

    def search_new_uids(self, imap, since_uid, limit=200):
        self.searches.append((int(since_uid), int(limit)))
        avail = [u for u in self.uids if u > since_uid]
        return [str(u) for u in avail[:limit]]

    def fetch_headers(self, imap, uid, folder="INBOX"):
        from unimail.core.models import NormalizedMail
        from unimail.platforms.base import ImapError
        if int(uid) in self.fail_uids:
            raise ImapError(f"模拟拉取失败 {uid}")
        return NormalizedMail(uid=str(uid), subject=f"mail {uid}",
                              from_addr="sender@example.com",
                              date=datetime.now(timezone.utc))

    def fetch_message(self, imap, uid, folder="INBOX"):
        from unimail.core.models import AttachmentMeta, NormalizedMail
        self.body_fetches.append(int(uid))
        # 完整解析比 BODYSTRUCTURE 多出 content_id：用于验证「按 part 对齐替换」
        # 而不是「再插一行」。
        atts = ([AttachmentMeta("page.pdf", "application/pdf", 128,
                               content_id="cid-page", part_index="2")]
                if int(uid) % 5 == 0 else [])
        return NormalizedMail(uid=str(uid), body_text=f"body {uid}",
                              body_html=f"<p>body {uid}</p>", attachments=atts)

    def fetch_attachment_meta(self, imap, uids, folder="INBOX"):
        """模拟 BODYSTRUCTURE：每 5 封里有一封带附件。"""
        from unimail.core.models import AttachmentMeta
        self.meta_fetches.append([str(u) for u in uids])
        return {
            str(u): [AttachmentMeta("page.pdf", "application/pdf", 128, part_index="2")]
            for u in uids if int(u) % 5 == 0
        }


def _make_sync_ctx(prefix):
    _tmp, cfg, _ctxmod, _svc = setup_env(prefix)
    from unimail.core.models import AccountDraft
    from unimail.ui.context import AppContext

    ctx = AppContext()
    ctx.bootstrap_new("pw-1234567890")
    account = ctx.accounts.add(AccountDraft(platform="qq", email="sync@qq.com",
                                            password="code"))
    return cfg, ctx, account


def _run_sync(ctx, account, adapter):
    from unimail.sync.worker import SyncWorker
    worker = SyncWorker(account, ctx.accounts, ctx.mails.mails,
                        ctx.accounts.cursors, ctx.security, ctx.bus)
    with patch("unimail.sync.worker.get_adapter", return_value=adapter):
        worker.run()
    return worker


def test_search_new_uids_order():
    """【回归】旧实现返回 uids[-limit:]，即「最新」一批 → 游标跳到末尾丢邮件。"""
    from unimail.platforms.base import ImapAdapter

    class _Imap:
        def select(self, *a, **k):
            return ("OK", [b""])

        def uid(self, command, *args):
            return ("OK", [b" ".join(str(u).encode() for u in range(1, 1001))])

    class _Adapter(ImapAdapter):
        platform = "custom"

    uids = _Adapter().search_new_uids(_Imap(), 0, limit=200)
    check("返回最旧的一批（UID 最小者优先）",
          len(uids) == 200 and uids[0] == "1" and uids[-1] == "200",
          f"len={len(uids)} first={uids[0] if uids else None} last={uids[-1] if uids else None}")


def test_sync_pagination_and_uidvalidity():
    """【回归】首同步必须分页追平（不再只入库最新 200 封），UIDVALIDITY 变化时清理旧副本。"""
    from unimail.core.models import MailFilter

    _cfg, ctx, account = _make_sync_ctx("sync_")
    mails = ctx.mails.mails

    # ---- 场景 A：450 封邮件，页大小 100 → 必须全部入库且游标推进到 450
    adapter = _FakeAdapter(range(1, 451), validity=100)
    _run_sync(ctx, account, adapter)

    count = len(mails.query(MailFilter(account_id=account.id, limit=10000)))
    check("首同步全量入库（不再只取最新一批）", count == 450, f"实际 {count}")
    last_uid, validity = ctx.accounts.cursors.get(account.id, "INBOX")
    check("游标推进到连续已抓取区间的最大 UID", last_uid == 450, f"实际 {last_uid}")
    check("游标记录 UIDVALIDITY", validity == 100, f"实际 {validity}")
    check("确实发生了分页", len(adapter.searches) >= 4, f"实际 {len(adapter.searches)} 页")

    # ---- 场景 B：UIDVALIDITY 变化 + UID 复用 → 旧副本必须被清理，新邮件不得被静默丢弃
    adapter.uids = [1, 2, 3, 4, 5]
    adapter.validity = 999
    _run_sync(ctx, account, adapter)

    rows = mails.query(MailFilter(account_id=account.id, limit=10000))
    check("UIDVALIDITY 变化后旧副本被清理", len(rows) == 5, f"实际 {len(rows)}")
    stored = {int(r["uid_validity"]) for r in
              ctx.db.query_all("SELECT uid_validity FROM mails WHERE account_id = ?",
                               (account.id,))}
    check("清理后仅保留新 UIDVALIDITY 的记录", stored == {999}, f"实际 {stored}")
    last_uid, validity = ctx.accounts.cursors.get(account.id, "INBOX")
    check("UIDVALIDITY 变化后游标重置并重新推进",
          last_uid == 5 and validity == 999, f"实际 {last_uid}/{validity}")

    # ---- 场景 C：中途单封失败 → 游标停在该封之前，下次同步能续上
    _cfg2, ctx2, account2 = _make_sync_ctx("sync2_")
    mails2 = ctx2.mails.mails
    adapter2 = _FakeAdapter(range(1, 11), validity=100)
    adapter2.fail_uids = {4}
    _run_sync(ctx2, account2, adapter2)
    last_uid, _ = ctx2.accounts.cursors.get(account2.id, "INBOX")
    check("单封失败时游标不越过该封", last_uid == 3, f"实际 {last_uid}")

    adapter2.fail_uids = set()
    _run_sync(ctx2, account2, adapter2)
    count2 = len(mails2.query(MailFilter(account_id=account2.id, limit=10000)))
    check("恢复后补齐剩余邮件", count2 == 10, f"实际 {count2}")
    last_uid, _ = ctx2.accounts.cursors.get(account2.id, "INBOX")
    check("恢复后游标追平", last_uid == 10, f"实际 {last_uid}")

    ctx.db.close()
    ctx2.db.close()


# ============================================================ 9. 侧车原子性
def test_sidecar_atomicity_and_recovery():
    tmp, cfg, _ctxmod, _svc = setup_env("side_")
    from unimail.core.security import SecurityError
    from unimail.ui.context import AppContext

    meta = cfg.DB_PATH.with_suffix(".meta.json")
    bak = meta.with_name(meta.name + ".bak")
    tmpfile = meta.with_name(meta.name + ".tmp")

    ctx = AppContext()
    ctx.bootstrap_new("pw-1234567890")
    check("首次建库后写入侧车", meta.exists())
    check("侧车记录数据库驱动",
          json.loads(meta.read_text("utf-8")).get("driver") == ctx.db.driver_name)
    check("侧车不含明文密码", "pw-1234567890" not in meta.read_text("utf-8"))
    ctx.db.close()

    ctx = AppContext()
    ctx.unlock("pw-1234567890")            # 第二次写入 → 产生 .bak
    check("旧侧车已备份为 .bak", bak.exists())
    check("写入后无 .tmp 残留", not tmpfile.exists())

    # 模拟写入过程中崩溃：主侧车半截 JSON
    meta.write_text('{"salt": "AA', "utf-8")
    ctx.db.close()
    ctx2 = AppContext()
    ctx2.is_first_run = False
    ctx2.unlock("pw-1234567890")
    check("主侧车损坏时自动回退备份", ctx2.security.is_unlocked)
    healed = json.loads(meta.read_text("utf-8"))
    check("回退后主侧车已自愈", bool(healed.get("verifier")))

    # 恢复包
    dest = tmp / "recovery.json"
    ctx2.export_recovery_bundle(dest)
    bundle = json.loads(dest.read_text("utf-8"))
    check("恢复包含 salt 与迭代次数",
          bool(bundle["kdf"]["salt"]) and int(bundle["kdf"]["iterations"]) > 0)
    blob = json.dumps(bundle)
    check("恢复包不含任何密文", "verifier" not in blob and "ciphertext" not in blob)
    ctx2.db.close()

    # 主备全坏 → 必须是可操作的错误，而不是"格式错误"
    meta.write_text("{broken", "utf-8")
    bak.write_text("{broken", "utf-8")
    ctx3 = AppContext()
    ctx3.is_first_run = False
    try:
        ctx3.unlock("pw-1234567890")
        check("主备均损坏时拒绝解锁", False, "竟然解锁成功")
    except SecurityError as exc:
        check("主备均损坏时给出可操作提示",
              "恢复包" in str(exc) and str(meta.name) in str(exc), f"实际 {exc}")


# ============================================================ 10. 数据清理路径
def test_reset_data_paths():
    """【回归】旧 reset_data 删的是 unimail.db.meta.json，真正的侧车从未被清理。"""
    tmp, cfg, _ctxmod, _svc = setup_env("reset_")
    import main as mainmod

    db = cfg.DB_PATH
    meta = db.with_suffix(".meta.json")
    att = tmp / "attachments"
    att.mkdir(parents=True, exist_ok=True)
    (att / "a.bin").write_bytes(b"x")

    db.write_bytes(b"db")
    Path(str(db) + "-wal").write_bytes(b"wal")
    meta.write_text("{}", "utf-8")
    meta.with_name(meta.name + ".bak").write_text("{}", "utf-8")
    meta.with_name(meta.name + ".tmp").write_text("{}", "utf-8")

    with patch.object(mainmod, "DB_PATH", db), \
            patch.object(mainmod, "ATTACHMENT_DIR", att):
        mainmod.reset_data()

    check("清掉真正的侧车文件", not meta.exists())
    check("清掉侧车备份", not meta.with_name(meta.name + ".bak").exists())
    check("清掉侧车临时文件", not meta.with_name(meta.name + ".tmp").exists())
    check("清掉 WAL", not Path(str(db) + "-wal").exists())
    check("清掉主库文件", not db.exists())
    check("清空附件目录", not any(att.iterdir()))


# ============================================================ 11. 数据库并发与加密模式
def test_database_concurrency_and_mode():
    from unimail.core.security import SecurityService
    from unimail.storage import SQLCIPHER_AVAILABLE, Database, DatabaseError

    tmp, _cfg, _ctxmod, _svc = setup_env("conc_")
    sec = SecurityService()
    params = SecurityService.new_kdf_params()

    db = Database(tmp / "c.db", sec.setup("pw123456", params), encrypted=False)

    check("busy_timeout 已设置", int(db.scalar("PRAGMA busy_timeout")) == 5000,
          f"实际 {db.scalar('PRAGMA busy_timeout')}")
    check("journal_mode = wal",
          str(db.scalar("PRAGMA journal_mode")).lower() == "wal")
    check("synchronous = NORMAL", int(db.scalar("PRAGMA synchronous")) == 1)
    check("外键约束开启", int(db.scalar("PRAGMA foreign_keys")) == 1)
    check("temp_store = MEMORY", int(db.scalar("PRAGMA temp_store")) == 2)

    # 线程本地连接会被登记，close() 必须回收全部
    def _touch():
        db.query_one("SELECT 1")

    t = threading.Thread(target=_touch)
    t.start()
    t.join()
    check("后台线程连接已登记", db.open_count() >= 2, f"实际 {db.open_count()}")
    db.close()
    check("close() 回收所有线程连接", db.open_count() == 0)
    try:
        db.query_one("SELECT 1")
        check("关闭后拒绝继续使用", False, "竟然还能查询")
    except DatabaseError:
        check("关闭后拒绝继续使用", True)

    # 事务持锁 + 事务内 execute 不提前提交
    db2 = Database(tmp / "c2.db", sec.setup("pw123456", params), encrypted=False)
    marks: dict[str, float] = {}

    def _holder():
        with db2.transaction() as conn:
            time.sleep(0.3)
            conn.execute("INSERT INTO meta(key, value) VALUES('a', '1')")
            marks["a_commit"] = time.monotonic()

    def _waiter():
        db2.execute("INSERT INTO meta(key, value) VALUES('b', '1')")
        marks["b_done"] = time.monotonic()

    t1 = threading.Thread(target=_holder)
    t1.start()
    time.sleep(0.05)
    t2 = threading.Thread(target=_waiter)
    t2.start()
    t1.join()
    t2.join()
    check("事务期间其它线程的写入被串行化",
          marks.get("b_done", 0) >= marks.get("a_commit", 0),
          f"{marks}")

    try:
        with db2.transaction() as conn:
            db2.execute("INSERT INTO meta(key, value) VALUES('nested', '1')")
            conn.execute("INSERT INTO meta(key, value) VALUES('plain', '1')")
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    check("事务内 execute 不提前提交（回滚后无残留）",
          db2.get_meta("nested") is None and db2.get_meta("plain") is None)
    db2.close()

    # 加密模式 fail-closed
    if not SQLCIPHER_AVAILABLE:
        try:
            Database(tmp / "x.db", b"0" * 32, encrypted=True)
            check("缺少 SQLCipher 时拒绝打开加密库", False, "竟然打开了")
        except DatabaseError as exc:
            check("缺少 SQLCipher 时给出安装提示", "sqlcipher3" in str(exc))
    else:  # pragma: no cover - 本机未安装
        enc = Database(tmp / "x.db", sec.setup("pw123456", params), encrypted=True)
        check("加密库以加密方式打开", enc.encrypted and enc.driver_name == "sqlcipher")
        enc.close()

    # 可用性开关必须是「实时读取」的单一事实源：历史上它同时以模块常量与内部变量
    # 两份形式存在，前者在导入期被各模块按值绑定，会造成判断分裂。
    import unimail.storage.database as dbmod
    from unimail.storage import sqlcipher_available

    real = dbmod._SQLCIPHER_AVAILABLE
    with patch.object(dbmod, "_SQLCIPHER_AVAILABLE", not real):
        check("SQLCipher 可用性是实时读取的单一事实源",
              sqlcipher_available() is (not real),
              f"实际 {sqlcipher_available()}")
    check("退出补丁后恢复真实值", sqlcipher_available() is real)


def test_legacy_sidecar_and_driver_mismatch():
    """旧版侧车没有 driver 字段；记录与实际不符时也必须给出可读结论。"""
    _tmp, cfg, _ctxmod, _svc = setup_env("legacy_")
    from unimail.core.security import SecurityError
    from unimail.storage import SQLCIPHER_AVAILABLE, DatabaseError
    from unimail.ui.context import AppContext

    ctx = AppContext()
    ctx.bootstrap_new("pw-1234567890")
    ctx.db.close()
    meta = cfg.DB_PATH.with_suffix(".meta.json")

    # 模拟 v1.1.0 的侧车：没有 driver 字段
    data = json.loads(meta.read_text("utf-8"))
    data.pop("driver", None)
    meta.write_text(json.dumps(data), "utf-8")

    ctx2 = AppContext()
    ctx2.is_first_run = False
    ctx2.unlock("pw-1234567890")
    expected = "sqlcipher" if SQLCIPHER_AVAILABLE else "sqlite3"
    check("旧侧车可自动探测出实际加密模式",
          ctx2.db.driver_name == expected, f"实际 {ctx2.db.driver_name}")
    check("探测结论已回写 sidecar（下次启动不再探测）",
          json.loads(meta.read_text("utf-8")).get("driver") == expected)
    check("解锁后库内 meta.driver 与 sidecar 一致",
          ctx2.db.registered_driver() == expected)
    ctx2.db.close()

    # sidecar 声称是加密库，但本机没有 SQLCipher → 必须是可读错误，而不是打不开。
    # 这里显式把可用性开关置为 False，否则在已装 SQLCipher 的环境里「声称加密」恰好
    # 与事实相符，用例前提不成立（本用例验证的是**记录与实际不符**时的行为）。
    data = json.loads(meta.read_text("utf-8"))
    data["driver"] = "sqlcipher"
    meta.write_text(json.dumps(data), "utf-8")
    ctx3 = AppContext()
    ctx3.is_first_run = False
    with patch("unimail.storage.database._SQLCIPHER_AVAILABLE", False):
        try:
            ctx3.unlock("pw-1234567890")
            check("驱动记录与库不符时不静默失败", False, "竟然解锁成功")
        except (DatabaseError, SecurityError) as exc:
            text = str(exc)
            check("驱动记录与库不符时给出可操作提示",
                  "sqlcipher3" in text or "加密" in text, f"实际 {text[:120]}")


# ============================================================ 12. 批量写入与列表投影
def test_batch_write_and_projection():
    """G1：批量写入、冲突精确记账、列表列投影、LIKE 通配符转义。"""
    from unimail.core.models import (
        MAIL_SUMMARY_COLUMNS,
        AccountDraft,
        AttachmentMeta,
        MailFilter,
        MailSummary,
        NormalizedMail,
    )
    from unimail.core.security import SecurityService
    from unimail.storage import AccountRepository, Database, MailRepository

    tmp, _cfg, _ctxmod, _svc = setup_env("batch_")
    sec = SecurityService()
    sec.setup("pw-1234567890", SecurityService.new_kdf_params())
    db = Database(tmp / "b.db", sec.db_key(), encrypted=False)
    accounts, mails = AccountRepository(db), MailRepository(db)
    acc = accounts.insert(AccountDraft(platform="qq", email="b@qq.com", password="x"))

    now = datetime.now(timezone.utc)
    body = "正文" * 600
    batch = [
        NormalizedMail(
            uid=str(i), subject=f"批量 {i}", from_addr=f"s{i}@example.com",
            date=now - timedelta(minutes=i), body_text=body, body_html=f"<p>{body}</p>",
            preview="预览",
            attachments=[AttachmentMeta("a.pdf", "application/pdf", 10, part_index="2")]
            if i == 1 else [],
        )
        for i in range(1, 201)
    ]
    res = mails.insert_mails_batch(acc.id, "qq", batch, uid_validity=5)
    check("批量写入全部落库", res.new_count == 200, f"实际 {res.new_count}")
    check("批量写入不误判冲突/重复", res.conflicts == 0 and res.existing == 0,
          f"conflicts={res.conflicts} existing={res.existing}")
    check("批量写入的附件行随邮件事务一起写入",
          int(db.scalar("SELECT COUNT(*) FROM attachments")) == 1)

    again = mails.insert_mails_batch(acc.id, "qq", batch, uid_validity=5)
    check("重复同步计入 existing 而非 inserted",
          again.new_count == 0 and again.existing == 200,
          f"{again.new_count}/{again.existing}")

    dup = mails.insert_mails_batch(
        acc.id, "qq",
        [NormalizedMail(uid="999", subject="d"), NormalizedMail(uid="999", subject="d")],
        uid_validity=5)
    check("同批内 UID 自去重", dup.new_count == 1 and dup.existing == 1,
          f"{dup.new_count}/{dup.existing}")

    # 唯一键是 (account_id, folder, uid)：同 UID 换一个 UIDVALIDITY 必然冲突。
    # 这类行被 INSERT OR IGNORE 跳过，其附件行必须一起剔除——否则会写入指向
    # 不存在邮件的附件行（外键开启时甚至直接抛 IntegrityError 让整页同步失败）。
    #
    # 必须显式传 known_uids（同步线程传的是「按 UIDVALIDITY 过滤后的集合」）：
    # 只传 None 时方法会取回该文件夹的**全部** UID，冲突会在内存去重阶段
    # 就被消化掉，根本走不到数据库的唯一键。
    conflict = mails.insert_mails_batch(
        acc.id, "qq",
        [NormalizedMail(uid="1", subject="撞号",
                        attachments=[AttachmentMeta("c.pdf", "application/pdf", 1,
                                                    part_index="2")])],
        uid_validity=6, known_uids=set())
    check("唯一键冲突被精确记账",
          conflict.conflicts == 1 and conflict.new_count == 0,
          f"conflicts={conflict.conflicts} inserted={conflict.new_count}")
    orphans = db.scalar(
        "SELECT COUNT(*) FROM attachments a WHERE NOT EXISTS "
        "(SELECT 1 FROM mails m WHERE m.id = a.mail_id)")
    check("冲突邮件不留下孤儿附件行", int(orphans) == 0, f"实际 {orphans}")
    check("冲突邮件自身未入库",
          int(db.scalar("SELECT COUNT(*) FROM mails WHERE uid = '1' AND uid_validity = 6")) == 0)

    # ---- 列投影：列表不再把正文搬进内存
    check("列表查询返回 MailSummary 投影",
          all(isinstance(r, MailSummary)
              for r in mails.query_summaries(MailFilter(limit=5))))
    row = mails.query_summaries(MailFilter(limit=1))[0]
    check("列表投影不含正文字段",
          not hasattr(row, "body_text") and not hasattr(row, "body_html"))
    sql, _params = mails._select_sql(MailFilter(), ", ".join(MAIL_SUMMARY_COLUMNS))
    check("投影 SQL 未选取正文列",
          "body_text" not in sql and "body_html" not in sql, sql)
    full = mails.get(res.inserted[0][1])
    check("按 id 取详情仍带正文", bool(full and full.body_text),
          f"实际 {len(full.body_text) if full else 'None'} 字")
    check("按 id 取详情会带上附件明细", bool(full) and len(full.attachments) == 1,
          f"实际 {len(full.attachments) if full else 'None'}")
    check("to_summary() 丢弃正文", not hasattr(full.to_summary(), "body_html"))

    # ---- LIKE 转义：用户输入的 % / _ 不能变成通配符
    mails.insert_mails_batch(acc.id, "qq", [
        NormalizedMail(uid="1001", subject="100%纯棉", date=now),
        NormalizedMail(uid="1002", subject="axb", date=now),
        NormalizedMail(uid="1003", subject="a_b", date=now),
    ], uid_validity=5)
    width = mails.query_summaries(MailFilter(keyword="%", limit=5000))
    check("关键词 % 被转义（不再匹配全库）", len(width) == 1, f"实际 {len(width)}")
    exact = mails.query_summaries(MailFilter(keyword="a_b", limit=5000))
    check("关键词 _ 被转义（不再匹配任意字符）", len(exact) == 1, f"实际 {len(exact)}")
    check("命中的就是字面量那条", bool(exact) and exact[0].uid == "1003",
          f"实际 {[r.uid for r in exact]}")
    db.close()


# ============================================================ 13. 索引与查询计划
def test_indexes_and_query_plan():
    """G1：列表筛选的复合索引必须真被用上，否则排序要建临时 B 树。"""
    from unimail.core.models import AccountDraft, NormalizedMail
    from unimail.core.security import SecurityService
    from unimail.storage import AccountRepository, Database, MailRepository

    tmp, _cfg, _ctxmod, _svc = setup_env("idx_")
    sec = SecurityService()
    sec.setup("pw-1234567890", SecurityService.new_kdf_params())
    db = Database(tmp / "i.db", sec.db_key(), encrypted=False)
    accounts, mails = AccountRepository(db), MailRepository(db)
    acc = accounts.insert(AccountDraft(platform="qq", email="i@qq.com", password="x"))

    now = datetime.now(timezone.utc)
    mails.insert_mails_batch(acc.id, "qq", [
        NormalizedMail(uid=str(i), subject=f"m{i}", from_addr="s@e.com",
                       date=now - timedelta(minutes=i), body_text="x")
        for i in range(1, 601)
    ], uid_validity=1)

    names = {r["name"] for r in db.query_all(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='mails'")}
    for expected in ("idx_mails_read", "idx_mails_acc_read", "idx_mails_validity"):
        check(f"索引 {expected} 已建立", expected in names, f"实际 {sorted(names)}")

    def _plan(sql, params=()):
        return " | ".join(
            str(r.get("detail") or "") for r in db.query_all("EXPLAIN QUERY PLAN " + sql, params))

    detail = _plan("SELECT id, subject, date FROM mails WHERE is_read = 0 "
                   "ORDER BY date DESC LIMIT 50")
    check("仅未读列表走 (is_read, date DESC) 索引",
          "idx_mails_read" in detail, detail)
    check("仅未读列表不再为排序建临时 B 树",
          "TEMP B-TREE" not in detail.upper(), detail)

    detail2 = _plan("SELECT id FROM mails WHERE account_id = ? AND is_read = 0 "
                    "ORDER BY date DESC LIMIT 50", (acc.id,))
    check("按账号 + 未读走复合索引", "idx_mails_acc_read" in detail2, detail2)
    check("按账号 + 未读不需要临时 B 树",
          "TEMP B-TREE" not in detail2.upper(), detail2)
    db.close()


# ============================================================ 14. HTML 白名单清洗
def test_html_whitelist_sanitizer():
    """G3：白名单重建取代黑名单正则——未来出现新向量时默认是丢弃而不是放过。"""
    from unimail.platforms.parser import sanitize_html

    html = (
        '<div onclick="steal()">'
        '<script>alert(1)</script>'
        '<style>body{background:url(http://evil/t.png)}</style>'
        '<iframe src="http://evil/f"></iframe>'
        '<p>正文一</p>'
        '<a href="javascript:alert(1)">xss</a>'
        '<a href="http://example.com/ok">ok</a>'
        '<img src="http://tracker.example/p.gif" srcset="a 1x" '
        'style="background:url(http://t)">'
        '</div>'
    )
    clean = sanitize_html(html)
    low = clean.lower()
    check("script 子树被整棵丢弃", "alert(1)" not in clean and "script" not in low)
    check("style 子树被丢弃（远程背景图不落地）", "background" not in low)
    check("iframe 子树被丢弃", "iframe" not in low)
    check("正文完整保留", "正文一" in clean, clean)
    check("javascript: 链接被丢弃", "javascript" not in low)
    check("合法链接保留并补 rel",
          'href="http://example.com/ok"' in clean and 'rel="noopener noreferrer"' in clean,
          clean)
    check("远程图片连 DOM 都不留",
          "tracker.example" not in clean and "<img" not in clean, clean)
    check("未列入白名单的属性（srcset/style）一律丢弃",
          "srcset" not in low and "style=" not in low, clean)
    check("事件属性丢弃", "onclick" not in low)

    # 【回归】<meta>/<input> 这类无结束标签的元素不能压入「丢弃栈」，
    # 否则它们之后的整篇正文都会被吞掉。
    swallowed = sanitize_html(
        '<head><meta charset="utf-8"><title>t</title></head>'
        '<body><p>关键正文</p></body>')
    check("自闭合类标签不吞掉后续正文", "关键正文" in swallowed, repr(swallowed))
    check("title 文本不作为正文输出", "t" not in swallowed.replace("关键正文", ""),
          repr(swallowed))

    check("文本被转义为实体",
          "&lt;b&gt;" in sanitize_html("<p>&lt;b&gt;</p>"))
    check("空输入安全返回", sanitize_html("") == "")

    # 清洗必须与解析链路串起来：parse_message 的 body_html 已经是清洗后的结果
    from unimail.platforms.parser import parse_message
    raw = (b"From: a@b.com\nSubject: t\nMIME-Version: 1.0\n"
           b'Content-Type: text/html; charset="utf-8"\n\n'
           b'<p>hi</p><script>alert(1)</script>')
    nm = parse_message(raw, "1")
    check("解析链路中 HTML 已清洗", "script" not in nm.body_html.lower(), nm.body_html)
    check("清洗后仍保留纯文本摘要", "hi" in nm.body_text, repr(nm.body_text))


# ============================================================ 15. BODYSTRUCTURE
def test_bodystructure_attachment_meta():
    """G1：只取邮件头拿不到部件信息 → 用 BODYSTRUCTURE 补附件元数据（不下正文）。"""
    from unimail.platforms.base import ImapAdapter
    from unimail.platforms.parser import (
        extract_bodystructure_from_fetch,
        parse_bodystructure,
    )

    struct = (
        '(("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 12 1)'
        ' ("APPLICATION" "PDF" ("NAME" "=?utf-8?B?5oql5ZGK?=.pdf") NIL NIL "BASE64" 2048'
        '  ("ATTACHMENT" ("FILENAME" "=?utf-8?B?5oql5ZGK?=.pdf")))'
        ' "MIXED")'
    )
    metas = parse_bodystructure(struct)
    check("从 BODYSTRUCTURE 识出 1 个附件", len(metas) == 1, f"实际 {len(metas)}")
    check("part 编号来自结构位置而非遍历序号",
          metas and metas[0].part_index == "2", f"实际 {metas and metas[0].part_index!r}")
    check("编码文件名被解码", metas and metas[0].filename == "报告.pdf",
          f"实际 {metas and metas[0].filename!r}")
    check("附件字节数取自服务器（无需下载）", metas and metas[0].size == 2048,
          f"实际 {metas and metas[0].size}")
    check("content-type 归一化", metas and metas[0].content_type == "application/pdf")

    nested = (
        '(("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 5 1)'
        ' (("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 5 1)'
        '  ("APPLICATION" "ZIP" ("NAME" "pkg.zip") NIL NIL "BASE64" 77'
        '   ("ATTACHMENT" ("FILENAME" "pkg.zip")))'
        '  "ALTERNATIVE")'
        ' "MIXED")'
    )
    deep = parse_bodystructure(nested)
    check("嵌套 multipart 的 part 编号逐层拼接",
          len(deep) == 1 and deep[0].part_index == "2.2",
          f"实际 {[(m.filename, m.part_index) for m in deep]}")

    rfc = ('("MESSAGE" "RFC822" ("NAME" "fwd.eml") NIL NIL "7BIT" 4096'
           ' NIL ("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 5 1) 7)')
    fwd = parse_bodystructure(rfc)
    check("内嵌邮件本身作为可下载附件",
          len(fwd) == 1 and fwd[0].part_index == "1" and fwd[0].filename == "fwd.eml",
          f"实际 {[(m.filename, m.part_index) for m in fwd]}")

    plain = parse_bodystructure('("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 5 1)')
    check("无附件的单部分邮件返回空列表", plain == [], f"实际 {plain}")
    check("空输入安全返回空列表", parse_bodystructure("") == [])
    check("畸形括号安全返回空列表", parse_bodystructure("((((( ") == [])
    check("非结构文本安全返回空列表", parse_bodystructure("NO [SERVERBUG] error") == [])

    full = b'12 (UID 345 BODYSTRUCTURE ' + struct.encode() + b')'
    uid, structure = extract_bodystructure_from_fetch(full)
    check("从 FETCH 响应取出 UID", uid == "345", f"实际 {uid!r}")
    check("按括号配平取出完整结构",
          bool(structure) and structure.startswith("(") and structure.endswith(")"),
          f"实际 {structure!r}")
    check("取出的结构可再次解析出附件", len(parse_bodystructure(structure)) == 1)

    # 字面量形式的 FETCH 响应：前缀/字面量被拆成两项，必须拼回去才能配平括号
    cut = full.index(b"BODYSTRUCTURE") + len(b"BODYSTRUCTURE")

    class _BsImap:
        def __init__(self, payload):
            self.payload = payload
            self.selected: list[str] = []

        def select(self, folder, readonly=False):
            self.selected.append(folder)
            return ("OK", [b""])

        def uid(self, command, *args):
            return ("OK", [self.payload])

    class _Adapter(ImapAdapter):
        platform = "custom"

    adapter = _Adapter()
    fake = _BsImap(full)
    got = adapter.fetch_attachment_meta(fake, ["345"], "INBOX")
    check("批量接口按 UID 归集附件元数据",
          list(got) == ["345"] and len(got["345"]) == 1, f"实际 {got}")
    check("一次 FETCH 覆盖整页 UID（0 次正文下载）", fake.selected == ["INBOX"])

    literal = _BsImap((full[:cut], full[cut:]))
    got2 = adapter.fetch_attachment_meta(literal, ["345"], "INBOX")
    check("字面量响应拼回后可解析出附件",
          list(got2) == ["345"] and len(got2["345"]) == 1, f"实际 {got2}")

    class _Boom:
        def select(self, *a, **k):
            raise OSError("connection reset")

        def uid(self, *a, **k):
            raise AssertionError("不应走到这里")

    check("BODYSTRUCTURE 失败不抛异常（附件信息只是附加项）",
          adapter.fetch_attachment_meta(_Boom(), ["1"], "INBOX") == {})
    check("空 UID 列表不发起请求", adapter.fetch_attachment_meta(_BsImap(full), []) == {})


def test_sync_backfills_attachment_meta():
    """【回归】只取邮件头的同步路径此前永远拿不到附件信息。

    `fetch_headers()` 走的是 `BODY.PEEK[HEADER]`，拿到的字节里没有任何 MIME
    部件，`parse_headers_only()` 必然解析出 0 个附件 → 列表永远不显示 📎、
    也永远不会产生可下载的附件记录。修复方式是用 BODYSTRUCTURE 每页补一次。
    """
    _cfg, ctx, account = _make_sync_ctx("attmeta_")
    adapter = _FakeAdapter(range(1, 31), validity=100)
    _run_sync(ctx, account, adapter)

    check("整页只调用一次 BODYSTRUCTURE（不是每封一次）",
          len(adapter.meta_fetches) == 1, f"实际 {len(adapter.meta_fetches)}")
    check("这一次请求覆盖了整页 UID",
          adapter.meta_fetches and len(adapter.meta_fetches[0]) == 30,
          f"实际 {adapter.meta_fetches}")

    rows = ctx.db.query_all(
        "SELECT uid, has_attachments FROM mails WHERE account_id = ?", (account.id,))
    with_att = {r["uid"] for r in rows if r["has_attachments"]}
    check("附件元数据已回填到邮件行",
          with_att == {"5", "10", "15", "20", "25", "30"}, f"实际 {sorted(with_att)}")
    count = int(ctx.db.scalar("SELECT COUNT(*) FROM attachments"))
    check("附件行数与元数据一致（无重复、无遗漏）", count == 6, f"实际 {count}")

    check("补正文数量受 fetch_body_limit 约束（不是每封都拉全文）",
          len(adapter.body_fetches) == 20, f"实际 {len(adapter.body_fetches)}")
    check("两个来源的附件元数据按 part 对齐替换、未翻倍",
          int(ctx.db.scalar("SELECT COUNT(*) FROM attachments")) == 6,
          f"实际 {ctx.db.scalar('SELECT COUNT(*) FROM attachments')}")
    filled = int(ctx.db.scalar(
        "SELECT COUNT(*) FROM attachments WHERE content_id = 'cid-page'"))
    covered = {u for u in adapter.body_fetches if u % 5 == 0}
    check("完整解析补上了 BODYSTRUCTURE 拿不到的 content_id",
          filled == len(covered), f"实际 {filled}，补正文覆盖 {sorted(covered)}")

    # 手动再走一次 BODYSTRUCTURE，模拟「同一封邮件两次拿到元数据」→ 不应翻倍
    from unimail.sync.worker import SyncWorker
    worker = SyncWorker(account, ctx.accounts, ctx.mails.mails,
                        ctx.accounts.cursors, ctx.security, ctx.bus)
    worker._attach_meta_for_page(adapter, None, account.id, ["5", "10"])
    check("重复回填附件元数据不会产生重复行",
          int(ctx.db.scalar("SELECT COUNT(*) FROM attachments")) == 6,
          f"实际 {ctx.db.scalar('SELECT COUNT(*) FROM attachments')}")
    ctx.db.close()


# ============================================================ 16. 附件落盘安全策略
def test_attachment_safety_policy():
    """G4：大小上限、危险扩展名不还原可执行后缀、独占创建、删除同步清盘。"""
    _tmp, _cfg, _ctxmod, svcmod = setup_env("attsafe_")
    from unimail.config import MAX_ATTACHMENT_BYTES
    from unimail.core.models import AccountDraft, AttachmentMeta, NormalizedMail
    from unimail.ui.context import AppContext

    ctx = AppContext()
    ctx.bootstrap_new("pw-1234567890")
    acc = ctx.accounts.add(AccountDraft(platform="qq", email="safe@qq.com", password="code"))

    def _add(uid, filename, size):
        nm = NormalizedMail(uid=str(uid), subject=f"att {uid}", attachments=[
            AttachmentMeta(filename, "application/octet-stream", size, part_index="2")])
        return ctx.mails.mails.insert_mail(acc.id, "qq", nm)

    class _Imap:
        def select(self, *a, **k):
            return ("OK", [b""])

        def close(self):
            pass

        def logout(self):
            pass

    fake = MagicMock()
    fake.connect.return_value = _Imap()
    fake.fetch_attachment.return_value = b"MZ\x90\x00evil-bytes"
    fake.disconnect = lambda x: None

    bom = _add(1, "bom.exe", 1024)
    att = ctx.mails.mails.attachments_of(bom)[0]
    with _fake_server(fake, svcmod):
        res = ctx.mails.download_attachment(att.id)
    check("危险扩展名不还原为可执行后缀",
          res.path.name.endswith(".exe.download"), f"实际 {res.path.name}")
    check("危险扩展名被标记为已改写", res.renamed is True)
    check("给出可执行的警示文案", res.danger and "可执行" in res.name_hint,
          repr(res.name_hint))
    check("文件确实落盘且内容完整",
          res.path.exists() and res.path.read_bytes() == b"MZ\x90\x00evil-bytes")

    # 独占创建：同名文件已存在时绝不覆盖
    target = svcmod.ATTACHMENT_DIR / "deadbeef_keep.bin"
    target.write_bytes(b"orig")
    written = svcmod.MailService._atomic_write_exclusive(target, b"new")
    check("同名文件不被覆盖", written != target and target.read_bytes() == b"orig",
          f"实际 {written.name}")
    check("改用序号后缀而不是覆盖", "(1)" in written.name, f"实际 {written.name}")
    check("不回落到改写原文件", target.read_bytes() == b"orig")

    # 超过单文件上限：必须在连接服务器之前就拒绝（元数据预检）
    big = _add(2, "huge.bin", MAX_ATTACHMENT_BYTES + 1)
    att_big = ctx.mails.mails.attachments_of(big)[0]
    fake.connect.reset_mock()
    try:
        with _fake_server(fake, svcmod):
            ctx.mails.download_attachment(att_big.id)
        check("超过单文件上限时拒绝下载", False, "竟然下载了")
    except ValueError as exc:
        check("超过单文件上限时给出上限提示", "上限" in str(exc), f"实际 {exc}")
    check("超限时根本不发起 IMAP 连接", fake.connect.call_count == 0,
          f"实际 {fake.connect.call_count} 次")

    # 删除邮件 / 删除账号都必须同步清掉磁盘明文副本
    att_path = res.path
    ctx.mails.delete(bom)
    check("删除邮件时一并删除磁盘副本", not att_path.exists())

    keep = _add(3, "doc.pdf", 10)
    att_keep = ctx.mails.mails.attachments_of(keep)[0]
    with _fake_server(fake, svcmod):
        res3 = ctx.mails.download_attachment(att_keep.id)
    check("普通扩展名保持原样", res3.path.name.endswith("doc.pdf") and not res3.renamed,
          f"实际 {res3.path.name}")
    ctx.accounts.remove(acc.id)
    check("删除账号时清掉其全部附件副本", not res3.path.exists())
    check("附件目录无 .part 残留",
          not list(svcmod.ATTACHMENT_DIR.glob("*.part")),
          f"实际 {list(svcmod.ATTACHMENT_DIR.glob('*.part'))}")
    ctx.db.close()


def test_orphan_attachment_cleanup():
    """G4：异常退出/历史版本只删库行不删文件 → 启动时清理孤儿文件。"""
    _tmp, _cfg, _ctxmod, svcmod = setup_env("orphan_")
    from unimail.core.models import AccountDraft, NormalizedMail
    from unimail.ui.context import AppContext

    ctx = AppContext()
    ctx.bootstrap_new("pw-1234567890")
    acc = ctx.accounts.add(AccountDraft(platform="qq", email="o@qq.com", password="code"))
    mid = ctx.mails.mails.insert_mail(acc.id, "qq", NormalizedMail(uid="1", subject="s"))

    # 手工制造：一个「数据库不认识」的附件文件（符合本程序命名规则）
    orphan = svcmod.ATTACHMENT_DIR / "abcdef12_orphan.bin"
    orphan.write_bytes(b"leftover")
    # 以及一个不属于本程序命名规则的文件——不能误删用户自己放的东西
    keep = svcmod.ATTACHMENT_DIR / "用户自己的文件.txt"
    keep.write_text("mine", "utf-8")

    # 让数据库"认识"一个已落盘文件，确认它不会被误删
    known = svcmod.ATTACHMENT_DIR / "01234567_known.bin"
    known.write_bytes(b"known")
    ctx.db.execute(
        "INSERT INTO attachments(id, mail_id, filename, content_type, size, stored_path) "
        "VALUES(?,?,?,?,?,?)",
        ("a1", mid, "known.bin", "application/octet-stream", 5, str(known)))

    removed = ctx.mails.cleanup_orphan_attachments()
    check("孤儿附件文件被清理", not orphan.exists() and removed == 1, f"实际 removed={removed}")
    check("数据库仍引用的文件不被误删", known.exists())
    check("不属于本程序命名规则的文件保持不动", keep.exists())
    ctx.db.close()


# ============================================================ 17. KDF 与密码策略
def test_kdf_algorithms_and_password_policy():
    """G2：Argon2id 为默认；旧 PBKDF2 库仍可解锁、可识别为待升级。"""
    from unimail.config import KDF_ALGORITHM, PASSWORD_MIN_LENGTH
    from unimail.core.security import (
        KdfParams,
        SecurityError,
        SecurityService,
        derive_master_key,
        password_policy_error,
        password_strength,
    )

    params = SecurityService.new_kdf_params()
    check("新建库默认使用 Argon2id", params.algorithm == KDF_ALGORITHM,
          f"实际 {params.algorithm}")
    check("Argon2id 内存代价不低于 64 MiB", params.memory_cost >= 64 * 1024,
          f"实际 {params.memory_cost} KiB")
    check("Argon2id 参数有可读描述", "Argon2id" in params.display, params.display)

    sec = SecurityService()
    sec.setup("a-strong-passphrase", params)
    verifier = SecurityService.make_verifier(sec._master_key)
    check("Argon2id 派生 + 校验通过",
          SecurityService().unlock("a-strong-passphrase", params, verifier) is not None)

    legacy = KdfParams(salt=b"0" * 16, iterations=1000, algorithm="pbkdf2", hash_len=32)
    own = SecurityService()
    own.setup("legacy-passphrase", legacy)
    legacy_verifier = SecurityService.make_verifier(own._master_key)
    check("PBKDF2 旧参数仍可解锁（不破坏已有库）",
          SecurityService().unlock("legacy-passphrase", legacy, legacy_verifier) is not None)
    check("同参数派生结果确定",
          derive_master_key("p", legacy) == derive_master_key("p", legacy))
    check("弱参数被识别为需要升级", SecurityService.needs_upgrade(legacy) is True)
    check("当前默认参数不需升级", SecurityService.needs_upgrade(params) is False)

    rt = KdfParams.from_dict(params.to_dict())
    check("KDF 参数可无损往返（sidecar 是明文 JSON）",
          rt.algorithm == params.algorithm and rt.salt == params.salt
          and rt.memory_cost == params.memory_cost and rt.hash_len == params.hash_len,
          f"实际 {rt.to_dict()}")

    try:
        KdfParams.from_dict({"salt": "AAAA", "algorithm": "scrypt"})
        check("未知算法被显式拒绝", False, "竟然接受了 scrypt")
    except SecurityError as exc:
        check("未知算法给出可读提示（而不是当成密码错）", "不支持" in str(exc), f"实际 {exc}")

    # 环境缺少 Argon2id 时必须优雅回退，而不是让整个应用起不来
    import unimail.core.security as secmod
    with patch.object(secmod, "_ARGON2_AVAILABLE", False):
        fallback = SecurityService.new_kdf_params()
        check("缺 Argon2id 时回退 PBKDF2 而非崩溃",
              fallback.algorithm == "pbkdf2", f"实际 {fallback.algorithm}")
        try:
            derive_master_key("x", params)
            check("无法派生 Argon2id 时提示升级依赖", False, "竟然派生成功")
        except SecurityError as exc:
            check("无法派生 Argon2id 时提示升级依赖", "cryptography" in str(exc),
                  f"实际 {exc}")

    # 密码策略
    check("低于下限的密码被拒绝",
          password_policy_error("a" * (PASSWORD_MIN_LENGTH - 1)) is not None)
    check("达到下限的密码通过",
          password_policy_error("a" * PASSWORD_MIN_LENGTH) is None)
    check("太短给 0 分并说明原因", password_strength("abc")[0] == 0)
    check("足够复杂的密码评分较高", password_strength("Xk7#mQ2$pL9@wZ4!")[0] >= 3,
          f"实际 {password_strength('Xk7#mQ2$pL9@wZ4!')}")


def test_kdf_upgrade_on_password_change():
    """G2：改密码是唯一能安全更换 salt 的时机 → 旧 PBKDF2 库借此升级。"""
    _tmp, cfg, _ctxmod, _svc = setup_env("kdfup_")
    import unimail.core.security as secmod
    from unimail.config import KDF_ALGORITHM, KDF_ALGORITHM as _cfg_algo
    from unimail.ui.context import AppContext

    meta = cfg.DB_PATH.with_suffix(".meta.json")

    with patch.object(secmod, "KDF_ALGORITHM", "pbkdf2"):
        ctx = AppContext()
        ctx.bootstrap_new("pw-1234567890")
        check("模拟旧库：以 PBKDF2 建库",
              json.loads(meta.read_text("utf-8"))["algorithm"] == "pbkdf2",
              json.loads(meta.read_text("utf-8")).get("algorithm"))
        ctx.db.close()

    ctx2 = AppContext()
    ctx2.is_first_run = False
    ctx2.unlock("pw-1234567890")
    check("旧 PBKDF2 库仍能正常解锁", ctx2.security.is_unlocked)
    check("检测到 KDF 需要升级", ctx2.kdf_upgrade_pending is True)

    res = ctx2.change_password("pw-1234567890", "pw-9876543210")
    check("改密码后 KDF 已升级到当前默认（Argon2id）",
          "Argon2id" in res.kdf, f"实际 {res.kdf!r}")
    check("升级后不再提示", ctx2.kdf_upgrade_pending is False)
    check("侧车已记录新算法",
          json.loads(meta.read_text("utf-8"))["algorithm"] == _cfg_algo,
          json.loads(meta.read_text("utf-8")).get("algorithm"))
    check("当前默认算法确实是 argon2id", KDF_ALGORITHM == "argon2id", KDF_ALGORITHM)
    ctx2.db.close()

    ctx3 = AppContext()
    ctx3.is_first_run = False
    ctx3.unlock("pw-9876543210")
    check("升级后重启仍可解锁", ctx3.security.is_unlocked)
    ctx3.db.close()


# ============================================================ 18. 解锁退避持久化
def test_unlock_guard_backoff():
    """G2：解锁退避必须持久化，否则「关掉再开」等于把尝试次数清零。"""
    _tmp, cfg, _ctxmod, _svc = setup_env("guard_")
    from unimail.core.security import SecurityError, UnlockGuard

    path = cfg.guard_path(cfg.DB_PATH)
    check("退避文件与数据库同目录", path.parent == cfg.DB_PATH.parent)

    guard = UnlockGuard(path)
    check("初始无失败记录", guard.failures == 0 and guard.remaining_wait() == 0)
    guard.check()                      # 不应抛错

    d1 = guard.record_failure()
    d2 = guard.record_failure()
    d3 = guard.record_failure()
    check("退避按 1/2/4 秒递增", (round(d1), round(d2), round(d3)) == (1, 2, 4),
          f"实际 {d1}/{d2}/{d3}")
    check("退避文件已落盘", path.exists())
    blob = path.read_text("utf-8")
    check("退避文件不含任何凭据或密文",
          "password" not in blob and "verifier" not in blob and "salt" not in blob, blob)

    fresh = UnlockGuard(path)          # 模拟重启进程
    check("失败次数跨进程保留", fresh.failures == 3, f"实际 {fresh.failures}")
    try:
        fresh.check()
        check("冷却期内拒绝再次尝试", False, "竟然通过了")
    except SecurityError as exc:
        check("冷却期内给出等待提示", "等待" in str(exc), f"实际 {exc}")

    for _ in range(10):
        guard.record_failure()
    check("退避有上限（不会无限增长）",
          guard.remaining_wait() <= cfg.UNLOCK_BACKOFF_MAX + 1.0,
          f"实际 {guard.remaining_wait():.1f}s")

    guard.reset()
    check("清零后失败次数归零", UnlockGuard(path).failures == 0)
    UnlockGuard(path).check()

    # 端到端：AppContext.unlock 失败要写入退避，且新进程立刻受同一限制
    _tmp2, cfg2, _c2, _s2 = setup_env("guard2_")
    from unimail.ui.context import AppContext

    c = AppContext()
    c.bootstrap_new("pw-1234567890")
    check("新建库会重置退避（不继承上一个库的失败计数）",
          UnlockGuard(cfg2.guard_path(cfg2.DB_PATH)).failures == 0)
    c.db.close()

    gp = cfg2.guard_path(cfg2.DB_PATH)

    def _let_cooldown_expire() -> None:
        """模拟「时间流逝」：只清掉冷却截止时间，**保留失败次数**。

        不能用 `reset()`——那等于把计数清零，反而绕过了本用例要验证的东西。
        """
        data = json.loads(gp.read_text("utf-8"))
        data["next_allowed"] = 0.0
        gp.write_text(json.dumps(data), "utf-8")

    c2 = AppContext()
    c2.is_first_run = False
    for _ in range(2):
        _let_cooldown_expire()
        with contextlib.suppress(SecurityError):
            c2.unlock("wrong-password")
    check("解锁失败被持久化", json.loads(gp.read_text("utf-8"))["failures"] == 2,
          gp.read_text("utf-8"))
    check("新进程立即处于冷却期", UnlockGuard(gp).remaining_wait() > 0)

    _let_cooldown_expire()             # 等价于用户等待结束
    c3 = AppContext()
    c3.is_first_run = False
    c3.unlock("pw-1234567890")
    check("冷却结束后正确密码可解锁", c3.security.is_unlocked)
    check("成功解锁后退避已清零", UnlockGuard(gp).failures == 0)
    c3.db.close()


# ============================================================ 19. 恶意 MIME 语料
def _hostile_mime_corpus() -> list[tuple[str, bytes]]:
    """真实世界里会遇到的坏输入：不是「构造精巧的攻击」，而是**每天都会出现**
    的畸形报文。解析链路必须逐个扛住——它们来自不可信的第三方。"""
    nested = b""
    depth = 40
    for i in range(depth):
        nested += (b'Content-Type: multipart/mixed; boundary="B%d"\r\n\r\n--B%d\r\n' % (i, i))
    nested += b"Content-Type: text/plain\r\n\r\nbody\r\n"
    for i in reversed(range(depth)):
        nested += b"--B%d--\r\n" % i

    return [
        ("空报文", b""),
        ("只有头部没有正文", b"Subject: only-headers\r\n"),
        ("只有正文没有头部", b"\r\njust a body without headers"),
        ("boundary 声明但从不闭合",
         b'Subject: unclosed\r\nMIME-Version: 1.0\r\n'
         b'Content-Type: multipart/mixed; boundary="NEVER"\r\n\r\n--NEVER\r\n'
         b"Content-Type: text/plain\r\n\r\nhi\r\n"),
        ("multipart 声明却给了单个字符串正文",
         b"Subject: s\r\nContent-Type: multipart/mixed\r\n\r\nplain text, no boundary"),
        (f"深嵌套 multipart（{depth} 层）",
         b"Subject: deep\r\nMIME-Version: 1.0\r\n" + nested),
        ("charset 声明 gb2312 但字节是 utf-8",
         b"Subject: =?gb2312?B?5L2g5aW9?=\r\n"
         b'Content-Type: text/plain; charset="gb2312"\r\n\r\n'
         + "中文正文".encode()),
        ("base64 声明却是垃圾数据",
         b'Subject: bad-b64\r\nContent-Type: text/plain; charset="utf-8"\r\n'
         b"Content-Transfer-Encoding: base64\r\n\r\n!!!not base64 at all!!!"),
        ("截断的编码头",
         b"Subject: =?utf-8?B?5LiN5a6M5pW0?=\r\n"
         b"From: =?utf-8?Q?unfinished\r\n\r\nbody"),
        ("头部 CRLF 注入（伪造额外头）",
         b"Subject: safe\r\nX-Injected: 1\r\n\r\nbody"),
        ("超长主题（10 万字符）",
         b"Subject: " + b"A" * 100_000 + b"\r\n\r\nbody"),
        ("路径穿越式附件名",
         b'Subject: traverse\r\nMIME-Version: 1.0\r\n'
         b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n--B\r\n'
         b'Content-Type: application/octet-stream; name="../../../../etc/passwd"\r\n'
         b'Content-Disposition: attachment; filename="../../../.bashrc"\r\n'
         b"Content-Transfer-Encoding: base64\r\n\r\nAAAA\r\n--B--\r\n"),
        ("HTML 正文里的 XSS / 跟踪像素",
         b'Subject: hostile-html\r\nMIME-Version: 1.0\r\n'
         b'Content-Type: text/html; charset="utf-8"\r\n\r\n'
         + (
             '<script>fetch("http://evil.example/x")</script>'
             '<img src="http://tracker.example/p.gif">'
             '<a href="javascript:alert(1)">click</a>'
             "<p>正常内容</p>"
         ).encode()),
    ]


def test_hostile_mime_corpus():
    """G5：畸形/恶意 MIME 不能让解析链路抛异常，也不能漏出可执行内容。"""
    from unimail.platforms.parser import (
        parse_headers_only,
        parse_message,
        sanitize_html,
    )

    crashed: list[str] = []
    for name, raw in _hostile_mime_corpus():
        try:
            nm = parse_message(raw, "1")
            hd = parse_headers_only(raw, "1")
        except Exception as exc:  # noqa: BLE001 - 这里就是要证明「不会抛」
            crashed.append(f"{name}: {type(exc).__name__}: {exc}")
            continue
        if not isinstance(nm.subject, str) or not isinstance(hd.subject, str):
            crashed.append(f"{name}: subject 不是字符串")
    check("全部畸形报文都能安全解析（不抛异常）", not crashed, "；".join(crashed))

    # 深嵌套：必须能解析完，而不是 RecursionError
    deep = dict(_hostile_mime_corpus())["深嵌套 multipart（40 层）"]
    nm_deep = parse_message(deep, "1")
    check("深嵌套 multipart 不会栈溢出",
          isinstance(nm_deep.body_html, str) and isinstance(nm_deep.body_text, str))

    # 编码声明与实际字节不符时：必须回落到能解码的尝试序列，而不是抛 UnicodeError
    wrong_cs = dict(_hostile_mime_corpus())["charset 声明 gb2312 但字节是 utf-8"]
    nm_cs = parse_message(wrong_cs, "1")
    check("charset 谎言不会导致解码失败", "中文" in nm_cs.body_text,
          f"实际 {nm_cs.body_text!r}")

    # 垃圾 base64：不能抛，也不能把正文当附件
    bad_b64 = dict(_hostile_mime_corpus())["base64 声明却是垃圾数据"]
    nm_b64 = parse_message(bad_b64, "1")
    check("垃圾 base64 不会导致解析失败", isinstance(nm_b64.body_text, str))

    # XSS / 跟踪像素：这是最需要被守住的一条
    hostile = dict(_hostile_mime_corpus())["HTML 正文里的 XSS / 跟踪像素"]
    nm_html = parse_message(hostile, "1")
    low = nm_html.body_html.lower()
    check("恶意 HTML 中的 script 已被剥离", "script" not in low, nm_html.body_html)
    check("恶意 HTML 中的跟踪像素已剥离", "tracker.example" not in low, nm_html.body_html)
    check("恶意 HTML 中的 javascript: 链已剥离", "javascript" not in low, nm_html.body_html)
    check("正常内容保留", "正常内容" in nm_html.body_html, nm_html.body_html)

    # 路径穿越式文件名：解析阶段**如实保留**（邮件里写的是什么就是什么，
    # 这样 UI 能原样展示给用户看），真正的防线在落盘阶段——这里验证那道防线。
    traverse = dict(_hostile_mime_corpus())["路径穿越式附件名"]
    nm_tr = parse_message(traverse, "1")
    check("路径穿越式文件名被如实解析（Content-Disposition 优先）",
          bool(nm_tr.attachments) and nm_tr.attachments[0].filename.startswith("../"),
          f"实际 {[a.filename for a in nm_tr.attachments]}")
    from unimail.core.services import safe_attachment_name
    hostile_names = [
        nm_tr.attachments[0].filename,
        "../../../../etc/passwd",
        "..\\..\\Windows\\System32\\cmd.exe",
        "/etc/shadow",
        "C:\\Windows\\notepad.exe",
        "NUL",
        "CON.txt",
        "com1.bat",
        "....",
        "   ",
        "report" + ".pdf" * 100,
        "bad\x00name\x1f.txt",
    ]
    leaks = []
    for bad in hostile_names:
        got = safe_attachment_name(bad)
        if "/" in got or "\\" in got or got in {"", ".", ".."}:
            leaks.append(f"{bad!r} → {got!r}")
        if len(got) > 120:
            leaks.append(f"{bad!r} → 超长 {len(got)}")
        if got.split(".", 1)[0].lower() in {"con", "prn", "aux", "nul", "com1"}:
            leaks.append(f"{bad!r} → 命中保留设备名 {got!r}")
    check("附件名净化不留任何路径分隔符 / 保留设备名", not leaks, "；".join(leaks))
    check("净化后的名字等于自身 basename（拼不出跨目录路径）",
          all(Path(safe_attachment_name(n)).name == safe_attachment_name(n)
              for n in hostile_names))
    check("空名字回落到中性占位名", safe_attachment_name("") == "attachment.bin")

    # 清洗器本身：单独再过一遍「白名单之外的标签/属性一律不输出」
    check("sanitize_html 对畸形输入不抛异常",
          isinstance(sanitize_html("<div><p>a<script>b<!-- c"), str))


# ============================================================ 20. 中断注入
def test_interruption_injection():
    """G5：在关键写入路径上注入中断，验证「要么完整落盘、要么保持原状」。

    这些路径的共同点是「写入过程中掉电/崩溃会造成不可逆损坏」：
    批量入库、附件落盘、侧车写入、整库加密迁移。
    """
    _tmp, _cfg, _ctxmod, svcmod = setup_env("crash_")
    from unimail.core.models import AccountDraft, NormalizedMail
    from unimail.core.security import SecurityService
    from unimail.storage import AccountRepository, Database, MailRepository
    from unimail.ui.context import atomic_write_json

    tmp, _cfg2, _ctxmod2, _svc2 = setup_env("crash_tx_")
    sec = SecurityService()
    sec.setup("pw-1234567890", SecurityService.new_kdf_params())
    db = Database(tmp / "t.db", sec.db_key(), encrypted=False)
    accounts, mails = AccountRepository(db), MailRepository(db)
    acc = accounts.insert(AccountDraft(platform="qq", email="c@qq.com", password="x"))
    now = datetime.now(timezone.utc)
    base = [NormalizedMail(uid=str(i), subject=f"m{i}", date=now) for i in range(1, 11)]

    # ---- ① 批量入库事务中途中断 → 整批回滚，不留「半页」
    sql_insert = (
        "INSERT INTO mails (id, account_id, platform, folder, uid, uid_validity, "
        "subject, date, created_at) VALUES (?,?,?,?,?,?,?,?,?)"
    )

    def _row(mail: NormalizedMail) -> tuple:
        return ("id-" + mail.uid, acc.id, "qq", "INBOX", mail.uid, 1,
                mail.subject, now.isoformat(), now.isoformat())

    with contextlib.suppress(RuntimeError), db.transaction() as conn:
        conn.executemany(sql_insert, [_row(m) for m in base[:5]])
        raise RuntimeError("注入中断：模拟写入中途掉电")
    check("事务中断后整批回滚，不留半页数据",
          int(db.scalar("SELECT COUNT(*) FROM mails")) == 0,
          f"实际 {db.scalar('SELECT COUNT(*) FROM mails')}")

    ok = mails.insert_mails_batch(acc.id, "qq", base, uid_validity=1)
    check("中断后事务仍可正常使用", ok.new_count == 10, f"实际 {ok.new_count}")

    # ---- ② 附件落盘中途中断 → 原文件不被改写、不留 .part 残骸
    target = svcmod.ATTACHMENT_DIR / "cafebabe_partial.bin"
    target.write_bytes(b"original")
    with patch("os.fsync", side_effect=OSError("模拟断电")):
        try:
            svcmod.MailService._atomic_write_exclusive(target, b"new-bytes")
            check("附件写入中断时抛错而不是静默成功", False, "竟然没抛错")
        except OSError:
            check("附件写入中断时抛错而不是静默成功", True)
    check("中断后原文件内容未被改写", target.read_bytes() == b"original")
    check("中断后不留 .part 残骸",
          not list(svcmod.ATTACHMENT_DIR.glob("*.part")),
          f"实际 {[p.name for p in svcmod.ATTACHMENT_DIR.glob('*.part')]}")
    check("中断后不留占位空文件",
          sorted(p.name for p in svcmod.ATTACHMENT_DIR.iterdir()) == [target.name],
          f"实际 {sorted(p.name for p in svcmod.ATTACHMENT_DIR.iterdir())}")

    # ---- ③ 侧车写入中途中断 → 旧侧车完好、不留 .tmp
    meta = _cfg.DB_PATH.with_suffix(".meta.json")
    atomic_write_json(meta, {"verifier": "v1", "salt": "s1"})
    before = meta.read_text("utf-8")
    with patch("os.replace", side_effect=OSError("模拟断电")):
        try:
            atomic_write_json(meta, {"verifier": "v2", "salt": "s2"})
            check("侧车写入中断时抛错而不是静默成功", False, "竟然没抛错")
        except OSError:
            check("侧车写入中断时抛错而不是静默成功", True)
    check("中断后旧侧车内容完好", meta.read_text("utf-8") == before)
    check("中断后不留 .tmp 残骸", not list(meta.parent.glob("*.tmp")),
          f"实际 {[p.name for p in meta.parent.glob('*.tmp')]}")
    check("旧侧车仍可被读回", json.loads(meta.read_text("utf-8"))["verifier"] == "v1")

    db.close()
    _assert_migration_failure_keeps_source()


def _assert_migration_failure_keeps_source() -> None:
    """④ 整库加密迁移在校验环节中断 → 原库保持可读，且不留 *.enc-tmp。"""
    from unimail.core.models import AccountDraft, NormalizedMail
    from unimail.core.security import SecurityService
    from unimail.storage import (
        AccountRepository,
        Database,
        DatabaseError,
        MailRepository,
        sqlcipher_available,
    )

    if not sqlcipher_available():
        # 降级模式（无 SQLCipher）下迁移入口本身就会明确拒绝，这里只验证这一点
        tmp, _cfg, _ctxmod, _svc = setup_env("crash_mig_")
        sec = SecurityService()
        sec.setup("pw-1234567890", SecurityService.new_kdf_params())
        plain = Database(tmp / "m.db", sec.db_key(), encrypted=False)
        try:
            plain.migrate_to_encrypted(b"k" * 32)
            check("无 SQLCipher 时迁移被明确拒绝", False, "竟然开始迁移了")
        except DatabaseError as exc:
            check("无 SQLCipher 时迁移被明确拒绝", "sqlcipher3" in str(exc), str(exc))
        plain.close()
        return

    tmp, _cfg, _ctxmod, _svc = setup_env("crash_mig_")
    sec = SecurityService()
    sec.setup("pw-1234567890", SecurityService.new_kdf_params())
    plain = Database(tmp / "m.db", sec.db_key(), encrypted=False)
    accounts = AccountRepository(plain)
    mails = MailRepository(plain)
    acc = accounts.insert(AccountDraft(platform="qq", email="m@qq.com", password="x"))
    mails.insert_mails_batch(acc.id, "qq", [
        NormalizedMail(uid=str(i), subject=f"m{i}",
                       date=datetime.now(timezone.utc)) for i in range(1, 4)
    ], uid_validity=1)

    with patch.object(Database, "_verify_migrated_file",
                      side_effect=DatabaseError("注入中断：迁移校验失败")):
        try:
            plain.migrate_to_encrypted(b"k" * 32)
            check("迁移校验失败时不替换原库", False, "竟然替换了")
        except DatabaseError:
            check("迁移校验失败时不替换原库", True)

    check("中断后不留 .enc-tmp 半成品", not list(tmp.glob("*.enc-tmp")),
          f"实际 {[p.name for p in tmp.glob('*.enc-tmp')]}")
    check("中断后数据库对象被恢复为可用（无需重启程序）",
          int(plain.scalar("SELECT COUNT(*) FROM mails")) == 3,
          f"实际 {plain.scalar('SELECT COUNT(*) FROM mails')}")
    plain.close()

    # 用裸 sqlite3 回读原文件，确认它仍是原来那个明文库
    import sqlite3
    conn = sqlite3.connect(str(tmp / "m.db"))
    rows = conn.execute("SELECT COUNT(*) FROM mails").fetchone()[0]
    conn.close()
    check("中断后磁盘上的原库文件仍是可读的明文库", int(rows) == 3, f"实际 {rows}")


# ============================================================ 21. 全文检索
def test_fulltext_search():
    """FTS5 全文索引：CJK 切分、触发器同步、LIKE 回退与注入安全。"""
    from datetime import datetime, timezone

    from unimail.core.models import MailFilter, NormalizedMail
    from unimail.core.textsearch import fts_eligible, match_query, segment
    from unimail.storage import Database, MailRepository

    _tmp, cfg, _ctx, _svc = setup_env("fts_")
    db = Database(cfg.DB_PATH, None, encrypted=False)
    mails = MailRepository(db)

    check("新库自动建立全文索引", db.fts_available)

    now = datetime.now(timezone.utc)

    def mk(uid, subject, body):
        return NormalizedMail(uid=uid, subject=subject, body_text=body,
                              preview=body[:80], date=now)

    res = mails.insert_mails_batch("acc1", "qq", [
        mk("1", "项目进度更新", "关于下周会议安排的通知，请查收附件。"),
        mk("2", "Quarterly report", "Please review the attached report."),
        mk("3", "全角测试", "ＡＢＣ １２３ 全角字母数字"),
        mk("4", "无关邮件", "今天天气不错。"),
    ], uid_validity=1)
    check("批量写入 4 封", len(res.inserted) == 4)
    check("触发器已同步索引行数", db.fts_stats() == (4, 4), f"实际 {db.fts_stats()}")

    def hits(kw):
        return [m.subject for m in mails.query_summaries(MailFilter(keyword=kw, limit=100))]

    check("中文 2 字检索命中", "项目进度更新" in hits("会议"), f"命中 {hits('会议')}")
    check("中文 4 字检索命中", "项目进度更新" in hits("会议安排"))
    check("中文跨词连续子串命中", "项目进度更新" in hits("项目进"))
    check("词序反例：搜「议会」不命中「会议」", hits("议会") == [], f"命中 {hits('议会')}")
    check("英文检索命中", "Quarterly report" in hits("report"))
    check("英文大小写不敏感", "Quarterly report" in hits("REPORT"))
    check("全角字母经 NFKC 命中", "全角测试" in hits("ABC"))
    check("全角数字经 NFKC 命中", "全角测试" in hits("123"))
    check("未出现的词不命中", hits("锌镉锑") == [])
    check("多词 AND：无邮件同时含两词则不命中", hits("会议 天气") == [])

    check("给出关键词命中总数", mails.count_search(MailFilter(keyword="会议")) == 1,
          f"实际 {mails.count_search(MailFilter(keyword='会议'))}")

    # ---- 更新正文 → 索引跟随
    mails.update_body(res.inserted[0][1], "改成了完全不同的内容", "")
    check("更新正文后旧词不再命中", "项目进度更新" not in hits("会议"))
    check("更新正文后新词可命中", "项目进度更新" in hits("完全不同的内容"),
          f"命中 {hits('完全不同的内容')}")
    check("更新正文后预览也同步刷新（列表摘要不再是空的）",
          bool((mails.get(res.inserted[0][1]).preview or "").strip()),
          f"实际 {mails.get(res.inserted[0][1]).preview!r}")

    # ---- 标已读 / 加星标不应触发索引重建（触发器限定 UPDATE OF 这几个列）
    mails.set_read(res.inserted[1][1], True)
    mails.set_starred(res.inserted[1][1], True)
    check("标已读/加星标后仍可检索", "Quarterly report" in hits("report"))
    check("标已读/加星标不改变索引行数", db.fts_stats() == (4, 4),
          f"实际 {db.fts_stats()}")

    # ---- 删除 → 索引跟随
    mails.delete(res.inserted[3][1])
    check("删除后索引行数跟进", db.fts_stats() == (3, 3), f"实际 {db.fts_stats()}")
    check("已删除邮件不再命中", "无关邮件" not in hits("天气"))

    # ---- 含标点的关键词回退 LIKE：语义与历史行为一致
    check("含标点的关键词不走全文索引",
          not fts_eligible("a_b") and not fts_eligible("%") and not fts_eligible("a-b"))
    check("纯字母数字 / CJK / 空格可走全文索引",
          fts_eligible("report") and fts_eligible("会议 纪要") and fts_eligible("API 文档"))
    check("纯空白不可检索", not fts_eligible("   "))

    # ---- 注入尝试：一律当普通文本，不抛异常、不匹配全库
    for evil in ['" OR 1=1', "*", "NEAR", "(", ")", ":", "^", "a NEAR b"]:
        got = hits(evil)
        check(f"注入尝试被安全处理 {evil!r}",
              all("无关" not in s for s in got), f"命中 {got}")

    # ---- 索引重建
    before = db.fts_stats()
    rebuilt = db.fts_rebuild()
    check("索引可全量重建且行数一致", rebuilt == before[0] == db.fts_stats()[1],
          f"重建 {rebuilt} / 重建前 {before}")
    check("重建后仍可检索", "Quarterly report" in hits("report"))

    # ---- 切分与匹配式
    check("CJK 逐字切分", " ".join(segment("会议").split()) == "会 议",
          f"实际 {segment('会议')!r}")
    check("NFKC 归一全角字母", segment("ＡＢＣ") == "ABC")
    check("切分对 None 安全返回空串", segment(None) == "")
    check("匹配式把中文词包成短语", match_query("会议") == '"会 议"',
          f"实际 {match_query('会议')!r}")
    check("多词用 AND 连接", match_query("会议 纪要") == '"会 议" AND "纪 要"',
          f"实际 {match_query('会议 纪要')!r}")
    check("引号被转义（无法闭合短语）", match_query('"') == '""""',
          f"实际 {match_query(chr(34))!r}")
    check("无词元时返回空串", match_query("   ") == "")

    db.close()


# ============================================================ 22. 会话引用链
def test_thread_grouping():
    """References / In-Reply-To 解析与会话归并键。"""
    from datetime import datetime, timezone

    from unimail.core.models import NormalizedMail
    from unimail.platforms.parser import parse_message
    from unimail.storage import Database, MailRepository

    def raw(headers: str, body: str = "正文") -> bytes:
        return (headers + "Content-Type: text/plain; charset=utf-8\r\n\r\n"
                + body).encode("utf-8")

    nm = parse_message(raw(
        "Subject: Re: 会议纪要\r\n"
        "Message-ID: <m3@example.com>\r\n"
        "References: <root@example.com> <m1@example.com> <m2@example.com>\r\n"
        "In-Reply-To: <m2@example.com>\r\n"), "3")
    check("解析出 References 里全部 message-id",
          nm.references == ["root@example.com", "m1@example.com", "m2@example.com"],
          f"实际 {nm.references}")
    check("解析出 In-Reply-To", nm.in_reply_to == ["m2@example.com"],
          f"实际 {nm.in_reply_to}")
    check("会话键取 References 的第一个（会话根）",
          nm.thread_key == "root@example.com", f"实际 {nm.thread_key}")
    check("自身 message-id 已去尖括号", nm.message_id == "m3@example.com",
          f"实际 {nm.message_id}")

    nm2 = parse_message(raw("Subject: hi\r\nIn-Reply-To: <parent@example.com>\r\n"), "4")
    check("无 References 时回落到 In-Reply-To",
          nm2.thread_key == "parent@example.com", f"实际 {nm2.thread_key}")

    nm3 = parse_message(raw("Subject: solo\r\nMessage-ID: <solo@example.com>\r\n"), "5")
    check("无引用头时回落到自身 message-id",
          nm3.thread_key == "solo@example.com", f"实际 {nm3.thread_key}")

    nm4 = parse_message(raw("Subject: bare\r\n"), "6")
    check("引用链全缺失时 thread_key 为空（交由落库侧兜底）",
          nm4.thread_key == "", f"实际 {nm4.thread_key!r}")

    nm5 = parse_message(raw("Subject: noangle\r\nReferences: a@x.com b@x.com\r\n"), "7")
    check("容忍不带尖括号的 message-id",
          nm5.references == ["a@x.com", "b@x.com"], f"实际 {nm5.references}")

    nm6 = parse_message(raw(
        "Subject: folded\r\n"
        "References: <r@x.com>\r\n <mid1@x.com>\r\n\t<mid2@x.com>\r\n"), "8")
    check("容忍折行的 References（RFC 5322 允许）",
          nm6.thread_key == "r@x.com" and len(nm6.references) == 3,
          f"实际 {nm6.references}")

    # ---- 落库后字段可读回，缺失时兜底为 mail_id
    _tmp, cfg, _ctx, _svc = setup_env("thread_")
    db = Database(cfg.DB_PATH, None, encrypted=False)
    mails = MailRepository(db)
    now = datetime.now(timezone.utc)
    res = mails.insert_mails_batch("acc1", "qq", [
        NormalizedMail(uid="1", subject="root", body_text="根", date=now,
                       message_id="root@x.com", thread_key="root@x.com"),
        NormalizedMail(uid="2", subject="re", body_text="回复", date=now,
                       message_id="m2@x.com", references=["root@x.com"],
                       in_reply_to=["root@x.com"], thread_key="root@x.com"),
        NormalizedMail(uid="3", subject="solo", body_text="单封", date=now),
    ], uid_validity=1)
    check("批量写入 3 封", len(res.inserted) == 3)
    ids = dict(res.inserted)
    m_root, m_re, m_solo = (mails.get(ids["1"]), mails.get(ids["2"]), mails.get(ids["3"]))
    check("落库后 References 可读回", m_re.references == ["root@x.com"],
          f"实际 {m_re.references}")
    check("落库后 In-Reply-To 可读回", m_re.in_reply_to == ["root@x.com"],
          f"实际 {m_re.in_reply_to}")
    check("同会话的两封 thread_key 相同",
          m_root.thread_key == m_re.thread_key == "root@x.com",
          f"实际 {m_root.thread_key} / {m_re.thread_key}")
    check("无引用头的邮件 thread_key 兜底为自身 mail_id",
          m_solo.thread_key == ids["3"], f"实际 {m_solo.thread_key!r} vs {ids['3']!r}")
    check("thread_key 可随列表投影取出（会话视图分组用）",
          m_re.to_summary().thread_key == "root@x.com")
    check("伪造的 ref_ids 脏值不会让邮件读不出来",
          _dirty_ref_ids_readable(db, mails, ids["1"]))
    db.close()


def _dirty_ref_ids_readable(db, mails, mail_id: str) -> bool:
    """把 ref_ids 改成非法 JSON，确认读取时退化为空列表而不是抛异常。"""
    db.execute("UPDATE mails SET ref_ids = ? WHERE id = ?", ("{不是 JSON", mail_id))
    try:
        return mails.get(mail_id).references == []
    except Exception:  # noqa: BLE001
        return False



# ============================================================ 26. 事件总线带负载
def test_event_bus_payloads():
    """v1.4.0：同步线程只报「新增了哪些 id」，UI 才能做增量插入。"""
    _tmp, _cfg, _ctxmod, _svc = setup_env("bus_")
    from unimail.core.events import EventBus

    bus = EventBus()
    inserted: list[tuple[str, list]] = []
    removed: list[list] = []
    tasks: list[tuple[str, str]] = []
    done: list[tuple[str, bool, str]] = []

    bus.mails_inserted.connect(lambda aid, ids: inserted.append((aid, list(ids))))
    bus.mails_removed.connect(lambda ids: removed.append(list(ids)))
    bus.task_started.connect(lambda tid, label: tasks.append((tid, label)))
    bus.task_finished.connect(lambda tid, ok, msg: done.append((tid, ok, msg)))

    bus.emit_mails_inserted("acc1", ["m1", "m2"])
    bus.emit_mails_inserted("acc1", [])          # 空列表不触发（避免无意义刷新）
    bus.emit_mails_removed(["m1"])
    bus.emit_task_started("sync:acc1", "同步 a@b.c")
    bus.emit_task_finished("sync:acc1", True, "新增 2 封")

    check("mails_inserted 携带账号与 id 列表", inserted == [("acc1", ["m1", "m2"])],
          f"实际 {inserted}")
    check("空的插入事件被过滤", len(inserted) == 1)
    check("mails_removed 携带 id 列表", removed == [["m1"]], f"实际 {removed}")
    check("task_started 携带任务标签", tasks == [("sync:acc1", "同步 a@b.c")])
    check("task_finished 携带结果与消息", done == [("sync:acc1", True, "新增 2 封")])


# ============================================================ 27. 待回写标记队列
def test_pending_flags_queue():
    """离线期间点的已读/星标要排队，下次同步推回服务器（STORE ±FLAGS）。"""
    _tmp, _cfg, _ctxmod, _svc = setup_env("pf_")
    from unimail.core.models import AccountDraft, NormalizedMail
    from unimail.storage import PendingFlagRepository
    from unimail.ui.context import AppContext

    ctx = AppContext()
    ctx.bootstrap_new("pw-1234567890")
    acc = ctx.accounts.add(AccountDraft(platform="qq", email="pf@qq.com", password="c"))
    store = PendingFlagRepository(ctx.db)

    nm = NormalizedMail(uid="1", subject="s", from_addr="a@b.c",
                        date=datetime.now(timezone.utc))
    mid = ctx.mails.mails.insert_mail(acc.id, "qq", nm)
    row = ctx.db.query_one("SELECT folder, uid FROM mails WHERE id = ?", (mid,))

    # 同一标志同时出现在增/删里 → 不产生任何记录（等价于没点）
    store.add(acc.id, "INBOX", row["uid"], add=["\\Seen"], remove=["\\Seen"])
    check("同标志同时增删视为无操作", store.count(acc.id) == 0,
          f"实际 {store.count(acc.id)}")

    # 反复点「已读/未读」必须收敛成**一条**记录（后者定稿），
    # 否则会堆出一串自相矛盾的 STORE 指令，按顺序全发一遍既浪费往返，
    # 又可能以中间态收场。
    store.add(acc.id, "INBOX", row["uid"], add=[], remove=["\\Seen"])
    store.add(acc.id, "INBOX", row["uid"], add=["\\Seen"], remove=[])
    check("反复切换只留一条记录", store.count(acc.id) == 1,
          f"实际 {store.count(acc.id)}")
    merged = store.list_for_account(acc.id)[0]
    check("最后一次意图定稿（只发 +FLAGS）",
          merged["add_flags"] == ["\\Seen"] and merged["remove_flags"] == [],
          f"实际 {dict(merged)}")

    # 不同标志叠加到同一条记录上
    store.drop_for_uid(acc.id, "INBOX", row["uid"])
    store.add(acc.id, "INBOX", row["uid"], add=["\\Flagged"], remove=[])
    store.add(acc.id, "INBOX", row["uid"], add=["\\Seen"], remove=[])
    check("两个不同标记合并为一条记录", store.count(acc.id) == 1)
    merged = store.list_for_account(acc.id)[0]
    check("合并后两个标志都在", sorted(merged["add_flags"]) == ["\\Flagged", "\\Seen"],
          f"实际 {dict(merged)}")

    store.drop_for_uid(acc.id, "INBOX", row["uid"])
    check("按 UID 清空队列", store.count(acc.id) == 0)

    # 不同 UID 互不干扰
    nm2 = NormalizedMail(uid="2", subject="s2", from_addr="a@b.c",
                         date=datetime.now(timezone.utc))
    mid2 = ctx.mails.mails.insert_mail(acc.id, "qq", nm2)
    row2 = ctx.db.query_one("SELECT folder, uid FROM mails WHERE id = ?", (mid2,))
    store.add(acc.id, "INBOX", row["uid"], add=["\\Seen"], remove=[])
    store.add(acc.id, "INBOX", row2["uid"], add=["\\Flagged"], remove=[])
    check("不同 UID 各自成条", store.count(acc.id) == 2)

    # mark_read 走服务层时应自动入队（开关默认开）
    store.drop_for_uid(acc.id, "INBOX", row["uid"])
    before = ctx.mails.pending_flag_count(acc.id)
    ctx.mails.sync_server_flags = True
    ctx.mails.mark_read(mid, True)
    check("标已读会排入待回写队列",
          ctx.mails.pending_flag_count(acc.id) == before + 1,
          f"实际 {ctx.mails.pending_flag_count(acc.id)}")
    item = next(i for i in store.list_for_account(acc.id) if i["uid"] == row["uid"])
    check("入队内容是 +FLAGS \\Seen",
          item["add_flags"] == ["\\Seen"] and item["remove_flags"] == [],
          f"实际 {dict(item)}")

    # 再点一次「未读」→ 同一 UID 收敛成一条，方向以后者为准
    ctx.mails.mark_read(mid, False)
    item = next(i for i in store.list_for_account(acc.id) if i["uid"] == row["uid"])
    check("反向操作覆盖同一条记录而不是再排一条",
          item["remove_flags"] == ["\\Seen"] and item["add_flags"] == [],
          f"实际 {dict(item)}")

    after = ctx.mails.pending_flag_count(acc.id)
    ctx.mails.sync_server_flags = False
    ctx.mails.mark_read(mid, True)
    check("关闭开关后不再入队", ctx.mails.pending_flag_count(acc.id) == after,
          f"实际 {ctx.mails.pending_flag_count(acc.id)} vs {after}")
    ctx.db.close()


# ============================================================ 28. 导出 eml / mbox / CSV
def test_export_formats():
    """导出必须能被第三方工具打开：RFC2047 主题、mboxo 转义、CSV BOM。"""
    import base64
    import csv as _csv
    import mailbox
    from email import message_from_bytes
    from email.header import decode_header, make_header

    _tmp, _cfg, _ctxmod, _svc = setup_env("exp_")
    from unimail.core.models import AccountDraft, MailFilter, NormalizedMail
    from unimail.ui.context import AppContext

    ctx = AppContext()
    ctx.bootstrap_new("pw-1234567890")
    acc = ctx.accounts.add(AccountDraft(platform="qq", email="exp@qq.com", password="c"))

    # 正文故意留一行以 `From ` 开头：这正是 mbox 解析器会误判为
    # 「下一封邮件开始」的陷阱行。
    ids = []
    for i, subject in enumerate(["第一封", "第二封 From 某人", "第三封"]):
        nm = NormalizedMail(uid=str(i + 1), subject=subject, from_addr="a@b.c",
                            body_text=f"body {i}\nFrom the start of a line\nend",
                            date=datetime.now(timezone.utc))
        ids.append(ctx.mails.mails.insert_mail(acc.id, "qq", nm))

    # 强制走本地重建：联网取原始报文的分支依赖真实 IMAP，
    # 在回归测试里既慢又不可复现。
    ctx.mails.sessions = None

    out = Path(tempfile.mkdtemp(prefix="exp_out_"))

    eml = ctx.mails.export_eml(ids[0], out / "a.eml")
    raw = eml.read_bytes()
    msg = message_from_bytes(raw)
    subject = str(make_header(decode_header(msg["Subject"] or "")))
    check("eml 主题经 RFC2047 编码后可还原", subject == "第一封", f"实际 {subject!r}")
    check("eml 是 RFC822（有 From/Date 头部）",
          bool(msg["From"]) and bool(msg["Date"]))
    payload = msg.get_payload(decode=True) or b""
    check("eml 正文可还原", b"body 0" in payload, f"实际 {payload[:80]!r}")
    check("重建件带 X-UniMail-Note 说明（不冒充原件）",
          "X-UniMail-Note" in msg)

    mbox, n = ctx.mails.export_mbox(ids, out / "a.mbox")
    body = mbox.read_bytes()
    check("mbox 导出全部邮件", n == 3, f"实际 {n}")
    seps = [ln for ln in body.split(b"\n") if ln.startswith(b"From a@b.c ")]
    check("mbox 每封以 From 分隔行开头", len(seps) == 3, f"实际 {len(seps)} 行")
    check("正文里以 From 开头的行被转义成 >From",
          b"\n>From the start of a line" in body)
    check("mboxo 转义没有把整封邮件写两遍",
          body.count(b"body 0") == 1, f"实际 {body.count(b'body 0')} 次")
    parsed = list(mailbox.mbox(str(mbox)))
    check("mbox 可被标准库按 mboxo 解析出 3 封", len(parsed) == 3,
          f"实际 {len(parsed)}")
    check("解析回来的主题正确",
          str(make_header(decode_header(parsed[0]["Subject"] or ""))) == "第一封")

    csv_path, rows = ctx.mails.export_csv(MailFilter(account_id=acc.id),
                                          out / "a.csv")
    text = csv_path.read_text("utf-8-sig")
    check("CSV 行数与邮件数一致", rows == 3)
    check("CSV 带 BOM（Excel 不乱码）", csv_path.read_bytes()[:3] == b"\xef\xbb\xbf")
    check("CSV 含主题列", "第一封" in text)
    header = next(iter(_csv.reader(text.splitlines())))
    check("CSV 首行是表头", header[0] == "时间" and "主题" in header, f"实际 {header}")
    # 整表按标准 CSV 解析一遍（而不是按行找字符串），这样字段里的
    # 逗号/引号有没有被正确转义才真的被验证到
    records = list(_csv.reader(text.splitlines()))
    check("CSV 每条记录列数与表头一致",
          all(len(r) == len(header) for r in records), f"实际 {[len(r) for r in records]}")
    subjects = [r[3] for r in records[1:]]
    check("CSV 主题列内容精确（未被逗号串列）",
          "第二封 From 某人" in subjects, f"实际 {subjects}")
    check("CSV 时间列非空", all(r[0] for r in records[1:]))
    check("CSV 是明文本（中文主题未被编码）",
          base64.b64encode("第一封".encode()).decode() not in text)
    ctx.db.close()


# ============================================================ 29. 界面偏好持久化
def test_ui_settings_roundtrip():
    _tmp, cfg, _ctxmod, _svc = setup_env("uiset_")
    from unimail.ui import settings as mod
    mod.SETTINGS_PATH = cfg.DB_PATH.parent / "ui.json"

    s = mod.UiSettings()
    s.theme_mode = "light"
    s.font_scale = 1.25
    s.view_mode = "thread"
    s.sync_server_flags = False
    s.device_unlock = True
    s.window_geometry = "abc="
    s.save()

    s2 = mod.UiSettings.load()
    check("往返保存与读取一致",
          (s2.theme_mode, s2.font_scale, s2.view_mode, s2.sync_server_flags,
           s2.device_unlock, s2.window_geometry)
          == ("light", 1.25, "thread", False, True, "abc="), f"实际 {s2}")

    # 越界值必须被拉回合法档位，否则会一路传进样式表
    s3 = mod.UiSettings(theme_mode="neon", font_scale=3.7, view_mode="grid")
    s3.sanitize()
    check("非法主题回落 system", s3.theme_mode == "system")
    check("非法字号回落 1.0", s3.font_scale == 1.0)
    check("非法视图回落 list", s3.view_mode == "list")

    # 未知字段（未来版本写入）应被忽略而不是报错
    mod.SETTINGS_PATH.write_text('{"theme_mode":"dark","unknown_key":1}', "utf-8")
    s4 = mod.UiSettings.load()
    check("未知字段被白名单过滤", s4.theme_mode == "dark")

    # 半截文件：启动时读不到就该回默认值，而不是崩
    mod.SETTINGS_PATH.write_text('{"theme_mode":', "utf-8")
    s5 = mod.UiSettings.load()
    check("损坏的设置文件回退默认值", s5 == mod.UiSettings())


# ============================================================ 30. 设备绑定免密解锁
def test_device_binding():
    """绑定只保存「被 OS 保护的密文」，且任何损坏都必须失败而不是错解。"""
    import base64

    from unimail.core import device_binding as dbmod
    from unimail.core.device_binding import DeviceBinding

    if sys.platform not in ("win32", "darwin"):
        print("  [skip] 当前平台不提供设备绑定后端")
        return

    home = Path(tempfile.mkdtemp(prefix="devb_"))
    binding = DeviceBinding(path=home / "device.key")
    if not binding.available():
        print("  [skip] 当前平台无可用设备绑定后端")
        return

    key = bytes(range(48))
    binding.bind(key, label="test")
    check("绑定后 is_bound 为真", binding.is_bound())
    check("绑定时间可读", binding.bound_at()[:4].isdigit())
    check("取回的主密钥一致", binding.recall() == key)
    meta = json.loads(binding.path.read_text("utf-8"))
    check("落盘的是密文而不是明文密钥",
          base64.b64encode(key).decode() not in binding.path.read_text("utf-8"))
    check("绑定文件不含明文业务字段", "password" not in meta)

    binding.unbind()
    check("解绑后 is_bound 为假", not binding.is_bound())
    check("解绑后取回为空", binding.recall() is None)

    # 一：整段密文被替换（同步盘截断、文件被覆盖）→ 直接失败
    binding.bind(key)
    broken = json.loads(binding.path.read_text("utf-8"))
    broken["blob"] = base64.b64encode(b"\x00" * 96).decode("ascii")
    binding.path.write_text(json.dumps(broken), encoding="utf-8")
    check("密文被整段替换后拒绝返回密钥", binding.recall() is None)
    check("失败原因被记录（供界面提示）", bool(binding.last_error))

    # 二：更隐蔽的一种——OS 解密封成功，但解出来的不是当初那把密钥。
    #     这正是「摘要校验」存在的理由：否则错误密钥会一路流到
    #     「数据库打不开」，比一句提示难排查得多。
    binding.bind(key)
    swapped = json.loads(binding.path.read_text("utf-8"))
    other = bytes(range(48, 96))
    if binding.backend == "dpapi":
        cipher = dbmod._dpapi_protect(other, dbmod._entropy(""))
        swapped["blob"] = base64.b64encode(cipher).decode("ascii")
    else:
        cipher = base64.b64encode(other).decode("ascii")
        binding._keychain_write(cipher)
        swapped["blob"] = cipher
    binding.path.write_text(json.dumps(swapped), encoding="utf-8")
    check("解出的密钥与摘要不符时拒绝返回", binding.recall() is None,
          f"实际 {binding.recall()!r}")

    # 三：摘要仍然完好时（未被动过）必须正常返回——否则就是「总是失败」
    binding.bind(key)
    check("完好文件仍然可用（不是一律失败）", binding.recall() == key)
    binding.unbind()


# ============================================================ 31. UI：令牌 / 模型 / 面板
def test_ui_layer():
    """UI 层的可测部分：令牌、模型增量、委托、面板交互、任务面板、锁屏。"""
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication(sys.argv[:1])

    from unimail.ui import theme as theme_mod
    from unimail.ui.theme import DARK, LIGHT, build_stylesheet, font_px, resolve_theme_mode

    check("主题解析：显式模式不受系统影响",
          resolve_theme_mode("dark") == "dark" and resolve_theme_mode("light") == "light")
    check("样式表由令牌生成且可重复",
          build_stylesheet(DARK) == build_stylesheet(DARK))
    check("浅色样式表使用浅色底", LIGHT.bg in build_stylesheet(LIGHT))
    check("深色样式表使用深色底", DARK.bg in build_stylesheet(DARK))
    check("两套样式表确实不同", build_stylesheet(DARK) != build_stylesheet(LIGHT))
    check("字号缩放改变字级", font_px("body", 1.25) > font_px("body", 1.0))
    check("遮罩不透明", "255" in DARK.overlay and "255" in LIGHT.overlay)

    from unimail.ui.icons import pixmap
    check("图标可渲染", not pixmap("mail", "#ffffff", 18).isNull())
    check("未知图标退化为占位而非崩溃", not pixmap("no-such-icon", "#fff").isNull())
    check("同名同色图标命中缓存", pixmap("mail", "#ffffff", 18)
          is pixmap("mail", "#ffffff", 18))

    from unimail.ui.mail_model import (
        MailTableModel,
        avatar_color,
        highlight_html,
        initials,
    )
    check("头像色稳定（同一发件人不变）",
          avatar_color("a@b.c") == avatar_color("a@b.c"))
    check("中文名取首字", initials("张三") == "张")
    check("西文名取缩写", initials("John Smith") == "JS")
    # 高亮必须先转义再插标签：主题里带 HTML 不能被渲染
    check("高亮不引入注入", "<b>" not in highlight_html("a<b>c", "b", "#fff"),
          highlight_html("a<b>c", "b", "#fff"))
    check("高亮命中所有出现位置",
          highlight_html("aa", "a", "#fff").count("background") == 2)

    # ---- 模型增量
    from unimail.core.models import MailSummary, ThreadSummary

    def mk(i, read=False, th=""):
        return MailSummary(
            id=f"id{i}", account_id="a", platform="qq", folder="INBOX", uid=str(i),
            subject=f"主题{i}", from_name=f"发件人{i}", from_addr=f"x{i}@q.com",
            date=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=i),
            is_read=read, thread_key=th)

    model = MailTableModel()
    model.set_mails([mk(i) for i in range(5)])
    check("初始 5 行", model.rowCount() == 5)
    check("增量插入不重置且置于顶部",
          model.insert_rows([mk(99)]) == 1 and model.id_at(0) == "id99")
    check("重复 id 不会插入两行", model.insert_rows([mk(99)]) == 0)
    check("批量删除行数正确", model.remove_ids(["id99", "id2"]) == 2
          and model.rowCount() == 4)
    check("排序保留选中", model.sort_by("sender") and model.rowCount() == 4)

    model.set_threads([ThreadSummary(latest=mk(1, th="T1"), total=3, unread=2)])
    check("会话视图折叠为一行", model.rowCount() == 1 and model.is_thread_head(0))
    check("展开插入成员行", model.set_thread_members(
        "T1", [mk(2, th="T1"), mk(3, th="T1")], 0) == 2 and model.rowCount() == 3)
    check("成员行缩进", model.meta_at(1).depth == 1)
    check("线程头记住展开态", model.is_thread_head(0) and model.meta_at(0).expanded)
    # 刷新（重新 set_threads）后展开态必须保留，否则同步一次就全部收起
    model.set_threads([ThreadSummary(latest=mk(1, th="T1"), total=3, unread=2)])
    check("展开状态跨刷新保留", model.is_expanded("T1"), "刷新后丢失了展开态")
    check("新表里仍能反查到线程头行号", model.row_of_thread("T1") == 0)
    check("重新摊开成员行", model.set_thread_members(
        "T1", [mk(2, th="T1"), mk(3, th="T1")], model.row_of_thread("T1")) == 2
        and model.rowCount() == 3)
    check("折叠移除成员行", model.collapse_thread("T1", 0) == 2
          and model.rowCount() == 1)
    check("折叠后展开态被清掉", not model.is_expanded("T1"))
    model.set_threads([ThreadSummary(latest=mk(1, th="T1"), total=3, unread=2)])
    check("折叠态同样跨刷新保留（不会被自动展开）",
          not model.is_expanded("T1") and model.meta_at(0).expanded is False)

    # ---- 面板：多选 / J-K / 会话展开
    from unimail.ui.inbox_panel import InboxPanel
    panel = InboxPanel()
    panel.apply_theme(theme_mod.DARK.to_dict())
    panel.set_mails([mk(i) for i in range(6)], keyword="主题", hit_count=6)
    check("列表模式装载 6 行", panel.model.row_count() == 6)
    panel.table.selectRow(1)
    panel.extend_selection(1)
    check("Shift+J 追加选中", sorted(panel.selected_ids()) == ["id1", "id2"],
          f"实际 {panel.selected_ids()}")
    panel.move_cursor(1)
    check("J 移动光标并单选该行（导航即重选，不是追加）",
          panel._current_row() == 3 and panel.selected_ids() == ["id3"],
          f"row={panel._current_row()} sel={panel.selected_ids()}")
    panel.select_all(True)
    check("全选", len(panel.selected_ids()) == 6)
    panel.select_all(False)
    check("取消选择后选中集为空",
          not panel.table.selectionModel().selectedRows())

    # 搜索高亮：命中数要如实反映，且主题里含 HTML 也不能被渲染
    panel.set_mails([mk(0)], keyword="主题", hit_count=1)
    check("高亮关键词被记进模型", panel.model.keyword == "主题")
    check("命中数写进工具栏",
          "1" in panel.toolbar.count.text() and "命中" in panel.toolbar.count.text(),
          f"实际 {panel.toolbar.count.text()!r}")

    # 会话视图：点线程头 → 发信号；主窗口回填成员后真正展开
    seen: list[tuple[str, int]] = []
    panel.thread_toggle_requested.connect(lambda k, r: seen.append((k, r)))
    panel.set_mails([mk(1, th="T1")], thread_mode=True,
                    threads=[ThreadSummary(latest=mk(1, th="T1"), total=3, unread=2)])
    check("会话视图装载线程头", panel.model.row_count() == 1)
    panel._toggle_thread_row(0)
    check("点会话头发展开请求", seen == [("T1", 0)], f"实际 {seen}")
    panel.toggle_thread("T1", 0, [mk(2, th="T1"), mk(3, th="T1")])
    check("回填成员后展开成 3 行", panel.model.row_count() == 3)
    check("面板能报出已展开的会话", panel.expanded_thread_keys() == {"T1"})
    check("面板能反查线程头行号", panel.row_of_thread("T1") == 0)
    panel.toggle_thread("T1", 0, [])
    check("再点一次折叠回 1 行", panel.model.row_count() == 1)

    # ---- 任务面板
    from unimail.ui.task_panel import TaskPanel
    tp = TaskPanel()
    tp.apply_theme(theme_mod.DARK.to_dict())
    check("无任务时隐藏", not tp.isVisible())
    tp.on_started("sync:a", "同步 a@b.c")
    check("任务开始后显示", tp.isVisible() and tp.row_count() == 1)
    tp.on_progress("sync:a", 3, 10)
    tp.on_finished("sync:a", True, "新增 3 封")
    check("完成后保留片刻供查看", tp.row_count() == 1 and tp.active_ids() == [])
    tp.on_started("sync:a", "同步 a@b.c")
    check("同一任务 id 归并为一行", tp.row_count() == 1)
    tp.clear_finished()
    check("清理已完成行", tp.row_count() == 1)

    # ---- 锁屏：必须真正盖住全部内容
    from unittest.mock import patch as _patch

    from unimail.core.models import AccountDraft, NormalizedMail
    from unimail.ui import main_window as mwmod, settings as setmod
    from unimail.ui.context import AppContext
    from unimail.ui.main_window import MainWindow
    setmod.SETTINGS_PATH = Path(tempfile.mkdtemp(prefix="lockcfg_")) / "ui.json"
    ctx = AppContext()
    ctx.bootstrap_new("pw-1234567890")
    acc = ctx.accounts.add(AccountDraft(platform="qq", email="lock@qq.com",
                                        password="c"))
    mid = ctx.mails.mails.insert_mail(
        acc.id, "qq",
        NormalizedMail(uid="1", subject="机密主题", from_addr="a@b.c",
                       body_text="机密正文内容", date=datetime.now(timezone.utc)))
    # 屏蔽窗口的启动定时任务：真实同步会开后台线程去连 IMAP，
    # 首启向导会弹模态框。这里只关心界面行为。
    real_sync = mwmod.MainWindow._initial_sync
    real_first = mwmod.MainWindow._maybe_first_run
    mwmod.MainWindow._initial_sync = lambda self: None
    mwmod.MainWindow._maybe_first_run = lambda self, auto=False: None
    win = MainWindow(ctx, setmod.UiSettings(theme_mode="dark"),
                     theme_mod.ThemeManager("dark"))
    win.resize(1000, 700)
    win.show()
    app.processEvents()
    win.reload_mails()
    win._on_mail_selected(mid)
    app.processEvents()
    check("详情面板已装载邮件",
          win.detail_panel.subject.text() == "机密主题",
          f"实际 {win.detail_panel.subject.text()!r}")
    win.lock("测试锁定")
    app.processEvents()
    check("遮罩可见", win.lock_overlay.isVisible())
    check("遮罩覆盖整个窗口", win.lock_overlay.geometry() == win.rect(),
          f"{win.lock_overlay.geometry()} vs {win.rect()}")
    check("点击命中遮罩（不会穿透到列表）",
          win.childAt(60, 300) is win.lock_overlay)
    check("锁定后窗口记住锁定态", win._locked)
    check("锁定时详情面板被清空（正文不留在控件里）",
          win.detail_panel.subject.text() == ""
          and "机密正文" not in win.detail_panel.body.toPlainText(),
          f"subject={win.detail_panel.subject.text()!r}")
    params, verifier, _ = ctx._read_security_meta()
    check("正确密码可通过校验", ctx.security.verify_password("pw-1234567890",
                                                            params, verifier))
    check("错误密码被拒绝", not ctx.security.verify_password("wrong-password",
                                                             params, verifier))

    # 错误密码：不能解锁，且要给出提示
    win.lock_overlay.password.setText("wrong-password")
    win.lock_overlay._try_unlock()
    app.processEvents()
    check("错误密码不解锁",
          win.lock_overlay.isVisible() and win._locked)
    check("错误密码有提示", win.lock_overlay.error.isVisible())

    # 正确密码：走真实解锁路径（信号 → 主窗口），遮罩必须自己收起来
    status: list[str] = []
    original_status = win.set_status
    win.set_status = lambda t: (status.append(t), original_status(t))
    win.lock_overlay.password.setText("pw-1234567890")
    win.lock_overlay._try_unlock()
    app.processEvents()
    check("解锁后遮罩隐藏", not win.lock_overlay.isVisible())
    check("解锁后锁定态复位", not win._locked)
    check("解锁后状态栏反馈", "已解锁" in status, f"实际 {status}")

    # 空闲超时自动锁定
    with _patch.object(mwmod, "AUTO_LOCK_SECONDS", 0):
        win._check_auto_lock()
    app.processEvents()
    check("空闲超时自动锁定",
          win._locked and win.lock_overlay.isVisible())
    # 走真实退出路径：停后台线程并摘掉装在应用 / 窗口上的全局事件
    # 过滤器——否则解释器退出阶段 Qt 的销毁顺序不确定，会回调一个
    # 已释放的过滤器对象（Linux + py3.10 实测会在断言全部通过后
    # 以 `munmap_chunk(): invalid pointer` 崩掉，退出码 134）。
    win.quit_app()
    app.processEvents()
    mwmod.MainWindow._initial_sync = real_sync
    mwmod.MainWindow._maybe_first_run = real_first


# ============================================================ 33. 服务端删除语义
class _ScriptedImap:
    """按脚本应答的假 IMAP 连接，用于验证**协议交互本身**。

    这里刻意不用 MagicMock：删除是不可逆操作，真正要验证的是「发了哪几条
    命令、顺序如何、有没有出现整文件夹 EXPUNGE」。MagicMock 会把任何调用
    都记下来并返回另一个 Mock，连返回值格式写错都发现不了。
    """

    def __init__(self, caps=("IMAP4REV1", "UIDPLUS"), list_data=()):
        self._caps = tuple(caps)
        self._list = list(list_data)
        self.commands: list[tuple] = []
        self.selected = None
        self.fail_on: set[str] = set()

    def capability(self):
        return ("OK", [" ".join(self._caps).encode()])

    def list(self, *args):
        return ("OK", list(self._list))

    def select(self, mailbox, readonly=False):
        self.selected = mailbox
        self.commands.append(("SELECT", mailbox, readonly))
        return ("OK", [b"1"])

    def uid(self, command, *args):
        self.commands.append(("UID", command, *args))
        if command in self.fail_on:
            return ("NO", [b"boom"])
        if command == "COPY":
            return ("OK", [b"[COPYUID 1 200 900]"])
        return ("OK", [b""])

    def close(self):
        pass

    def logout(self):
        pass

    def uid_calls(self):
        """只取 UID 命令，形如 [("COPY", ('200', '"Trash"')), ...]。"""
        return [(c[1], c[2:]) for c in self.commands if c[0] == "UID"]


def test_server_side_delete():
    """删除语义：默认只删本机副本；显式开启时才动用服务器，且必须可恢复。"""
    _tmp, _cfg, _ctxmod, svcmod = setup_env("srvdel_")
    from unimail.config import PLATFORMS
    from unimail.core.models import AccountDraft
    from unimail.platforms.base import (
        ImapAdapter,
        ImapError,
        encode_mailbox,
        parse_list_line,
        utf7_decode,
        utf7_encode,
    )
    from unimail.ui.context import AppContext

    # ---- 1. 文件夹名编解码（163 / QQ 的中文名是这条链路的必经环节）
    check("文件夹名编码后必为 ASCII",
          all(encode_mailbox(n).isascii()
              for n in ("已删除", "废件箱", "Sent Messages", "A&B", "INBOX")),
          f"实际 {encode_mailbox('已删除')!r}")
    check("中文名用修改版 UTF-7（+ 位移、, 代替 /）",
          encode_mailbox("已删除") == "+XfJSIJZk-", f"实际 {encode_mailbox('已删除')!r}")
    check("字面量 & 转义为 &-", encode_mailbox("A&B") == "A&-B",
          f"实际 {encode_mailbox('A&B')!r}")
    check("含 ] 的名字加引号（Gmail 的 [Gmail]/Trash）",
          encode_mailbox("[Gmail]/Trash") == '"[Gmail]/Trash"',
          f"实际 {encode_mailbox('[Gmail]/Trash')!r}")
    check("含空格的名字加引号（QQ 的 Deleted Messages）",
          encode_mailbox("Deleted Messages") == '"Deleted Messages"',
          f"实际 {encode_mailbox('Deleted Messages')!r}")
    check("UTF-7 往返一致（含 & 与 + 这类位移冲突字符）",
          all(utf7_decode(utf7_encode(s)) == s
              for s in ("已删除", "A&B", "a+b-c", "INBOX", "废件箱", "已发送")),
          f"实际 {utf7_decode(utf7_encode('a+b-c'))!r}")
    check("解不开的位移序列原样保留，不猜",
          utf7_decode("+不是合法base64-") == "+不是合法base64-",
          f"实际 {utf7_decode('+不是合法base64-')!r}")

    # ---- 2. LIST 响应解析
    flags, name = parse_list_line(r'(\HasNoChildren \Trash) "/" "Deleted Messages"')
    check("LIST 属性被解析出来",
          flags == frozenset({r"\HASNOCHILDREN", r"\TRASH"}), f"实际 {flags}")
    check("带引号的文件夹名被还原", name == "Deleted Messages", f"实际 {name!r}")
    check("NIL 分隔符兼容", parse_list_line(r"(\HasNoChildren) NIL INBOX")[1] == "INBOX")
    check("畸形行返回 None（交给宽松回退解析）", parse_list_line("garbage") is None)

    # ---- 3. 垃圾箱定位：优先 \Trash 属性，其次平台候选名
    adapter = ImapAdapter(PLATFORMS["qq"])
    trash_first = _ScriptedImap(list_data=[
        b'(\\HasNoChildren) "/" "INBOX"',
        b'(\\HasNoChildren \\Trash) "/" "Trash"',
    ])
    check("优先按 \\Trash 属性定位", adapter.find_trash_folder(trash_first) == "Trash")

    by_name = _ScriptedImap(list_data=[
        b'(\\HasNoChildren) "/" "INBOX"',
        b'(\\HasNoChildren) "/" "Deleted Messages"',
    ])
    check("服务器不宣告 \\Trash 时按平台候选名兜底",
          adapter.find_trash_folder(by_name) == "Deleted Messages",
          f"实际 {adapter.find_trash_folder(by_name)!r}")

    none_found = _ScriptedImap(list_data=[b'(\\HasNoChildren) "/" "INBOX"'])
    check("确实没有垃圾箱时返回 None", adapter.find_trash_folder(none_found) is None)

    noselect = _ScriptedImap(list_data=[b'(\\Noselect \\Trash) "/" "[Gmail]"'])
    check("跳过 \\Noselect 的占位文件夹", adapter.find_trash_folder(noselect) is None)

    # ---- 4. 协议序列必须是 COPY → STORE \Deleted → UID EXPUNGE
    scripted = _ScriptedImap(list_data=[
        b'(\\HasNoChildren \\Trash) "/" "Deleted Messages"'
    ])
    moved = adapter.move_to_trash(scripted, "200")
    check("返回实际使用的垃圾箱名", moved == "Deleted Messages", f"实际 {moved!r}")
    calls = scripted.uid_calls()
    check("协议顺序：COPY → STORE → EXPUNGE",
          [c[0] for c in calls] == ["COPY", "STORE", "EXPUNGE"], f"实际 {calls}")
    check("第一步先复制进垃圾箱（保证可恢复）",
          calls[0][1] == ("200", '"Deleted Messages"'), f"实际 {calls[0]}")
    check("只加 \\Deleted，不碰其它标志",
          calls[1][1][:2] == ("200", "+FLAGS.SILENT") and "\\Deleted" in calls[1][1][2],
          f"实际 {calls[1]}")
    check("用 UID EXPUNGE 精确删除单个 UID",
          calls[2][1] == ("200",), f"实际 {calls[2]}")
    check("全程未出现整文件夹 EXPUNGE",
          not any(c[0] == "EXPUNGE" for c in scripted.commands),
          f"实际 {scripted.commands}")
    check("以可写方式打开源文件夹（readonly=False）",
          ("SELECT", "INBOX", False) in scripted.commands, f"实际 {scripted.commands}")

    # ---- 5. 没有 UIDPLUS 必须拒绝，且一条删除命令都不能发
    no_uidplus = _ScriptedImap(caps=("IMAP4REV1",),
                               list_data=[b'(\\HasNoChildren \\Trash) "/" "Trash"'])
    try:
        adapter.move_to_trash(no_uidplus, "200")
        check("无 UIDPLUS 时拒绝执行", False, "竟然没有抛错")
    except ImapError as exc:
        check("无 UIDPLUS 时拒绝执行（并说明原因）",
              "UIDPLUS" in str(exc), f"实际 {exc}")
    check("拒绝时未发出任何命令", no_uidplus.commands == [], f"实际 {no_uidplus.commands}")

    # ---- 6. 找不到垃圾箱也必须拒绝：宁可报错，也不做不可恢复的删除
    no_trash = _ScriptedImap(list_data=[b'(\\HasNoChildren) "/" "INBOX"'])
    try:
        adapter.move_to_trash(no_trash, "200")
        check("找不到垃圾箱时拒绝执行", False, "竟然没有抛错")
    except ImapError as exc:
        check("找不到垃圾箱时拒绝执行", "垃圾箱" in str(exc), f"实际 {exc}")
    check("拒绝时未发出任何 UID 命令",
          not [c for c in no_trash.commands if c[0] == "UID"],
          f"实际 {no_trash.commands}")

    # ---- 7. 服务层：先服务器、后本地；服务器失败则本地原样保留
    from unimail.platforms.parser import parse_message

    RAW = (b"From: a@b.com\r\nSubject: x\r\n"
           b"Date: Mon, 15 Oct 2026 10:00:00 +0800\r\n\r\nbody\r\n")
    ctx = AppContext()
    ctx.bootstrap_new("pw1234567890")
    acc = ctx.accounts.add(AccountDraft(platform="qq", email="me@qq.com", password="code"))
    # 绕开保活会话池：这里要验证的是服务层的调用顺序，不是连接复用
    ctx.mails.sessions = None

    class _TrashAdapter:
        def __init__(self, ok=True):
            self.ok = ok
            self.calls: list[tuple] = []

        def connect(self, account, password):
            return _ScriptedImap()

        def disconnect(self, imap):
            pass

        def move_to_trash(self, imap, uid, folder="INBOX"):
            self.calls.append((str(uid), folder))
            if not self.ok:
                raise ImapError("模拟服务器拒绝删除")
            return "Deleted Messages"

    ok_mid = ctx.mails.mails.insert_mail(acc.id, "qq", parse_message(RAW, "200"))
    ok_adapter = _TrashAdapter(ok=True)
    with _fake_server(ok_adapter, svcmod):
        target = ctx.mails.delete(ok_mid, on_server=True)
    check("delete(on_server=True) 返回目标垃圾箱", target == "Deleted Messages",
          f"实际 {target!r}")
    check("服务器动作带上正确的 UID 与文件夹",
          ok_adapter.calls == [("200", "INBOX")], f"实际 {ok_adapter.calls}")
    check("服务器成功后才删本地副本", ctx.mails.get(ok_mid) is None)

    bad_mid = ctx.mails.mails.insert_mail(acc.id, "qq", parse_message(RAW, "201"))
    bad_adapter = _TrashAdapter(ok=False)
    try:
        with _fake_server(bad_adapter, svcmod):
            ctx.mails.delete(bad_mid, on_server=True)
        check("服务器失败时对外抛错", False, "竟然没有抛错")
    except ImapError:
        check("服务器失败时对外抛错", True)
    check("服务器失败时本地副本保持不变（杜绝「假删除」）",
          ctx.mails.get(bad_mid) is not None)

    # ---- 8. 批量：单封失败不拖垮整批，且失败项必须被逐条报出
    good_mid = ctx.mails.mails.insert_mail(acc.id, "qq", parse_message(RAW, "202"))
    bad_mid2 = ctx.mails.mails.insert_mail(acc.id, "qq", parse_message(RAW, "203"))

    class _PartialAdapter(_TrashAdapter):
        def move_to_trash(self, imap, uid, folder="INBOX"):
            self.calls.append((str(uid), folder))
            if str(uid) == "203":
                raise ImapError("模拟这一封删不掉")
            return "Trash"

    partial = _PartialAdapter()
    with _fake_server(partial, svcmod):
        result = ctx.mails.delete_many([good_mid, bad_mid2], on_server=True)
    check("批量：成功的那封被删除",
          result.removed == 1 and ctx.mails.get(good_mid) is None, f"实际 {result}")
    check("批量：失败的那封仍留在本地", ctx.mails.get(bad_mid2) is not None)
    check("批量：失败项被逐条记录（而不是只报一个数字）",
          len(result.failed) == 1 and result.failed[0][0] == bad_mid2,
          f"实际 {result.failed}")
    check("批量：removed_ids 只含成功项", result.removed_ids == [good_mid],
          f"实际 {result.removed_ids}")
    check("批量：尝试过两封", len(partial.calls) == 2, f"实际 {partial.calls}")

    # ---- 9. 默认路径：on_server=False 时绝不碰网络
    local_mid = ctx.mails.mails.insert_mail(acc.id, "qq", parse_message(RAW, "204"))
    never = _TrashAdapter()
    with _fake_server(never, svcmod):
        ret = ctx.mails.delete(local_mid)
    check("默认删除不触发任何服务器调用", never.calls == [], f"实际 {never.calls}")
    check("默认删除返回空串（表示未走服务器）", ret == "")
    check("默认删除确实移除了本地副本", ctx.mails.get(local_mid) is None)

    # ---- 10. 设置项的类型收敛（"false" 字符串不能被当成 True）
    from unimail.ui import settings as setmod
    s_false = setmod.UiSettings(delete_on_server="false")
    s_false.sanitize()
    check("字符串 \"false\" 不会被当成 True",
          s_false.delete_on_server is False, f"实际 {s_false.delete_on_server!r}")
    s_true = setmod.UiSettings(delete_on_server="yes")
    s_true.sanitize()
    check("字符串 \"yes\" 被识别为 True", s_true.delete_on_server is True)
    s_bad = setmod.UiSettings(delete_on_server="maybe")
    s_bad.sanitize()
    check("无法识别的值回落到安全默认（关）", s_bad.delete_on_server is False)
    check("服务器删除默认关闭", setmod.UiSettings().delete_on_server is False)


# ============================================================ 34. 代码签名参数
def test_build_signing_args():
    """打包脚本的签名参数拼装。

    为什么值得测：签名一旦漏掉或参数写错，产物是个**能跑但没签名**的 exe——
    本地双击完全正常，问题只在别人下载时才暴露成 SmartScreen 拦截。
    这类「本地看不出问题」的失败必须由测试兜住。
    """
    from unittest.mock import patch

    import build_exe as B

    calls: list[list[str]] = []

    class _Ok:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        return _Ok()

    tmp = Path(tempfile.mkdtemp(prefix="umsignargs_"))
    exe = tmp / "UniMail.exe"
    exe.write_bytes(b"MZ" + b"\0" * 64)

    with patch.object(B, "find_signtool", return_value=r"C:\fake\signtool.exe"), \
            patch.object(B.subprocess, "run", side_effect=fake_run), \
            patch.object(B, "signature_status", return_value="Valid"):
        # ---- 证书存储指纹（推荐路径：命令行里不出现密码）
        ok = B.sign_exe(exe, B.SignConfig(thumbprint="AB CD EF"))
        argv = calls[-1]
        check("指纹方式签名成功", ok is True)
        check("用 /sha1 指定证书（且去掉空格）",
              "/sha1" in argv and argv[argv.index("/sha1") + 1] == "ABCDEF", f"实际 {argv}")
        check("默认带时间戳（/tr + /td sha256）",
              "/tr" in argv and argv[argv.index("/td") + 1] == "sha256", f"实际 {argv}")
        check("文件摘要固定 sha256",
              "/fd" in argv and argv[argv.index("/fd") + 1] == "sha256", f"实际 {argv}")
        check("最后一项是被签的文件", argv[-1] == str(exe), f"实际 {argv[-1]!r}")

        # ---- PFX 路径 + 关闭时间戳
        calls.clear()
        ok2 = B.sign_exe(exe, B.SignConfig(pfx=tmp / "c.pfx", pfx_password="pw",
                                           timestamp=False))
        argv2 = calls[-1]
        check("PFX 方式签名成功", ok2 is True)
        check("用 /f 与 /p 传证书与密码",
              "/f" in argv2 and "/p" in argv2, f"实际 {argv2}")
        check("关闭时间戳时不出现 /tr", "/tr" not in argv2, f"实际 {argv2}")

        # ---- 没给证书时必须拒绝，而不是"签个空转"
        calls.clear()
        ok3 = B.sign_exe(exe, B.SignConfig())
        check("未提供证书时拒绝签名", ok3 is False)
        check("拒绝时根本不调用 signtool", calls == [], f"实际 {calls}")

    # ---- 校验结论异常时必须判失败，不能把未签名产物放过去
    class _Noop:
        returncode = 0
        stdout = ""
        stderr = ""

    with patch.object(B, "find_signtool", return_value="signtool"), \
            patch.object(B.subprocess, "run", return_value=_Noop()), \
            patch.object(B, "signature_status", return_value="NotSigned"):
        check("校验为 NotSigned 时判定失败",
              B.sign_exe(exe, B.SignConfig(thumbprint="X")) is False)

    # ---- 环境里没有 signtool 时给出可操作提示，而不是抛异常
    with patch.object(B, "find_signtool", return_value=None):
        check("缺少 signtool 时返回失败而非抛异常",
              B.sign_exe(exe, B.SignConfig(thumbprint="X")) is False)

    # ---- signtool 定位：按 SDK 版本号排序，取最新的一套
    check("SDK 版本号可比较（10.0.26100.0 > 10.0.10011.0）",
          B.sdk_version_key(r"C:\Kits\10\bin\10.0.26100.0\x64\signtool.exe")
          > B.sdk_version_key(r"C:\Kits\10\bin\10.0.10011.0\x64\signtool.exe"))


SUITES = [
    ("安全层", test_security),
    ("存储层", test_storage),
    ("【回归】改主密码后凭据可用性", test_change_password_regression),
    ("【回归】IMAP part 编号", test_imap_part_numbering),
    ("【回归】附件真实下载", test_attachment_download),
    ("数据库迁移与版本", test_migration),
    ("TLS 证书校验", test_tls_certificate_verification),
    ("【回归】同步游标与 UIDVALIDITY", test_sync_pagination_and_uidvalidity),
    ("侧车原子性与恢复包", test_sidecar_atomicity_and_recovery),
    ("旧版侧车与驱动不一致", test_legacy_sidecar_and_driver_mismatch),
    ("数据清理路径", test_reset_data_paths),
    ("数据库并发与加密模式", test_database_concurrency_and_mode),
    # ---- 第二批（v1.3.0）
    ("批量写入与列表投影", test_batch_write_and_projection),
    ("列表索引与查询计划", test_indexes_and_query_plan),
    ("HTML 白名单清洗", test_html_whitelist_sanitizer),
    ("BODYSTRUCTURE 附件元数据", test_bodystructure_attachment_meta),
    ("【回归】同步回填附件信息", test_sync_backfills_attachment_meta),
    ("附件落盘安全策略", test_attachment_safety_policy),
    ("孤儿附件清理", test_orphan_attachment_cleanup),
    ("KDF 算法与密码策略", test_kdf_algorithms_and_password_policy),
    ("KDF 渐进升级", test_kdf_upgrade_on_password_change),
    ("解锁退避持久化", test_unlock_guard_backoff),
    ("恶意 MIME 语料", test_hostile_mime_corpus),
    ("关键路径中断注入", test_interruption_injection),
    # ---- 第三批（v1.4.0）
    ("全文检索（FTS5 + CJK 切分）", test_fulltext_search),
    ("会话引用链与归并键", test_thread_grouping),
    # ---- 第四批（v1.4.0 – v1.6.0）
    ("事件总线带负载", test_event_bus_payloads),
    ("待回写标记队列", test_pending_flags_queue),
    ("导出 eml / mbox / CSV", test_export_formats),
    ("界面偏好持久化", test_ui_settings_roundtrip),
    ("设备绑定免密解锁", test_device_binding),
    ("UI：令牌 / 模型 / 面板 / 锁屏", test_ui_layer),
    # ---- 第五批（删除语义与服务端删除）
    ("删除语义与服务端删除", test_server_side_delete),
    ("代码签名参数拼装", test_build_signing_args),
]


def main() -> int:
    print("=" * 60)
    print("UniMail 回归测试套件")
    print("=" * 60)
    failed = 0
    for title, fn in SUITES:
        print(f"\n▸ {title}")
        try:
            fn()
        except AssertionError as exc:
            failed += 1
            print(f"  ✗ 该组失败：{exc}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            import traceback
            print(f"  ✗ 该组异常：{exc}")
            traceback.print_exc()

    total = len(TRUTH)
    passed = sum(1 for _, ok in TRUTH if ok)
    print("\n" + "=" * 60)
    print(f"断言通过 {passed}/{total}，失败组 {failed}")
    print("=" * 60)
    if failed:
        print("存在失败 ✗")
        code = 1
    else:
        print("全部通过 ✓")
        code = 0
    # 退出码保卫战：套件里建过 QApplication，收尾时 Qt 相关 DLL 在
    # ExitProcess 的 DLL_PROCESS_DETACH 阶段可能崩溃（0xC0000005），
    # 把已经确定的退出码覆盖掉（且表现随 console/管道环境漂移：
    # 同一台机器 git-bash 报 0、PowerShell 报 0xC0000005、CI 报 1）。
    # 所有断言已经跑完、输出已经落盘，清理毫无意义——Windows 上直接
    # TerminateProcess 自身：不执行 DLL 卸载通知，退出码原样送达父进程。
    sys.stdout.flush()
    sys.stderr.flush()
    if sys.platform == "win32":
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.TerminateProcess(kernel32.GetCurrentProcess(), code)
    os._exit(code)


if __name__ == "__main__":
    sys.exit(main())

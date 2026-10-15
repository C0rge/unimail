"""UniMail 回归测试套件。

覆盖：
    1. 安全层：密钥派生、加解密、错误密码拒绝
    2. 存储层：账号、邮件、附件、游标、级联删除
    3. 【回归】改主密码后凭据仍可解密（v1.0.0 严重 bug）
    4. 【回归】IMAP part 编号正确（v1.0.0 用 walk() 序号，取错附件）
    5. 【回归】附件下载返回真实字节流（v1.0.0 是占位文本）
    6. 数据库迁移：v1 → v3 自动补列
    7. TLS 证书校验（v1.2.0：修复 IMAP 不校验证书）
    8. 【回归】同步游标语义与 UIDVALIDITY 清理（v1.2.0：修复静默丢邮件）
    9. 侧车原子写 / 备份回退 / 恢复包（v1.2.0）
   10. 数据清理路径（--reset 覆盖真正的侧车文件名）
   11. 数据库并发三件套 + 加密模式 fail-closed（v1.2.0）

运行：python tests/smoke.py
"""
from __future__ import annotations

import json
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

    import unimail.ui.context as ctxmod
    import unimail.core.services as svcmod
    ctxmod.DB_PATH = cfg.DB_PATH
    svcmod.ATTACHMENT_DIR = cfg.ATTACHMENT_DIR
    return tmp, cfg, ctxmod, svcmod


# ============================================================ 1. 安全层
def test_security():
    from unimail.core.security import SecurityError, SecurityService

    sec = SecurityService()
    params = SecurityService.new_kdf_params()
    sec.setup("hunter2", params)
    verifier = SecurityService.make_verifier(sec._master_key)  # noqa: SLF001

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
        AccountRepository, AttachmentRepository, CursorRepository, Database, MailRepository,
    )

    sec = SecurityService()
    params = SecurityService.new_kdf_params()
    db = Database(tmp / "test.db", sec.setup("pw123456", params))

    accounts = AccountRepository(db)
    mails = MailRepository(db)
    cursors = CursorRepository(db)
    attaches = AttachmentRepository(db)

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
        ctx2.change_password("wrong-old", "another-123")
        check("错误旧密码被拒绝", False, "竟然改成功了")
    except SecurityError:
        check("错误旧密码被拒绝", True)

    check("失败后凭据未损坏",
          ctx2.accounts.reload_password(ctx2.accounts.get(a1.id)) == "SECRET-AAA")
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
    ctx.bootstrap_new("pw123456")
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

    with patch.object(svcmod, "get_adapter", return_value=fake):
        path = ctx.mails.download_attachment(atts[0].id)

    content = path.read_bytes()
    check("下载的是真实字节流", content == FAKE_PDF, f"实际 {content[:40]!r}")
    check("不再是占位内容", "占位".encode() not in content)

    call = fake.fetch_attachment.call_args[0]
    check("FETCH 使用正确 part 编号", call[2] == "2", f"实际 {call[2]!r}")
    check("FETCH 使用正确 UID", str(call[1]) == "200", f"实际 {call[1]!r}")

    fake.fetch_attachment.reset_mock()
    with patch.object(svcmod, "get_adapter", return_value=fake):
        path2 = ctx.mails.download_attachment(atts[0].id)
    check("二次下载命中缓存", fake.fetch_attachment.call_count == 0)
    check("两次返回同一路径", path2 == path)

    ctx.db.close()


# ============================================================ 6. 数据库迁移
def test_migration():
    """v1 库（无 part_index / uid_validity 列）应能自动迁移到 v3。"""
    import sqlite3
    tmp, cfg, ctxmod, _svc = setup_env("mig_")

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
    db = Database(cfg.DB_PATH, sec.setup("pw123456", params))

    cols = {r["name"] for r in db.query_all("PRAGMA table_info(attachments)")}
    check("迁移后新增 part_index 列", "part_index" in cols, f"实际列: {sorted(cols)}")
    mail_cols = {r["name"] for r in db.query_all("PRAGMA table_info(mails)")}
    check("迁移后新增 uid_validity 列", "uid_validity" in mail_cols,
          f"实际列: {sorted(mail_cols)}")
    check("历史行按游标回填 uid_validity",
          int(db.query_one("SELECT uid_validity FROM mails WHERE id = 'm1'")["uid_validity"]) == 77)
    check("db_version 升到 3", db.get_meta("db_version") == "3",
          f"实际 {db.get_meta('db_version')}")

    db.close()
    db2 = Database(cfg.DB_PATH, None)
    check("重复迁移幂等", "uid_validity" in
          {r["name"] for r in db2.query_all("PRAGMA table_info(mails)")})
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
        try:
            get_adapter("custom").connect(acct, "pw")
        except Exception:  # noqa: BLE001 - 只关心传参
            pass
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
        from unimail.core.models import NormalizedMail
        self.body_fetches.append(int(uid))
        return NormalizedMail(uid=str(uid), body_text=f"body {uid}",
                              body_html=f"<p>body {uid}</p>")


def _make_sync_ctx(prefix):
    _tmp, cfg, _ctxmod, _svc = setup_env(prefix)
    from unimail.core.models import AccountDraft
    from unimail.ui.context import AppContext

    ctx = AppContext()
    ctx.bootstrap_new("pw-123456")
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

    cfg, ctx, account = _make_sync_ctx("sync_")
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
    cfg2, ctx2, account2 = _make_sync_ctx("sync2_")
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
    ctx.bootstrap_new("pw-123456")
    check("首次建库后写入侧车", meta.exists())
    check("侧车记录数据库驱动",
          json.loads(meta.read_text("utf-8")).get("driver") == ctx.db.driver_name)
    check("侧车不含明文密码", "pw-123456" not in meta.read_text("utf-8"))
    ctx.db.close()

    ctx = AppContext()
    ctx.unlock("pw-123456")            # 第二次写入 → 产生 .bak
    check("旧侧车已备份为 .bak", bak.exists())
    check("写入后无 .tmp 残留", not tmpfile.exists())

    # 模拟写入过程中崩溃：主侧车半截 JSON
    meta.write_text('{"salt": "AA', "utf-8")
    ctx.db.close()
    ctx2 = AppContext()
    ctx2.is_first_run = False
    ctx2.unlock("pw-123456")
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
        ctx3.unlock("pw-123456")
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
    from unimail.storage import Database, DatabaseError, SQLCIPHER_AVAILABLE

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


def test_legacy_sidecar_and_driver_mismatch():
    """旧版侧车没有 driver 字段；记录与实际不符时也必须给出可读结论。"""
    tmp, cfg, _ctxmod, _svc = setup_env("legacy_")
    from unimail.core.security import SecurityError
    from unimail.storage import DatabaseError, SQLCIPHER_AVAILABLE
    from unimail.ui.context import AppContext

    ctx = AppContext()
    ctx.bootstrap_new("pw-123456")
    ctx.db.close()
    meta = cfg.DB_PATH.with_suffix(".meta.json")

    # 模拟 v1.1.0 的侧车：没有 driver 字段
    data = json.loads(meta.read_text("utf-8"))
    data.pop("driver", None)
    meta.write_text(json.dumps(data), "utf-8")

    ctx2 = AppContext()
    ctx2.is_first_run = False
    ctx2.unlock("pw-123456")
    expected = "sqlcipher" if SQLCIPHER_AVAILABLE else "sqlite3"
    check("旧侧车可自动探测出实际加密模式",
          ctx2.db.driver_name == expected, f"实际 {ctx2.db.driver_name}")
    check("探测结论已回写 sidecar（下次启动不再探测）",
          json.loads(meta.read_text("utf-8")).get("driver") == expected)
    check("解锁后库内 meta.driver 与 sidecar 一致",
          ctx2.db.registered_driver() == expected)
    ctx2.db.close()

    # sidecar 声称是加密库，但（本机）并未安装 SQLCipher → 必须是可读错误，而不是打不开
    data = json.loads(meta.read_text("utf-8"))
    data["driver"] = "sqlcipher"
    meta.write_text(json.dumps(data), "utf-8")
    ctx3 = AppContext()
    ctx3.is_first_run = False
    try:
        ctx3.unlock("pw-123456")
        check("驱动记录与库不符时不静默失败", False, "竟然解锁成功")
    except (DatabaseError, SecurityError) as exc:
        text = str(exc)
        check("驱动记录与库不符时给出可操作提示",
              "sqlcipher3" in text or "加密" in text, f"实际 {text[:120]}")


def main() -> int:
    print("=" * 60)
    print("UniMail 回归测试套件")
    print("=" * 60)
    suites = [
        ("安全层", test_security),
        ("存储层", test_storage),
        ("【回归】改主密码后凭据可用性", test_change_password_regression),
        ("【回归】IMAP part 编号", test_imap_part_numbering),
        ("【回归】附件真实下载", test_attachment_download),
        ("数据库迁移 v1→v3", test_migration),
        ("TLS 证书校验", test_tls_certificate_verification),
        ("【回归】同步游标与 UIDVALIDITY", test_sync_pagination_and_uidvalidity),
        ("侧车原子性与恢复包", test_sidecar_atomicity_and_recovery),
        ("旧版侧车与驱动不一致", test_legacy_sidecar_and_driver_mismatch),
        ("数据清理路径", test_reset_data_paths),
        ("数据库并发与加密模式", test_database_concurrency_and_mode),
    ]
    failed = 0
    for title, fn in suites:
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
        return 1
    print("全部通过 ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())

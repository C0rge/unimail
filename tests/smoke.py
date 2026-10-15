"""UniMail 回归测试套件。

覆盖：
    1. 安全层：密钥派生、加解密、错误密码拒绝
    2. 存储层：账号、邮件、附件、游标、级联删除
    3. 【回归】改主密码后凭据仍可解密（v1.0.0 严重 bug）
    4. 【回归】IMAP part 编号正确（v1.0.0 用 walk() 序号，取错附件）
    5. 【回归】附件下载返回真实字节流（v1.0.0 是占位文本）
    6. 数据库迁移：v1 → v2 自动补列

运行：python tests/smoke.py
"""
from __future__ import annotations

import sys
import tempfile
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
    """v1 库（无 part_index 列）应能自动迁移到 v2。"""
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
        INSERT INTO meta(key, value) VALUES('db_version', '1');
    """)
    conn.commit()
    conn.close()

    from unimail.core.security import SecurityService
    from unimail.storage import Database

    sec = SecurityService()
    params = SecurityService.new_kdf_params()
    db = Database(cfg.DB_PATH, sec.setup("pw123456", params))

    cols = {r["name"] for r in db.query_all("PRAGMA table_info(attachments)")}
    check("迁移后新增 part_index 列", "part_index" in cols, f"实际列: {sorted(cols)}")
    check("db_version 升到 2", db.get_meta("db_version") == "2",
          f"实际 {db.get_meta('db_version')}")

    db.close()
    db2 = Database(cfg.DB_PATH, None)
    check("重复迁移幂等", "part_index" in
          {r["name"] for r in db2.query_all("PRAGMA table_info(attachments)")})
    db2.close()


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
        ("数据库迁移 v1→v2", test_migration),
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

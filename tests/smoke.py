"""手动验证加密与存储层（不依赖 UI）。

运行：
    python -m tests.smoke
或：
    python tests/smoke.py
"""
from __future__ import annotations

import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from unimail.core.models import AccountDraft, AttachmentMeta, MailFilter, NormalizedMail
from unimail.core.security import SecurityError, SecurityService
from unimail.storage import (
    AccountRepository,
    AttachmentRepository,
    CursorRepository,
    Database,
    MailRepository,
)


def test_security() -> None:
    sec = SecurityService()
    params = SecurityService.new_kdf_params()
    sec.setup("hunter2", params)
    verifier = SecurityService.make_verifier(sec._master_key)  # noqa: SLF001

    ct = sec.encrypt_secret("my-imap-password")
    assert sec.decrypt_secret(ct) == "my-imap-password"
    print("[ok] 凭据加解密")

    sec.lock()
    assert not sec.is_unlocked

    sec2 = SecurityService()
    try:
        sec2.unlock("wrong-password", params, verifier)
        raise AssertionError("错误密码不应通过校验")
    except SecurityError:
        print("[ok] 错误主密码被正确拒绝")

    sec2.unlock("hunter2", params, verifier)
    print("[ok] 正确主密码解锁成功")


def test_storage() -> None:
    tmp = Path(tempfile.mkdtemp())
    db_path = tmp / "test.db"

    sec = SecurityService()
    params = SecurityService.new_kdf_params()
    db_key = sec.setup("pw123456", params)
    db = Database(db_path, db_key)

    accounts = AccountRepository(db)
    mails = MailRepository(db)
    cursors = CursorRepository(db)
    attaches = AttachmentRepository(db)

    acc = accounts.insert(AccountDraft(
        platform="qq", email="a@qq.com", password="x", display_name="测试",
    ))
    accounts.put_credential(acc.id, sec.encrypt_secret("authorization-code-16"))
    print(f"[ok] 账号写入（id={acc.id[:8]}…）")

    stored = accounts.get_credential(acc.id)
    assert sec.decrypt_secret(stored) == "authorization-code-16"
    print("[ok] 凭据密文存储与还原")

    now = datetime.now(timezone.utc)
    for i in range(5):
        mails.insert_mail(acc.id, "qq", NormalizedMail(
            uid=str(100 + i),
            subject=f"测试邮件 {i}",
            from_name="发件人",
            from_addr=f"sender{i}@example.com",
            to_addrs=["a@qq.com"],
            date=now - timedelta(hours=i),
            body_text=f"这是第 {i} 封测试邮件的正文内容。",
            preview=f"这是第 {i} 封测试邮件…",
            attachments=[AttachmentMeta("file.pdf", "application/pdf", 1024)] if i == 0 else [],
        ))
    # 重复插入应被忽略
    dup = mails.insert_mail(acc.id, "qq", NormalizedMail(uid="100", subject="dup"))
    assert dup is None
    print("[ok] 邮件写入 + UID 去重")

    found = mails.query(MailFilter(account_id=acc.id))
    assert len(found) == 5, f"期望 5 封，实际 {len(found)}"
    print(f"[ok] 查询返回 {len(found)} 封")

    kw = mails.query(MailFilter(keyword="第 3 封"))
    assert len(kw) == 1
    print("[ok] 关键词筛选生效")

    total, unread = mails.count_by_account()[acc.id]
    assert total == 5 and unread == 5
    mails.set_read(found[0].id, True)
    total, unread = mails.count_by_account()[acc.id]
    assert unread == 4
    print("[ok] 已读/未读计数")

    # 结果按 date DESC 排序，带附件的是最新一封（i=0）
    with_attach = next(m for m in found if m.has_attachments)
    atts = mails.attachments_of(with_attach.id)
    assert len(atts) == 1, f"期望 1 个附件，实际 {len(atts)}"
    attaches.set_stored_path(atts[0].id, str(tmp / "file.pdf"))
    assert attaches.get(atts[0].id).stored_path
    print("[ok] 附件元数据与落盘路径")

    cursors.upsert(acc.id, "INBOX", 104, 7)
    last_uid, validity = cursors.get(acc.id, "INBOX")
    assert last_uid == 104 and validity == 7
    print("[ok] 同步游标")

    accounts.delete(acc.id)
    assert mails.query(MailFilter(account_id=acc.id)) == []
    assert accounts.get(acc.id) is None
    print("[ok] 级联删除账号及其邮件")

    print(f"[i] 加密等级：{db.encryption_level}")
    db.close()


def main() -> int:
    print("=" * 56)
    print("UniMail 核心层冒烟测试")
    print("=" * 56)
    test_security()
    print("-" * 56)
    test_storage()
    print("=" * 56)
    print("全部通过 ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""演示数据注入：无需真实邮箱即可查看完整界面效果。

仅在 `python main.py --seed` 时调用。
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from .core.models import AccountDraft, AttachmentMeta, NormalizedMail

log = logging.getLogger(__name__)

# 演示模式固定主密码：仅在 --seed 时使用，真实使用请走登录对话框
DEMO_PASSWORD = "unimail-demo"

_DEMO_ACCOUNTS = [
    ("qq", "zhangsan@qq.com", "工作邮箱", "demo-qq-pass"),
    ("163", "zhangsan@163.com", "个人邮箱", "demo-163-pass"),
    ("gmail", "zhangsan.dev@gmail.com", "海外账号", "demo-gmail-pass"),
    ("outlook", "zhangsan@outlook.com", "公司邮箱", "demo-outlook-pass"),
]

_DEMO_MAILS = [
    # (platform, subject, from_name, from_addr, body_text, hours_ago, has_attach, read)
    ("qq", "【周报】Q4 项目进度同步与下周排期", "李经理", "limanager@company.com",
     "各位好：\n\n本周我们完成了统一收件箱的核心检索模块，"
     "增量同步的 UID 游标方案也已落地。\n\n下周重点：\n"
     "1. 完成多平台适配器的 Gmail OAuth2 接入\n"
     "2. 附件预览能力（PDF / 图片）\n"
     "3. 数据库迁移脚本与回滚方案\n\n"
     "如有阻塞请随时找我。\n\n李", 2, True, False),
    ("qq", "关于数据库加密方案的确认", "王工", "wang@company.com",
     "关于主密码派生，我建议用 PBKDF2-HMAC-SHA256 至少 60 万次迭代，"
     "盐值 16 字节随机。数据库层用 SQLCipher 做整库 AES-256，"
     "这样即使 db 文件被拷走也无法还原。\n\n请确认后我这边开始改。", 5, False, False),
    ("163", "您的账单已生成（2026 年 10 月）", "网易支付", "noreply@163.com",
     "尊敬的用户：\n\n您 2026 年 10 月的账单已生成，"
     "本期应还金额 ¥ 328.00，最后还款日为 10 月 25 日。\n\n"
     "请及时还款，以免影响信用记录。", 8, True, True),
    ("163", "验证码：836421", "网易云音乐", "noreply@music.163.com",
     "您的验证码是 836421，5 分钟内有效。请勿将验证码告知他人。", 11, False, True),
    ("gmail", "Your Google Account security alert", "Google", "no-reply@accounts.google.com",
     "A new sign-in on Windows was detected for your Google Account.\n\n"
     "If this was you, no action is needed. If not, secure your account now.", 20, False, False),
    ("gmail", "GitHub: [unimail] PR #42 merged", "GitHub", "notifications@github.com",
     "Your pull request \"feat: add incremental IMAP sync\" has been merged into main.\n\n"
     "3 files changed, 218 insertions(+), 12 deletions(-)", 26, False, False),
    ("outlook", "会议邀请：架构评审会（周一 10:00）", "张总监", "director@corp.com",
     "邀请你参加架构评审会。\n\n时间：周一 10:00 - 11:30\n"
     "地点：3F 会议室 / Teams 线上\n"
     "议题：多平台邮箱统一管理的加密存储与同步机制\n\n请提前 5 分钟到会。", 30, True, False),
    ("outlook", "劳动合同续签通知", "HR 部门", "hr@corp.com",
     "您好：\n\n您的劳动合同将于下月到期，请于本周五前到 HR 部门办理续签手续。\n"
     "需携带：身份证原件、原合同。", 48, True, True),
    ("qq", "发票已开具，请查收", "财务部", "finance@company.com",
     "您申请的差旅费发票已开具完成，电子发票见附件。\n合计金额：¥ 2,480.00", 54, True, True),
    ("gmail", "Weekly digest: 12 new repositories you might like", "GitHub Explore",
     "explore@github.com",
     "Here are this week's trending repositories in Python, TypeScript and Rust.", 72, False, True),
]


def seed_demo_data(ctx) -> None:
    """向空库注入演示账号与邮件。已有数据时跳过。"""
    assert ctx.accounts and ctx.mails
    if ctx.accounts.list():
        log.info("数据库已有账号，跳过演示数据注入")
        return

    account_map: dict[str, str] = {}
    for platform, email, name, pwd in _DEMO_ACCOUNTS:
        draft = AccountDraft(
            platform=platform, email=email, password=pwd,
            display_name=name, sync_interval=300,
        )
        account = ctx.accounts.add(draft)
        account_map[platform] = account.id
        ctx.accounts.set_status(account.id, "ok")

    now = datetime.now(timezone.utc)
    inserted = 0
    uid_counter: dict[str, int] = {}
    for (platform, subject, from_name, from_addr, body, hours, has_attach,
         is_read) in _DEMO_MAILS:
        account_id = account_map.get(platform)
        if not account_id:
            continue
        uid_counter[platform] = uid_counter.get(platform, 100) + 1
        attachments = []
        if has_attach:
            attachments = [
                AttachmentMeta("Q4-进度报告.pdf", "application/pdf", 384_512),
                AttachmentMeta("封面图.png", "image/png", 92_160,
                               content_id="cover@unimail"),
            ]
        html_body = "".join(f"<p>{line}</p>" for line in body.split("\n") if line.strip())
        mail = NormalizedMail(
            uid=str(uid_counter[platform]),
            folder="INBOX",
            message_id=f"<demo-{platform}-{uid_counter[platform]}@unimail>",
            subject=subject,
            from_name=from_name,
            from_addr=from_addr,
            to_addrs=[f"{platform}_owner@example.com"],
            date=now - timedelta(hours=hours),
            body_text=body,
            body_html=html_body,
            preview=body.replace("\n", " ")[:200],
            attachments=attachments,
            raw_size=len(body.encode("utf-8")) + 2048,
        )
        mail_id = ctx.mails.mails.insert_mail(account_id, platform, mail, uid_validity=1)
        if mail_id:
            inserted += 1
            if is_read:
                ctx.mails.mails.set_read(mail_id, True)
            # 写同步游标，避免 seed 后立刻触发全量拉取
            ctx.accounts.cursors.upsert(account_id, "INBOX",
                                        int(mail.uid), 1)

    for account_id in account_map.values():
        ctx.accounts.accounts.set_last_synced(account_id)

    log.info("已注入演示数据：%d 个账号，%d 封邮件", len(account_map), inserted)
    print(f"[演示模式] 已注入 {len(account_map)} 个账号、{inserted} 封邮件")
    print(f"[演示模式] 主密码为：{DEMO_PASSWORD}")

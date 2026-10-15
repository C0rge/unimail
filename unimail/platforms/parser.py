"""MIME 解析：把原始 RFC822 报文归一化成 NormalizedMail。

处理的坑：
    - 各类中文编码（GBK/GB2312/GB18030）头字段与正文
    - 多层 multipart / 内嵌资源 (content-id)
    - 附件文件名编码 (=?utf-8?B?...?=)
    - HTML 清洗（剥离脚本与远程跟踪像素）
"""
from __future__ import annotations

import email
import email.header
import email.utils
import re
from datetime import datetime, timezone
from email.message import Message

from ..core.models import AttachmentMeta, NormalizedMail

# 常见中文邮箱的错误编码标注
_ENCODING_FIXES = {
    "gb2312": "gb18030",
    "gbk": "gb18030",
    "ansi_x3.4-1968": "gb18030",
    "unknown-8bit": "utf-8",
    "x-unknown": "utf-8",
    "unicode-1-1-utf-7": "utf-8",
}

_SCRIPT_RE = re.compile(r"<(script|iframe|object|embed)[^>]*>.*?</\1>", re.I | re.S)
_STYLE_TAG_RE = re.compile(r"<style[^>]*>.*?</style>", re.I | re.S)
_ON_ATTR_RE = re.compile(r"\son\w+\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.I)
_REMOTE_IMG_RE = re.compile(r"<img[^>]*\ssrc\s*=\s*(\"|')?(https?:)?//[^>]*>", re.I)


def _fix_charset(charset: str | None) -> str:
    if not charset:
        return "utf-8"
    cs = charset.strip().lower()
    return _ENCODING_FIXES.get(cs, cs)


def decode_header_value(raw: str | None) -> str:
    """解码 =?utf-8?B?...?= 形式的邮件头。"""
    if not raw:
        return ""
    try:
        parts = email.header.decode_header(raw)
    except Exception:  # noqa: BLE001
        return str(raw)
    out: list[str] = []
    for content, charset in parts:
        if isinstance(content, bytes):
            cs = _fix_charset(charset)
            for attempt in (cs, "utf-8", "gb18030", "latin-1"):
                try:
                    out.append(content.decode(attempt, errors="strict"))
                    break
                except (UnicodeDecodeError, LookupError):
                    continue
            else:
                out.append(content.decode("utf-8", errors="replace"))
        else:
            out.append(content)
    return "".join(out).strip()


def parse_address(raw: str | None) -> tuple[str, str]:
    """返回 (显示名, 邮箱地址)。"""
    if not raw:
        return "", ""
    name, addr = email.utils.parseaddr(raw)
    return decode_header_value(name), (addr or "").strip()


def parse_address_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [a for _, a in email.utils.getaddresses([raw]) if a]


def parse_date(raw: str | None) -> datetime:
    if raw:
        try:
            dt = email.utils.parsedate_to_datetime(raw)
            if dt is not None:
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
        except (TypeError, ValueError, IndexError):
            pass
    return datetime.now(timezone.utc)


def decode_payload(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = _fix_charset(part.get_content_charset())
    for attempt in (charset, "utf-8", "gb18030", "latin-1"):
        try:
            return payload.decode(attempt, errors="strict")
        except (UnicodeDecodeError, LookupError):
            continue
    return payload.decode("utf-8", errors="replace")


def sanitize_html(html: str) -> str:
    """基础 HTML 清洗：去脚本 / 事件属性 / 远程图片（防跟踪像素）。"""
    if not html:
        return ""
    out = _SCRIPT_RE.sub("", html)
    out = _STYLE_TAG_RE.sub("", out)
    out = _ON_ATTR_RE.sub("", out)
    out = _REMOTE_IMG_RE.sub("<!-- 远程图片已屏蔽 -->", out)
    return out


def html_to_text(html: str) -> str:
    """极简 HTML → 纯文本，用于生成摘要。"""
    if not html:
        return ""
    text = re.sub(r"<(br|/p|/div|/tr)[^>]*>", "\n", html, flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
    text = (text.replace("&nbsp;", " ").replace("&amp;", "&")
                .replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"'))
    return re.sub(r"\n{3,}", "\n\n", re.sub(r"[ \t]{2,}", " ", text)).strip()


def make_preview(text: str, limit: int = 200) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def parse_message(raw_bytes: bytes, uid: str, folder: str = "INBOX") -> NormalizedMail:
    """把原始报文解析为 NormalizedMail。"""
    msg = email.message_from_bytes(raw_bytes)

    body_text = ""
    body_html = ""
    attachments: list[AttachmentMeta] = []

    if msg.is_multipart():
        for idx, part in enumerate(msg.walk()):
            ctype = part.get_content_type()
            disp = (part.get_content_disposition() or "").lower()
            filename = part.get_filename()

            if filename or disp == "attachment":
                attachments.append(AttachmentMeta(
                    filename=decode_header_value(filename) or f"attachment-{idx}",
                    content_type=ctype,
                    size=len(part.get_payload(decode=True) or b""),
                    content_id=(part.get("Content-ID") or "").strip("<>") or None,
                    part_index=str(idx),
                ))
                continue

            if ctype == "text/plain" and not body_text:
                body_text = decode_payload(part)
            elif ctype == "text/html" and not body_html:
                body_html = decode_payload(part)
    else:
        if msg.get_content_type() == "text/html":
            body_html = decode_payload(msg)
        else:
            body_text = decode_payload(msg)

    clean_html = sanitize_html(body_html)
    if not body_text:
        body_text = html_to_text(clean_html)

    subject = decode_header_value(msg.get("Subject")) or "(无主题)"
    from_name, from_addr = parse_address(msg.get("From"))

    return NormalizedMail(
        uid=str(uid),
        folder=folder,
        message_id=(msg.get("Message-ID") or "").strip(),
        subject=subject,
        from_name=from_name,
        from_addr=from_addr,
        to_addrs=parse_address_list(msg.get("To")),
        date=parse_date(msg.get("Date")),
        body_text=body_text,
        body_html=clean_html,
        preview=make_preview(body_text),
        attachments=attachments,
        raw_size=len(raw_bytes),
    )


def parse_headers_only(raw_bytes: bytes, uid: str, folder: str = "INBOX") -> NormalizedMail:
    """只解析邮件头（用于列表快速展示，正文留空待按需拉取）。"""
    msg = email.message_from_bytes(raw_bytes)
    subject = decode_header_value(msg.get("Subject")) or "(无主题)"
    from_name, from_addr = parse_address(msg.get("From"))
    attachments: list[AttachmentMeta] = []
    if msg.is_multipart():
        for idx, part in enumerate(msg.walk()):
            fn = part.get_filename()
            if fn:
                attachments.append(AttachmentMeta(
                    filename=decode_header_value(fn),
                    content_type=part.get_content_type(),
                    size=0,
                    part_index=str(idx),
                ))
    return NormalizedMail(
        uid=str(uid),
        folder=folder,
        message_id=(msg.get("Message-ID") or "").strip(),
        subject=subject,
        from_name=from_name,
        from_addr=from_addr,
        to_addrs=parse_address_list(msg.get("To")),
        date=parse_date(msg.get("Date")),
        preview="",
        attachments=attachments,
        raw_size=len(raw_bytes),
    )

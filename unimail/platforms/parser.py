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


def iter_imap_parts(msg: Message, prefix: str = ""):
    """按 RFC 3501 规则遍历 MIME，产出 (imap_part_number, part)。

    IMAP 的 part 编号规则：
        - 非 multipart 的最顶层单部分 → "1"
        - multipart 的各子部分 → 依次为 "1", "2", "3"…
        - 嵌套 multipart → 父编号.子编号，如 "2.1"
        - 内嵌 message/rfc822 → 追加 ".1"

    注意：这与 email 库的 msg.walk() 顺序编号**完全不同**，
    直接拿 walk() 的序号去 FETCH BODY[n] 会取到错误内容。
    """
    if msg.is_multipart():
        if msg.get_content_type() == "message/rfc822":
            # 内嵌邮件：其子部分从 .1 开始
            for sub in msg.get_payload():
                yield from iter_imap_parts(sub, f"{prefix}.1" if prefix else "1")
            return
        for i, part in enumerate(msg.get_payload(), start=1):
            sub_prefix = f"{prefix}.{i}" if prefix else str(i)
            yield from iter_imap_parts(part, sub_prefix)
    else:
        yield (prefix or "1"), msg


def _extract_attachments(msg: Message) -> list[AttachmentMeta]:
    """用 IMAP part 编号提取附件元数据。"""
    out: list[AttachmentMeta] = []
    for part_no, part in iter_imap_parts(msg):
        ctype = part.get_content_type()
        disp = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()

        if not (filename or disp == "attachment"):
            continue
        payload = part.get_payload(decode=True)
        size = len(payload) if payload else 0
        if size == 0 and part.get("Content-Transfer-Encoding") is None:
            # 未解码（如 base64 头缺失），用编码后长度估算
            raw = part.get_payload()
            size = len(raw) if isinstance(raw, str) else 0
        out.append(AttachmentMeta(
            filename=decode_header_value(filename) or f"attachment-{part_no}",
            content_type=ctype,
            size=size,
            content_id=(part.get("Content-ID") or "").strip("<>") or None,
            part_index=part_no,
        ))
    return out


def parse_message(raw_bytes: bytes, uid: str, folder: str = "INBOX") -> NormalizedMail:
    """把原始报文解析为 NormalizedMail。"""
    msg = email.message_from_bytes(raw_bytes)

    body_text = ""
    body_html = ""
    attachments = _extract_attachments(msg)

    if msg.is_multipart():
        for _part_no, part in iter_imap_parts(msg):
            ctype = part.get_content_type()
            disp = (part.get_content_disposition() or "").lower()
            if part.get_filename() or disp == "attachment":
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
        attachments=_extract_attachments(msg),
        raw_size=len(raw_bytes),
    )

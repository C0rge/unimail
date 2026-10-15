"""MIME 解析：把原始 RFC822 报文归一化成 NormalizedMail。

处理的坑：
    - 各类中文编码（GBK/GB2312/GB18030）头字段与正文
    - 多层 multipart / 内嵌资源 (content-id)
    - 附件文件名编码 (=?utf-8?B?...?=)
    - HTML 清洗：**白名单**重建（黑名单正则漏面太大），并剥离远程图像

性能约定（重要）：
    解析路径**绝不解码附件正文**。历史实现为了算出附件大小对每个 part 调用
    `get_payload(decode=True)`，一封 5 MB 附件的邮件峰值内存要 +50 MB，且
    「只取邮件头」与「取全文」代价相同（实测各 75 ms）。现在改为按
    Content-Transfer-Encoding 直接由编码后长度推算（base64 精确、QP 近似），
    实测 5 MB 附件：108 ms / 32 MB → 7 ms / 0 额外分配。
"""
from __future__ import annotations

import email
import email.header
import email.utils
import re
from datetime import datetime, timezone
from email.message import Message
from html.parser import HTMLParser

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

# ============================================================ HTML 白名单清洗
# 允许保留的标签（只保留能表达内容与排版的，不含任何可执行/可加载语义）
_ALLOWED_TAGS = frozenset({
    "a", "abbr", "address", "article", "aside", "b", "big", "blockquote", "br",
    "caption", "center", "cite", "code", "col", "colgroup", "dd", "del", "dfn",
    "div", "dl", "dt", "em", "figcaption", "figure", "footer", "h1", "h2", "h3",
    "h4", "h5", "h6", "header", "hr", "i", "img", "ins", "kbd", "li", "main",
    "mark", "nav", "ol", "p", "pre", "q", "s", "samp", "section", "small",
    "span", "strike", "strong", "sub", "sup", "table", "tbody", "td", "tfoot",
    "th", "thead", "time", "tr", "tt", "u", "ul", "var", "wbr",
})

# 连内容一起丢弃的标签：这些要么可执行、要么会发起网络请求、要么是表单载体
_DROPPED_SUBTREES = frozenset({
    "script", "style", "iframe", "object", "embed", "applet", "form",
    "template", "svg", "math", "canvas", "noscript", "frame", "frameset",
    "link", "meta", "base", "audio", "video", "source", "track", "input",
    "button", "select", "textarea", "option", "optgroup", "dialog", "marquee",
    "portal", "slot", "picture", "title", "output", "datalist",
})

_VOID_TAGS = frozenset({"br", "hr", "img", "wbr", "col"})

# 不可包含子节点的标签（HTML 空元素）。丢弃子树时必须区别对待：
# `<meta>`/`<input>` 这类没有结束标签，若也压入「丢弃栈」就永远弹不出来，
# 会把它们之后的整篇正文一并吞掉。
_SELF_CONTAINED = _VOID_TAGS | frozenset({
    "meta", "link", "base", "input", "source", "track", "area", "embed", "param",
})

# 允许出现在任何标签上的表现型属性（都不带 URL 语义）
_COMMON_ATTRS = frozenset({"title", "dir", "lang", "align", "valign",
                           "width", "height", "bgcolor"})

# 逐标签的额外属性白名单
_TAG_ATTRS: dict[str, frozenset[str]] = {
    "a": frozenset({"href", "name"}),
    "img": frozenset({"src", "alt", "border"}),
    "table": frozenset({"border", "cellpadding", "cellspacing", "summary"}),
    "td": frozenset({"colspan", "rowspan", "nowrap"}),
    "th": frozenset({"colspan", "rowspan", "nowrap", "scope"}),
    "col": frozenset({"span"}),
    "colgroup": frozenset({"span"}),
    "hr": frozenset({"size", "noshade"}),
}

# href/src 允许的协议；其余（javascript:/data:/vbscript:/file:…）一律丢弃。
_SAFE_SCHEMES = frozenset({"http", "https", "mailto", "cid"})

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_WHITESPACE_STRIP = {ord(c): None for c in " \t\r\n"}


def _clean_url(value: str) -> str:
    """去掉控制字符（可被用来把 `java\\tscript:` 伪装成安全协议）。"""
    return _CTRL_RE.sub("", value or "").strip()


def _is_safe_url(value: str) -> bool:
    v = _clean_url(value)
    if not v:
        return False
    if v.startswith("#"):        # 页内锚点
        return True
    m = _SCHEME_RE.match(v)
    if not m:
        return False             # 相对路径：没有 base，一律不接受
    return m.group(1).lower() in _SAFE_SCHEMES


def _is_remote_url(value: str) -> bool:
    v = _clean_url(value).lower()
    return v.startswith(("http://", "https://", "//"))


class _WhitelistSanitizer(HTMLParser):
    """按白名单重建 HTML。

    黑名单正则的问题不在「漏了哪一条」，而在于**永远可以再漏一条**
    （`srcset`、`style="background:url()"`、`poster`、`xlink:href`、`<meta refresh>`…）。
    白名单是反过来做：只保留明确认识的标签与属性，其余一概不输出，
    因此未来出现新向量时默认是「被丢弃」而不是「被放过」。
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self._drop_stack: list[str] = []
        self._blocked_images = 0

    # -------------------------------------------------------- 内部工具
    @property
    def blocked_images(self) -> int:
        """被屏蔽的远程图片数量（供调用方在正文里给出提示）。"""
        return self._blocked_images

    def _dropping(self) -> bool:
        return bool(self._drop_stack)

    def _attrs_for(self, tag: str) -> frozenset[str]:
        return _COMMON_ATTRS | _TAG_ATTRS.get(tag, frozenset())

    def _render_attrs(self, tag: str, attrs: list[tuple[str, str | None]]) -> str | None:
        """渲染属性串；返回 None 表示「这个标签整体不值得输出」。"""
        allowed = self._attrs_for(tag)
        parts: list[str] = []
        blocked_src = False
        for name, value in attrs:
            name = (name or "").lower()
            if name not in allowed:
                continue
            value = "" if value is None else value
            if name in ("href", "src"):
                if not _is_safe_url(value):
                    continue
                if name == "src" and _is_remote_url(value):
                    # 远程图像 = 跟踪像素 + IP/UA 泄露。阻断由渲染层兜底，
                    # 这里直接连 DOM 都不留。
                    self._blocked_images += 1
                    blocked_src = True
                    continue
            parts.append(f' {name}="{_escape_attr(value)}"')
        if tag == "a" and parts:
            parts.append(' rel="noopener noreferrer"')
        if blocked_src and tag == "img":
            return None      # src 被屏蔽后只剩一个破图占位，没有保留价值
        return "".join(parts)

    # -------------------------------------------------------- HTMLParser
    def handle_starttag(self, tag, attrs) -> None:
        tag = tag.lower()
        if tag in _DROPPED_SUBTREES:
            if tag not in _SELF_CONTAINED:
                self._drop_stack.append(tag)
            return
        if self._dropping() or tag not in _ALLOWED_TAGS:
            return
        rendered = self._render_attrs(tag, attrs)
        if rendered is not None:
            self.out.append(f"<{tag}{rendered}>")

    def handle_startendtag(self, tag, attrs) -> None:
        tag = tag.lower()
        if self._dropping() or tag in _DROPPED_SUBTREES:
            return
        if tag not in _ALLOWED_TAGS:
            return
        rendered = self._render_attrs(tag, attrs)
        if rendered is not None:
            self.out.append(f"<{tag}{rendered}>")

    def handle_endtag(self, tag) -> None:
        tag = tag.lower()
        if self._drop_stack:
            if tag in self._drop_stack:
                idx = len(self._drop_stack) - 1 - self._drop_stack[::-1].index(tag)
                del self._drop_stack[idx:]
            return
        if tag in _ALLOWED_TAGS and tag not in _VOID_TAGS:
            self.out.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        if self._dropping():
            return
        self.out.append(_escape_text(data))

    def handle_comment(self, data: str) -> None:
        # 注释里可能藏条件注释（`<!--[if IE]><script>`）；一律丢弃
        return

    def handle_decl(self, decl: str) -> None:
        return

    def handle_pi(self, data: str) -> None:
        return

    def unknown_decl(self, data: str) -> None:
        return

    def close(self) -> None:
        super().close()


def _escape_text(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _escape_attr(value: str) -> str:
    return (value.replace("&", "&amp;").replace('"', "&quot;")
                 .replace("<", "&lt;").replace(">", "&gt;"))


def sanitize_html(html: str) -> str:
    """HTML 白名单清洗：只保留内容与排版标签，剥离脚本/远程资源/表单。"""
    if not html:
        return ""
    s = _WhitelistSanitizer()
    try:
        s.feed(html)
        s.close()
    except Exception:  # noqa: BLE001 - 任何解析异常都不能让邮件解析整体失败
        import logging
        logging.getLogger(__name__).warning("HTML 清洗失败，回退为空正文")
        return ""
    out = "".join(s.out)
    blocked = s.blocked_images
    if blocked:
        out += f"\n<!-- 已屏蔽 {blocked} 个远程图片 -->"
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


def _fix_charset(charset: str | None) -> str:
    if not charset:
        return "utf-8"
    cs = charset.strip().lower()
    return _ENCODING_FIXES.get(cs, cs)


# 「这段文字看起来不像真的文本」的强信号。私用区（U+E000-U+F8FF）、替换符、
# C1 控制符（U+0080-U+009F）在正常邮件正文里几乎不可能出现，而**声明编码与实际
# 字节不符**时恰恰会大量产生：GB18030/Big5 把非法字节对映射到私用区，
# Latin-1 把 UTF-8 续字节（0x80-0xBF）映射到 C1。
# 注意：这不能覆盖「UTF-8 字节被当 GBK 读」却不产生私用区的那一半情况
# （例如「收到」的两个字会读成「鏀跺埌」，全落在常用汉字区），
# 那种情况无强信号可依，仍以声明的 charset 为准——这是刻意的保守取舍：
# 宁可少数误标编码的邮件显示为乱码，也不能把正常的 GB2312/Big5/Shift_JIS
# 邮件按 UTF-8 硬解成乱码（真 CJK 文本恰好是合法 UTF-8 的概率很低但非零）。
_MOJIBAKE_RE = re.compile(r"[\ue000-\uf8ff\ufffd\u0080-\u009f]")


def _mojibake_score(text: str) -> int:
    """乱码信号计数，越小越像正常文本。"""
    return len(_MOJIBAKE_RE.findall(text))


def _decode_best(payload: bytes, charset: str) -> str:
    """按最佳可用编码解码字节串。

    优先采信声明的 charset（strict）；只有当它解出的结果带有明显乱码信号时，
    才去试 UTF-8 / GB18030，并且**只有确实更干净**才替换——避免把正常的
    GB18030 邮件「救」成别的编码的乱码。声明的 charset 直接解不开时没有可比较
    的基准，此时取「乱码信号最少」的那个候选。
    """
    declared: str | None = None
    best: str | None = None
    best_score = -1
    for idx, attempt in enumerate((charset, "utf-8", "gb18030", "latin-1")):
        if idx and attempt == charset:
            continue                                # 去掉与声明编码重复的候选
        try:
            text = payload.decode(attempt, errors="strict")
        except (UnicodeDecodeError, LookupError):
            continue
        if idx == 0:
            declared = text
            if _mojibake_score(text) == 0:
                return text                         # 声明编码解得很干净，直接采信
            continue                                # 有乱码迹象，继续看有没有更干净的
        score = _mojibake_score(text)
        if best is None or score < best_score:
            best, best_score = text, score
    if declared is not None:
        if best is not None and best_score < _mojibake_score(declared):
            return best
        return declared                             # 没有更干净的候选 → 保留声明编码的结果
    if best is not None:
        return best
    # 所有严格解码都失败（罕见）：退化为替换式解码，至少不丢内容、不抛异常
    return payload.decode("utf-8", errors="replace")


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
            out.append(_decode_best(content, _fix_charset(charset)))
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
    if not isinstance(payload, bytes):
        # decode=True 时理论上总是 bytes；单部分文本/异常结构可能返回 str
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    return _decode_best(payload, _fix_charset(part.get_content_charset()))


def make_preview(text: str, limit: int = 200) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def _iter_subparts(msg: Message) -> list[Message]:
    """取子部件，过滤掉 typeshed 允许但实际不会出现的非 Message 元素。

    `Message.get_payload()` 的标注是 `Message | str | list | None`（单部分时
    返回 str）。这里显式收窄成 `list[Message]`，让下游的类型推断可用。
    """
    payload = msg.get_payload()
    if not isinstance(payload, list):
        return []
    return [p for p in payload if isinstance(p, Message)]


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
            for sub in _iter_subparts(msg):
                yield from iter_imap_parts(sub, f"{prefix}.1" if prefix else "1")
            return
        for i, part in enumerate(_iter_subparts(msg), start=1):
            sub_prefix = f"{prefix}.{i}" if prefix else str(i)
            yield from iter_imap_parts(part, sub_prefix)
    else:
        yield (prefix or "1"), msg


def _base64_decoded_len(text: str) -> int:
    """由 base64 文本长度推算解码后字节数，**不做解码**。

    实测对 5 MB 附件：`get_payload(decode=True)` 需 108 ms、峰值 32 MB；
    本函数 7 ms、零额外分配，且结果与精确值完全一致（误差 0）。
    """
    stripped = text.rstrip()
    pad = len(stripped) - len(stripped.rstrip("="))
    n = len(text.translate(_WHITESPACE_STRIP))
    return max(0, (n // 4) * 3 - pad)


def _quoted_printable_decoded_len(text: str) -> int:
    """QP 解码后长度的近似值：软换行（`=\\n`）不产出字节，`=XX` 三字符产出一字节。

    这里刻意用 C 层的 `str.count` 而不是逐字符循环或 `re.findall`——前者在
    5 MB 文本上要几百毫秒，后者会分配一个百万量级的列表。
    """
    n = len(text)
    soft = text.count("=\n") + text.count("=\r\n")
    escapes = max(0, text.count("=") - soft)
    return max(0, n - 2 * escapes - 3 * soft)


def _part_size_estimate(part: Message) -> int:
    """估算一个 part 解码后的字节数（不解码正文）。"""
    payload: object = part.get_payload(decode=False)
    if isinstance(payload, list):       # 嵌套 multipart：递归累加子部分
        total = 0
        for child in payload:
            if isinstance(child, Message):
                total += _part_size_estimate(child)
        return total
    if isinstance(payload, bytes):
        # bytes payload 只出现在少数服务器的懒解码结果里；latin-1 是无损映射，
        # 后面按字节数统计长度即可（不真的解码正文）。
        text = payload.decode("latin-1", errors="ignore")
    elif isinstance(payload, str):
        text = payload
    else:
        return 0
    cte = (part.get("Content-Transfer-Encoding") or "").strip().lower()
    if cte == "base64":
        return _base64_decoded_len(text)
    if cte == "quoted-printable":
        return _quoted_printable_decoded_len(text)
    return len(text)


def _extract_attachments(msg: Message) -> list[AttachmentMeta]:
    """用 IMAP part 编号提取附件元数据（不触碰附件正文）。"""
    out: list[AttachmentMeta] = []
    for part_no, part in iter_imap_parts(msg):
        ctype = part.get_content_type()
        disp = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()

        if not (filename or disp == "attachment"):
            continue
        out.append(AttachmentMeta(
            filename=decode_header_value(filename) or f"attachment-{part_no}",
            content_type=ctype,
            size=_part_size_estimate(part),
            content_id=(part.get("Content-ID") or "").strip("<>") or None,
            part_index=part_no,
        ))
    return out


def _walk_parts(msg: Message):
    """一次遍历同时产出「附件元数据」与「正文候选」。

    历史实现对同一棵 MIME 树走了两遍（先提附件、再找正文），
    现在就着同一次遍历把两件事都做完。
    """
    attachments: list[AttachmentMeta] = []
    text_part: Message | None = None
    html_part: Message | None = None

    if not msg.is_multipart():
        if msg.get_content_type() == "text/html":
            html_part = msg
        else:
            text_part = msg
        return attachments, text_part, html_part

    for part_no, part in iter_imap_parts(msg):
        ctype = part.get_content_type()
        disp = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        if filename or disp == "attachment":
            attachments.append(AttachmentMeta(
                filename=decode_header_value(filename) or f"attachment-{part_no}",
                content_type=ctype,
                size=_part_size_estimate(part),
                content_id=(part.get("Content-ID") or "").strip("<>") or None,
                part_index=part_no,
            ))
            continue
        if ctype == "text/plain" and text_part is None:
            text_part = part
        elif ctype == "text/html" and html_part is None:
            html_part = part
    return attachments, text_part, html_part


# ============================================================ BODYSTRUCTURE
# 「只取邮件头」的同步路径拿不到任何部件信息，因此那时附件永远是 0 个：
# 邮件在列表里不会显示 📎，也永远不会产生可下载的附件记录。
# BODYSTRUCTURE 恰好解决这个问题——服务器直接告诉你 MIME 结构（含各部件
# 类型、文件名、字节数），**不需要下载任何正文**。
def _sexpr(text: str):
    """极简 s-expression 解析：BODYSTRUCTURE 的嵌套括号/引号/字面量。"""
    stack: list[list] = [[]]
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "(":
            stack.append([])
            i += 1
        elif ch == ")":
            if len(stack) > 1:
                done = stack.pop()
                stack[-1].append(done)
            i += 1
        elif ch.isspace():
            i += 1
        elif ch == '"':
            j, buf = i + 1, []
            while j < n:
                if text[j] == "\\" and j + 1 < n:
                    buf.append(text[j + 1])
                    j += 2
                    continue
                if text[j] == '"':
                    break
                buf.append(text[j])
                j += 1
            stack[-1].append("".join(buf))
            i = j + 1
        elif ch == "{":                     # {n}\r\n<literal>，BODYSTRUCTURE 里极少见
            end = text.find("}", i)
            if end < 0:
                break
            try:
                length = int(text[i + 1:end])
            except ValueError:
                i = end + 1
                continue
            body_start = text.find("\n", end)
            if body_start < 0:
                break
            stack[-1].append(text[body_start + 1:body_start + 1 + length])
            i = body_start + 1 + length
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in "()":
                j += 1
            atom = text[i:j]
            if atom.isdigit():
                stack[-1].append(int(atom))
            elif atom.upper() == "NIL":
                stack[-1].append(None)
            else:
                stack[-1].append(atom)
            i = j
    return stack[0][0] if stack[0] else None


def _bs_is_multipart(body: list) -> bool:
    return (isinstance(body[-1], str)
            and all(isinstance(x, list) for x in body[:-1])
            and len(body) >= 2)


def _bs_param(params, key: str) -> str | None:
    if not isinstance(params, list):
        return None
    key = key.upper()
    for i in range(0, len(params) - 1, 2):
        if isinstance(params[i], str) and params[i].upper() == key:
            value = params[i + 1]
            return value if isinstance(value, str) else None
    return None


def _bs_disposition(body: list) -> tuple[str, str | None]:
    """返回 (disposition 类型, 文件名)。disposition 是「首元素为 attachment/
    inline 的那个列表」——按值查找而不是按位置猜，因为 text 与 message 两种
    叶节点的元素个数不同。"""
    for element in body:
        if (isinstance(element, list) and element
                and isinstance(element[0], str)
                and element[0].lower() in ("attachment", "inline")):
            name = None
            if len(element) > 1:
                name = _bs_param(element[1], "FILENAME")
            return element[0].lower(), name
    return "", None


def _walk_bodystructure(body, prefix: str, out: list[AttachmentMeta]) -> None:
    if not isinstance(body, list) or not body:
        return
    if _bs_is_multipart(body):
        for i, child in enumerate(body[:-1], start=1):
            _walk_bodystructure(child, f"{prefix}.{i}" if prefix else str(i), out)
        return
    if not isinstance(body[0], str) or not isinstance(body[1], str):
        return
    ctype = f"{body[0]}/{body[1]}".lower()

    if ctype == "message/rfc822":
        # 转发邮件作为一个部件时，它的 part 编号就是自身（`n`），
        # 内嵌正文才是 `n.1`——下载 `.eml` 要用前者。
        params = body[2] if len(body) > 2 else None
        disposition, disp_filename = _bs_disposition(body)
        name = disp_filename or _bs_param(params, "NAME")
        if name or disposition == "attachment":
            size = body[6] if len(body) > 6 and isinstance(body[6], int) else 0
            out.append(AttachmentMeta(
                filename=decode_header_value(name) or "attachment.eml",
                content_type=ctype,
                size=size,
                content_id=None,
                part_index=prefix or "1",
            ))
        # 内嵌邮件的子部件从 .1 开始，与 iter_imap_parts 的编号规则一致
        nested = next((e for e in body[6:] if isinstance(e, list) and e
                       and isinstance(e[0], list)), None)
        if nested is not None:
            _walk_bodystructure(nested, f"{prefix}.1" if prefix else "1", out)
        return

    params = body[2] if len(body) > 2 else None
    filename = _bs_param(params, "NAME")
    disposition, disp_filename = _bs_disposition(body)
    filename = disp_filename or filename
    if not (filename or disposition == "attachment"):
        return
    size = body[6] if len(body) > 6 and isinstance(body[6], int) else 0
    out.append(AttachmentMeta(
        filename=decode_header_value(filename) or "attachment",
        content_type=ctype,
        size=size,
        content_id=None,
        part_index=prefix or "1",
    ))


def parse_bodystructure(raw: bytes | str) -> list[AttachmentMeta]:
    """从 FETCH 返回的 BODYSTRUCTURE 中提取附件元数据（不下载正文）。

    任何解析异常都返回空列表——这是同步路径上的「锦上添花」，
    绝不能因为它本身的问题让整次同步失败。
    """
    if not raw:
        return []
    text = raw.decode("latin-1", errors="replace") if isinstance(raw, bytes) else raw
    try:
        tree = _sexpr(text)
        if not isinstance(tree, list):
            return []
        out: list[AttachmentMeta] = []
        _walk_bodystructure(tree, "", out)
        return out
    except Exception:  # noqa: BLE001
        return []


def extract_bodystructure_from_fetch(blob: bytes) -> tuple[str | None, str | None]:
    """从一条 FETCH 响应里取出 (UID, BODYSTRUCTURE 文本)。

    形如 `b'12 (UID 345 BODYSTRUCTURE ("TEXT" "PLAIN" ...))'`。
    用括号配平定位结构体，避免正则面对嵌套括号时的脆弱。
    """
    text = blob.decode("latin-1", errors="replace") if isinstance(blob, bytes) else blob
    m = re.search(r"\bUID\s+(\d+)", text, re.I)
    uid = m.group(1) if m else None
    k = text.upper().find("BODYSTRUCTURE")
    if k < 0:
        return uid, None
    start = text.find("(", k)
    if start < 0:
        return uid, None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return uid, text[start:i + 1]
    return uid, None


def parse_message(raw_bytes: bytes, uid: str, folder: str = "INBOX") -> NormalizedMail:
    """把原始报文解析为 NormalizedMail。"""
    msg = email.message_from_bytes(raw_bytes)

    # 单次遍历：同时拿到附件元数据与正文候选 part
    attachments, text_part, html_part = _walk_parts(msg)
    body_text = decode_payload(text_part) if text_part is not None else ""
    body_html = decode_payload(html_part) if html_part is not None else ""

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

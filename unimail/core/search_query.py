"""搜索语法的解析：把用户输入拆成「结构化条件 + 自由关键词」。

为什么需要它
------------
竞品（Gmail、Foxmail、Mailspring）都支持 `from:` `subject:` `has:attachment`
这类前缀语法，UniMail 的搜索框目前只把它当成一个裸关键词丢给 FTS5。
加语法不是炫技——它是「几千封邮件里快速定位」的刚需：搜「from:boss 报销」
比「在几千封里肉眼找老板发的那封报销邮件」快一个数量级。

设计取舍
--------
只做**前缀语法**（`字段:值`），不做布尔运算（`AND/OR/NOT`）。理由：
1. 布尔运算在邮件场景的使用率远低于前缀筛选，而解析器复杂度陡增；
2. 用户输入里的 `AND`/`OR` 可能是邮件正文里的真实词，误判会让搜索结果
   莫名其妙地少；
3. 多个条件默认是「同时满足」（AND），符合直觉。

已知边界（刻意不做）
------------------
* 不解析引号分组：`subject:"会议 纪要"` 里的冒号后带引号，这里**不**做
  引号感知的 token 化——前缀值取「到下一个空白为止」，带空格的短语要么
  用多个词（AND 语义），要么走自由关键词。
* 不把前缀词当自由文本：`from:` 后面的值只用于精确/模糊匹配发件人，
  不会再喂给全文索引。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# 前缀 → MailFilter 的字段语义。值统一小写，解析时大小写不敏感。
# 每个前缀的「值如何匹配」在 apply_to() 里决定，这里只登记「认识哪些前缀」。
_PREFIX_ALIASES = {
    "from": "from",
    "发件人": "from",
    "to": "to",
    "收件人": "to",
    "subject": "subject",
    "主题": "subject",
    "has": "has",
    "is": "is",
    "in": "folder",
    "文件夹": "folder",
    "platform": "platform",
    "平台": "platform",
}

# `has:` / `is:` 接受的值（大小写不敏感）
_HAS_VALUES = {"attachment", "附件", "attachments"}
_IS_VALUES = {"unread", "未读", "read", "已读", "starred", "星标", "flagged"}


@dataclass
class ParsedQuery:
    """解析结果：结构化条件 + 剩余自由关键词。"""
    from_addr: str = ""            # from: 的值（模糊匹配 from_addr / from_name）
    to_addr: str = ""              # to: 的值
    subject: str = ""              # subject: 的值
    folder: str = ""               # in: 的值（文件夹名）
    platform: str = ""             # platform: 的值
    has_attachment: bool | None = None     # has:attachment / None=未指定
    unread_only: bool | None = None        # is:unread / is:read
    starred_only: bool | None = None       # is:starred
    keyword: str = ""              # 去掉前缀条件后剩余的自由文本
    errors: list[str] = field(default_factory=list)  # 无法识别的输入提示


# 前缀的正则：`字段:值`，字段与值之间允许无空格或一个空格。
# 值取「到下一个空白为止」。`(?i)` 大小写不敏感。
_PREFIX_RE = re.compile(r"(?i)\b([a-zA-Z\u4e00-\u9fff]+)\s*:\s*([^\s]+)")


def parse_query(raw: str) -> ParsedQuery:
    """把搜索输入解析成结构化条件 + 自由关键词。

    例：
        "from:boss 报销"        → from_addr="boss", keyword="报销"
        "has:attachment 会议"   → has_attachment=True, keyword="会议"
        "is:unread from:张三"   → unread_only=True, from_addr="张三"
        "in:已删除 报告"        → folder="已删除", keyword="报告"

    无法识别的前缀值（如 `has:xyz`）进 errors，供 UI 提示「不支持这个条件」，
    而不是静默丢弃——静默丢弃会让用户以为筛选生效了，实际什么都没过滤。
    """
    result = ParsedQuery()
    # 先摘出所有前缀 token，剩下的拼回自由文本。逐段扫描而不是正则全局替换，
    # 是为了把「无法识别的值」也摘出来，而不是把它误当自由关键词。
    consumed: list[tuple[int, int]] = []   # 已识别的前缀片段 (start, end)，用于从原文剔除
    for match in _PREFIX_RE.finditer(raw):
        # 只处理「词边界对齐」的匹配，避免把 `a:b` 里的 `a` 误当前缀
        # （例如正文里写 `http://x` 时，`http` 不是我们要的前缀）。
        key = match.group(1)
        value = match.group(2)
        normalized = _PREFIX_ALIASES.get(key.lower())
        if normalized is None:
            # 不认识的前缀：当成自由文本保留，不消费。
            continue
        _apply(result, normalized, value)
        consumed.append((match.start(), match.end()))

    # 剩余自由文本 = 原输入去掉所有已识别前缀片段后，空白归一。
    if consumed:
        rest = raw
        # 从后往前删，避免索引偏移
        for start, end in reversed(consumed):
            rest = rest[:start] + " " + rest[end:]
        result.keyword = " ".join(rest.split())
    else:
        result.keyword = " ".join(raw.split())
    return result


def _apply(result: ParsedQuery, field_name: str, value: str) -> None:
    v = value.strip().strip('"\'')       # 容忍手打的引号
    if field_name == "from":
        result.from_addr = v
    elif field_name == "to":
        result.to_addr = v
    elif field_name == "subject":
        result.subject = v
    elif field_name == "folder":
        result.folder = v
    elif field_name == "platform":
        result.platform = v
    elif field_name == "has":
        if v.lower() in _HAS_VALUES:
            result.has_attachment = True
        else:
            result.errors.append(f"不支持 has:{value}（可用：has:attachment）")
    elif field_name == "is":
        low = v.lower()
        if low in ("unread", "未读"):
            result.unread_only = True
        elif low in ("read", "已读"):
            result.unread_only = False
        elif low in ("starred", "星标", "flagged"):
            result.starred_only = True
        else:
            result.errors.append(f"不支持 is:{value}（可用：is:unread / is:read / is:starred）")


def has_structured(query: str) -> bool:
    """输入里是否含任何前缀语法（用于 UI 决定是否提示语法可用）。"""
    return any(m.group(1).lower() in _PREFIX_ALIASES
               for m in _PREFIX_RE.finditer(query))


__all__ = ["ParsedQuery", "has_structured", "parse_query"]

"""全文检索的文本归一化与 CJK 切分（SQLite FTS5 配套）。

为什么不能直接用 FTS5 自带的分词器
----------------------------------
`unicode61` 把连续的中文当作**一个词元**（`关于下周会议安排的通知` 是单个
token），于是任何子串查询都命中不了——实测搜「会议」命中 0。
`trigram` 按 3 字符滑窗，2 字中文查询（`会议`、`项目`）直接失效，
而 2 字词恰恰是中文搜索最常用的形态。两者都不可直接用。

方案
----
写入索引前把每个 CJK 字符**逐字切开**（用空格分隔），查询侧用同一套规则切分
后构造**短语查询**：`会议` → `"会 议"`。效果：

* 任意长度都能命中（含单字）；
* 短语查询要求字序相邻，搜「议会」不会误命中「会议」；
* 语义等价于原来的 `LIKE '%kw%'` 子串匹配，但可以走索引。

归一化用 NFKC：全角字母/数字折成半角（搜 `ABC` 能命中 `ＡＢＣ`），
全角标点折成半角后由 unicode61 自然地当作分隔符。

实测（2 万封、约 1% 命中；Windows / SQLCipher 3.50.4）
------------------------------------------------------
* 无命中查询 47.1 ms → 0.05 ms（无命中是最坏情况，也正是用户最常遇到的）
* 4 字中文查询 10.2×；2 字命中受 LIMIT 与回表 join 限制约 1.6×
* 写入 11832 → 6605 封/秒（切分回调 + 索引构建开销；仍远快于原先的 659 封/秒）
"""
from __future__ import annotations

import re
import unicodedata

# 需要逐字切分的字符范围。刻意包含日文假名与韩文谚文——它们同样不被
# unicode61 按字符切分，漏掉的话日韩正文的检索行为会和中文不一致。
_CJK_RANGES = (
    "\u3400-\u4dbf"    # CJK 扩展 A
    "\u4e00-\u9fff"    # CJK 基本区
    "\uf900-\ufaff"    # CJK 兼容表意文字
    "\u3040-\u30ff"    # 平假名 + 片假名
    "\uac00-\ud7af"    # 韩文谚文音节
)
_CJK_CHAR = re.compile(f"([{_CJK_RANGES}])")


def normalize(text: str) -> str:
    """NFKC 归一：全角字母数字折半角，全角标点折成 unicode61 认的分隔符。"""
    return unicodedata.normalize("NFKC", text or "")


def segment(text: str | None) -> str:
    """把每个 CJK 字符用空格包起来，交给 unicode61 逐字切分。

    这个函数同时注册进 SQLite 作为 `seg()`，供写入触发器调用——因此即使有
    代码绕过仓储直接写 `mails`（历史上 `worker` / `body_fetcher` 就有裸 SQL），
    全文索引也不会与内容表脱节。
    """
    if text is None:
        return ""
    return _CJK_CHAR.sub(r" \1 ", normalize(str(text)))


def match_query(raw: str) -> str:
    """把用户输入转成安全的 FTS5 MATCH 表达式。

    按空白分词，词内 CJK 逐字切开后**整体包进双引号**成短语，词间用 AND 连接::

        会议 纪要  ->  "会 议" AND "纪 要"
        API 文档   ->  "API" AND "文 档"

    所有输入都落在引号内，因此 FTS5 的语法字符（``"`` ``*`` ``OR`` ``NOT``
    ``NEAR`` ``(`` ``)`` ``:`` ``^``）一律失效——搜 ``" OR 1=1`` 只会得到一个
    匹配不到的短语，无法注入语法。

    返回空串表示「没有可检索的词元」（输入全为空白或标点），调用方应跳过 FTS。
    """
    parts: list[str] = []
    for word in normalize(raw).split():
        seg = " ".join(segment(word).split())
        if seg:
            parts.append('"' + seg.replace('"', '""') + '"')
    return " AND ".join(parts)


def query_terms(raw: str) -> list[str]:
    """返回用于**应用层高亮**的原词（已 NFKC 归一，未切分）。

    高亮刻意不交给 SQL 的 `snippet()`：它返回的是切分后文本
    （``会  议`` 之间带空格），直接塞进界面会破坏排版。这里给出原词，
    由界面层在原始正文里定位并加标记。
    """
    return [w for w in normalize(raw).split() if w]


def fts_eligible(raw: str) -> bool:
    """判断关键词是否适合走全文索引。

    unicode61 只把「字母数字与 CJK」收作词元，其余字符（``%`` ``_`` ``+`` ``.``
    ``@`` ``-`` ``()`` …）一律当分隔符丢弃。这对 FTS 本身没问题，但会让**搜索
    语义静默改变**：``a_b`` 会被索引/查询成「a 紧跟 b」，于是不含下划线的 ``ab``
    也被算作命中——而原先的 ``LIKE '%a_b%'`` 只匹配字面量。

    所以判据很保守：关键词里一旦出现标点或符号就回退 `LIKE`（慢一些，但语义与
    历史行为一致）。纯字母数字 / CJK / 空格的关键词才交给全文索引。

    `str.isalnum()` 对 CJK 汉字与假名同样返回 True，无需额外判断。
    """
    text = normalize(raw)
    if not text.strip():
        return False
    for ch in text:
        if ch.isspace() or ch.isalnum():
            continue
        return False
    return True

"""平台适配层包。"""
from .adapters import all_platforms, get_adapter
from .base import (
    Folder,
    ImapAdapter,
    ImapError,
    encode_mailbox,
    make_account_stub,
    parse_list_line,
    utf7_decode,
    utf7_encode,
)

__all__ = [
    "Folder",
    "ImapAdapter",
    "ImapError",
    "all_platforms",
    "encode_mailbox",
    "get_adapter",
    "make_account_stub",
    "parse_list_line",
    "utf7_decode",
    "utf7_encode",
]

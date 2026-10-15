"""平台适配层包。"""
from .adapters import all_platforms, get_adapter
from .base import Folder, ImapAdapter, ImapError, make_account_stub

__all__ = [
    "get_adapter",
    "all_platforms",
    "ImapAdapter",
    "ImapError",
    "Folder",
    "make_account_stub",
]

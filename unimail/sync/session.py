"""IMAP 会话池：每账号复用一条保活连接。

背景（v1.5.0，P8）
------------------
改造前每次操作都「TCP + TLS 握手 + LOGIN + LOGOUT」地新建连接：
查看一封邮件的附件、补拉一封正文、下载内嵌图片，各要一次完整握手。
实测一次握手往返 300–800 ms，绝大多数时间花在协议协商而不是取数据。
同一账号 20 个并发任务就是 20 条连接，很多邮箱还会因此触发「登录过于频繁」。

设计
----
* **每账号一条会话**（`ImapSession`），内部用可重入锁保证「同一时刻只有一个使用者」——
  IMAP 协议本身就是有状态的命令行协议，并发使用同一条连接必然串包。
* `borrow()` 是唯一的取用入口，返回上下文管理器：进入时探活（`NOOP`），
  退出时若本次调用抛异常则把连接标记为脏、关闭，下次自动重连。
* 空闲超过 `idle_timeout` 的会话由 `sweep()` 回收（调度器心跳顺带调用）。
* 总连接数以 `max_sessions` 为目标：需要新建会话且已达上限时，优先回收一个
  「不在使用」的最久未用会话。

为什么不用信号量做槽位控制（v1.6.1 修正）
-----------------------------------------
v1.5.0–v1.6.0 用 `BoundedSemaphore` 限制连接数，写法是：

    if not self._slots.acquire(blocking=False):
        self._evict_lru_locked()      # 若全部 in_use → 一个槽位都释放不出来
        self._slots.acquire()         # ← 阻塞，而此时**仍持有 self._lock**

槽位只在 `_evict_lru_locked` / `close_account` / `close_all` 三处释放，而这三处
都必须先拿到 `self._lock`。于是「8 个账号的会话同时在使用、第 9 个账号到来」会让
该线程永久阻塞在 `acquire()` 上，并连带把 `sweep()` / `close_account()` /
`close_all()` / `stats()` 全部堵死 —— 而 `Scheduler.tick` 是在**主线程**调用
`sweep()` 的，最终表现是界面永久冻结、进程关不掉。

现在改为**不做无界等待**：容量已满且存在空闲会话就回收它；若全都在用（这是
`Scheduler.tick` 一次派发所有到期账号时的正常情形），允许临时超额并记一条
WARNING，等这一批结束后在 `_release()` 里回落到上限。池锁**绝不跨越任何阻塞
调用**：所有 `close()`（内含 `LOGOUT` 网络往返）都挪到锁外执行。

为什么用 `NOOP` 探活：TCP 连接可能在服务器侧已经被单方面关闭（NAT 超时、
服务端 `IDLE` 超时），此时本地 socket 看起来仍是「已连接」，直到下一次读写
才发现。`NOOP` 是一次极轻量的往返，能在真正取数据前发现这点。
"""
from __future__ import annotations

import contextlib
import logging
import threading
import time
from collections.abc import Iterator
from typing import Any

from ..core.models import Account
from ..platforms import ImapError, get_adapter

log = logging.getLogger(__name__)

DEFAULT_MAX_SESSIONS = 8
DEFAULT_IDLE_TIMEOUT = 240.0     # 秒；超过则回收，避免长期占用服务器连接配额


class ImapSession:
    """一个账号的保活 IMAP 连接。"""

    def __init__(self, account: Account, password: str) -> None:
        self.account_id = account.id
        self.platform = account.platform
        self._account = account
        self._password = password
        self._adapter = get_adapter(account.platform)
        self._imap: Any = None
        self._lock = threading.RLock()
        self._dirty = False
        self.in_use = False
        self.last_used = time.monotonic()
        self.reconnects = 0

    # ------------------------------------------------------------ 连接
    def _connect(self):
        if self._imap is not None:
            self._drop()
        self._imap = self._adapter.connect(self._account, self._password)
        self._dirty = False
        self.reconnects += 1
        return self._imap

    def _probe(self) -> bool:
        """`NOOP` 探活。没有该方法的实现（测试替身）视为「仍然可用」。"""
        noop = getattr(self._imap, "noop", None)
        if noop is None:
            return True
        try:
            noop()
            return True
        except Exception:  # noqa: BLE001 - 任何异常都等价于「连接已不可用」
            return False

    def _drop(self) -> None:
        imap, self._imap = self._imap, None
        if imap is not None:
            # 断开失败不影响调用方：连接可能早就断了
            self._adapter.disconnect(imap)

    @property
    def alive(self) -> bool:
        return self._imap is not None

    @property
    def idle_seconds(self) -> float:
        return time.monotonic() - self.last_used

    # ------------------------------------------------------------ 取用
    @contextlib.contextmanager
    def borrow(self) -> Iterator:
        """独占取用连接。

        同一账号的并发任务会在这里排队（IMAP 是有状态协议，不能并发共用）。
        本次调用抛异常时把连接标记为脏，退出时关闭——协议状态可能已经错位，
        继续复用会得到难以诊断的怪结果。
        """
        with self._lock:
            imap = self._imap
            if imap is None or not self._probe():
                imap = self._connect()
            self.in_use = True
            try:
                yield imap
            except BaseException:
                self._dirty = True
                raise
            finally:
                self.in_use = False
                self.last_used = time.monotonic()
                if self._dirty:
                    self._drop()

    def close(self) -> None:
        with self._lock:
            self._drop()

    def interrupt(self) -> None:
        """从别的线程强行打断阻塞中的调用（用于取消/退出）。

        Python 无法把异常注入另一个线程的阻塞 socket 读，唯一可靠的办法是
        关掉底层 socket——读取会立刻以 `OSError` 返回。不做这一步，
        「退出时等待任务归还」会一直卡到 TCP 超时（最长 30 s）。
        """
        imap = self._imap
        if imap is None:
            return
        sock = getattr(imap, "sock", None)
        if sock is None:
            return
        import socket as _socket
        with contextlib.suppress(OSError, AttributeError):
            sock.shutdown(_socket.SHUT_RDWR)
        with contextlib.suppress(OSError, AttributeError):
            sock.close()


class SessionPool:
    """按账号管理保活会话，限制总连接数并回收空闲连接。

    不做网络 IO，因此可以在无网络环境（测试）里实例化；真正的连接发生在
    第一次 `borrow()` 时。
    """

    def __init__(self, max_sessions: int = DEFAULT_MAX_SESSIONS,
                 idle_timeout: float = DEFAULT_IDLE_TIMEOUT) -> None:
        self.max_sessions = max(1, int(max_sessions))
        self.idle_timeout = float(idle_timeout)
        self._sessions: dict[str, ImapSession] = {}
        self._lock = threading.Lock()
        self._borrows: dict[str, int] = {}
        # 临时超额的次数，仅供诊断（正常应为 0，或只在「一次派发很多账号」时短暂 > 0）
        self._over_capacity = 0

    # ------------------------------------------------------------ 内部
    def _get_or_create(self, account: Account, password: str) -> ImapSession:
        """取出（或新建）该账号的会话，并把「已借出」登记在锁内完成。

        登记借用的时机很关键：`ImapSession.borrow()` 要等到进入下一步才会把
        `in_use` 置真。若中间这段窗口被 `_detach_lru_locked()` 判定为「空闲」
        并回收，调用方手里就留下一条**不在 `_sessions` 里**的孤儿连接——
        永远不会被回收，连接数还会突破上限。所以这里在释放池锁之前就计入
        `_borrows`，让驱逐逻辑看得到它。
        """
        victim: ImapSession | None = None
        with self._lock:
            session = self._sessions.get(account.id)
            if session is None:
                if len(self._sessions) >= self.max_sessions:
                    victim = self._detach_lru_locked()
                    if victim is None:
                        # 全都在用：这是 Scheduler.tick 一次派发多个账号时的正常
                        # 情形。宁可临时超额，也绝不阻塞（阻塞会连带锁死主线程）。
                        self._over_capacity += 1
                        log.warning(
                            "IMAP 会话数已达上限 %d 且全部在用，临时超额建立账号 %s 的连接；"
                            "这一批结束后会自动回落",
                            self.max_sessions, account.id,
                        )
                session = ImapSession(account, password)
                self._sessions[account.id] = session
            self._borrows[account.id] = self._borrows.get(account.id, 0) + 1
        # close() 内含 LOGOUT 网络往返，必须在池锁之外执行
        if victim is not None:
            victim.close()
        return session

    def _detach_lru_locked(self, exclude: str | None = None) -> ImapSession | None:
        """摘除「不在使用」的最久未用会话并返回它（**不做 IO**，调用方在锁外关闭）。

        `exclude` 用于避免刚归还的会话被立刻回收——保留它才能实现保活复用。
        没有任何可回收对象时返回 None。
        """
        candidates = [
            (s.last_used, aid) for aid, s in self._sessions.items()
            if not s.in_use and aid not in self._borrows and aid != exclude
        ]
        if not candidates:
            return None
        _ts, account_id = min(candidates)
        return self._sessions.pop(account_id, None)

    def _release(self, account_id: str) -> None:
        """归还一次借用；若此前曾临时超额，顺手回落到上限。"""
        victim: ImapSession | None = None
        with self._lock:
            left = self._borrows.get(account_id, 1) - 1
            if left <= 0:
                self._borrows.pop(account_id, None)
            else:
                self._borrows[account_id] = left
            if len(self._sessions) > self.max_sessions:
                # 优先保留刚用过的会话（它最可能被立刻复用）
                victim = self._detach_lru_locked(exclude=account_id)
        if victim is not None:
            victim.close()

    # ------------------------------------------------------------ 对外
    @contextlib.contextmanager
    def borrow(self, account: Account, password: str) -> Iterator:
        session = self._get_or_create(account, password)
        try:
            with session.borrow() as imap:
                yield imap
        finally:
            self._release(account.id)

    def close_account(self, account_id: str) -> None:
        with self._lock:
            session = self._sessions.pop(account_id, None)
            self._borrows.pop(account_id, None)
        if session is None:
            return
        session.close()

    def interrupt_account(self, account_id: str) -> None:
        """打断该账号正在阻塞的调用（取消/退出用，不影响会话的存续）。"""
        with self._lock:
            session = self._sessions.get(account_id)
        if session is not None:
            session.interrupt()

    def sweep(self) -> int:
        """回收空闲超时的会话。返回回收数量。

        `aid not in self._borrows` 是必要的：`in_use` 要等到 `ImapSession.borrow()`
        内部才置真，两者之间存在一个「已借出但尚未标记在用」的窗口。
        """
        with self._lock:
            stale = [
                aid for aid, s in self._sessions.items()
                if not s.in_use and aid not in self._borrows
                and s.idle_seconds > self.idle_timeout
            ]
        for aid in stale:
            self.close_account(aid)
        return len(stale)

    def close_all(self) -> None:
        with self._lock:
            ids = list(self._sessions)
        for aid in ids:
            self.close_account(aid)

    def stats(self) -> dict[str, float | int]:
        with self._lock:
            return {
                "sessions": len(self._sessions),
                "max_sessions": self.max_sessions,
                "in_use": len(self._borrows),
                "over_capacity": self._over_capacity,
            }

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)


__all__ = ["DEFAULT_IDLE_TIMEOUT", "DEFAULT_MAX_SESSIONS", "ImapSession", "SessionPool"]


# 供调用方捕获：会话层统一把连接类失败归一成 ImapError
SESSION_ERRORS = (ImapError, OSError)

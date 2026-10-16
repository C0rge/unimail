"""把阻塞式服务调用搬到后台线程池，并把结果排队回主线程（P1）。

问题
----
附件下载、附件预览、内嵌图下载、`.eml` / `.mbox` 导出，以及「移入服务器
垃圾箱」的批量删除，此前都在 GUI 线程里同步执行。这些动作每一条都至少包含
一次 IMAP 往返（`FETCH_TIMEOUT` 默认 30 秒），服务端一慢整窗就冻住：
不重绘、不响应鼠标，Windows 会直接给标题栏加上「未响应」。批量删除更糟——
它是**逐封**一次往返，选中 300 封就是 300 次串行等待。

原先靠 `QApplication.processEvents()` 缓解，但那不是解法：它只是把一次长阻塞
切成很多次短阻塞，并且允许事件**重入**（导出途中还能再点一次导出、再点一次
删除），反而放大了竞态。

做法
----
* **执行体复用 `BodyFetchPool` 的线程池**（`submit_generic()`）。不新起第二个
  池：第二个池就是第二套「关停 / 取消 / 重启」语义，而 C3、C6 已经说明这类
  竞态是这个项目最容易出错的地方。
* 完成与进度都通过 Qt 信号回主线程；工作线程里绝不碰控件。
* 调用方只提供两个普通函数：干活的 `fn`，以及主线程里的
  `handler(result, error)`。这样既有的 UI 收尾逻辑（弹窗文案、状态栏、详情
  面板）可以原样复用，只是换了个线程执行——不必为「异步化」重写一套收尾。

线程归属
--------
`handler` 一定在主线程执行：信号由工作线程 `emit`，但接收者
（`IoTaskRunner`）属于主线程，Qt 的 AutoConnection 会把这次投递排队进主线程
的事件队列——与 `EventBus` 现有用法是同一套机制。反过来说，`fn` 一定在
**工作线程**执行，它里面不许出现任何 Qt 控件调用。
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import Future
from typing import Any

from PySide6.QtCore import QObject, Signal

from ..sync.body_fetcher import BodyFetchPool

log = logging.getLogger(__name__)

# 主线程侧的收尾回调：(result, error)。二者必有一个为 None。
Handler = Callable[[Any, BaseException | None], None]


class IoTaskRunner(QObject):
    """后台 IO 的提交点，也是结果回投主线程的落点。"""

    # (handler, result, error, key)：用 `object` 承载任意 Python 对象。
    _done = Signal(object, object, object, object)
    # (handler, args)：后台任务的进度回调借它请求「在主线程执行 handler(*args)」。
    _call = Signal(object, object)

    def __init__(self, pool: BodyFetchPool | None, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._pool = pool
        self._accepting = True
        self._keys: set[str] = set()
        self._done.connect(self._deliver)
        self._call.connect(self._invoke)

    # ------------------------------------------------------------ 生命周期
    @property
    def accepting(self) -> bool:
        """是否仍在接受新任务（退出流程中会变成 False）。"""
        return self._accepting

    def stop(self) -> None:
        """退出流程：不再接受新任务，也不再回投结果。

        退出时还回投结果是危险的——回调会弹「下载失败」之类的对话框，而窗口
        已经在销毁路径上，用户看到的是一次莫名其妙的报错弹窗卡住退出。
        """
        self._accepting = False

    # ------------------------------------------------------------ 提交
    def submit(self, fn: Callable[[], Any], handler: Handler,
               key: str | None = None) -> bool:
        """后台执行 `fn()`，完成后在**主线程**调用 `handler(result, error)`。

        `key` 用于去重：同一个 key 上一次还没跑完时，重复提交会被忽略——
        用户连点两次「下载附件」不该真的下载两遍，也不该叠两层结果弹窗。

        返回 False 表示这次没有真正提交（已 `stop()` / 池已关闭 / key 重复）。
        此时**不会**调用 `handler`，调用方不必为「没提交成功」再写一个分支。
        """
        if not self._accepting or (key is not None and key in self._keys):
            return False
        if self._pool is None:
            log.warning("后台 IO 池不可用（数据库尚未解锁？），任务未提交")
            return False
        try:
            fut = self._pool.submit_generic(fn)
        except RuntimeError:
            # 线程池已关闭（与退出流程的竞态）：如实记一笔，交给调用方决定口径
            log.info("后台 IO 线程池已关闭，任务未提交")
            return False
        if key is not None:
            self._keys.add(key)

        def _finished(f: Future, cb: Handler = handler,
                      task_key: str | None = key) -> None:
            try:
                result: Any = f.result()
                error: BaseException | None = None
            except BaseException as exc:        # noqa: BLE001 - 原样交回主线程裁决
                result, error = None, exc
            self._done.emit(cb, result, error, task_key)

        fut.add_done_callback(_finished)
        return True

    def post(self, handler: Callable[..., None], *args: Any) -> None:
        """请求在主线程执行 `handler(*args)`（供后台任务的进度回调使用）。"""
        if self._accepting:
            self._call.emit(handler, args)

    def in_flight(self) -> int:
        """尚未回投结果的任务数（含去重占位），供状态栏/退出前提示。"""
        return len(self._keys)

    # ------------------------------------------------------------ 回投
    def _deliver(self, handler: Handler, result: Any, error: Any, key: Any) -> None:
        if key is not None:
            self._keys.discard(key)
        if not self._accepting:
            return
        try:
            handler(result, error)
        except Exception:
            log.exception("后台 IO 结果处理失败")

    def _invoke(self, handler: Callable[..., None], args: Any) -> None:
        try:
            handler(*args)
        except Exception:
            log.exception("后台 IO 进度回调失败")

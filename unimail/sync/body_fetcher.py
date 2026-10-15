"""按需拉取邮件正文：在后台线程中补拉单封邮件的完整正文。"""
from __future__ import annotations

import logging

from PySide6.QtCore import QThread, Signal

from ..core.events import EventBus
from ..core.security import SecurityError
from ..core.services import AccountService
from ..platforms import ImapError, get_adapter
from ..storage import MailRepository

log = logging.getLogger(__name__)


class BodyFetchWorker(QThread):
    """拉取单封邮件的完整正文。

    使用场景：列表只同步了邮件头（快速填充），用户点开某封时才补拉正文。
    """

    fetched = Signal(str, str, str)   # mail_id, body_text, body_html
    failed = Signal(str, str)         # mail_id, error

    def __init__(self, mail_id: str, account_id: str, folder: str, uid: str,
                 platform: str, account_service: AccountService,
                 mails: MailRepository, bus: EventBus, parent=None) -> None:
        super().__init__(parent)
        self.mail_id = mail_id
        self.account_id = account_id
        self.folder = folder or "INBOX"
        self.uid = uid
        self.platform = platform
        self.account_service = account_service
        self.mails = mails
        self.bus = bus

    def run(self) -> None:
        account = self.account_service.get(self.account_id)
        if account is None:
            self.failed.emit(self.mail_id, "账号不存在")
            return
        adapter = get_adapter(self.platform)
        imap = None
        try:
            password = self.account_service.reload_password(account)
            imap = adapter.connect(account, password)
            try:
                imap.select(self.folder, readonly=True)
            except Exception:  # noqa: BLE001
                pass
            mail = adapter.fetch_message(imap, self.uid, self.folder)
            self.mails.update_body(self.mail_id, mail.body_text, mail.body_html)
            self.fetched.emit(self.mail_id, mail.body_text, mail.body_html)
            log.debug("已补拉正文：mail=%s uid=%s", self.mail_id[:8], self.uid)
        except (ImapError, SecurityError) as exc:
            self.failed.emit(self.mail_id, str(exc))
        except Exception as exc:  # noqa: BLE001
            log.exception("补拉正文失败")
            self.failed.emit(self.mail_id, f"补拉正文异常：{exc}")
        finally:
            if imap is not None:
                adapter.disconnect(imap)


class BodyFetchPool:
    """管理正文补拉线程，避免重复拉取同一封邮件。"""

    def __init__(self, account_service: AccountService, mails: MailRepository,
                 bus: EventBus) -> None:
        self.account_service = account_service
        self.mails = mails
        self.bus = bus
        self._workers: dict[str, BodyFetchWorker] = {}
        self._requested: set[str] = set()

    def is_pending(self, mail_id: str) -> bool:
        return mail_id in self._requested

    def request(self, mail_id: str) -> bool:
        """请求补拉正文；已在队列中则返回 False。"""
        if mail_id in self._requested:
            return False
        row = self.mails.db.query_one(
            "SELECT account_id, folder, uid, platform FROM mails WHERE id = ?",
            (mail_id,),
        )
        if row is None:
            return False

        self._requested.add(mail_id)
        worker = BodyFetchWorker(
            mail_id, row["account_id"], row["folder"], str(row["uid"]),
            row["platform"], self.account_service, self.mails, self.bus,
        )
        worker.fetched.connect(self._on_fetched)
        worker.failed.connect(self._on_failed)
        worker.finished.connect(lambda mid=mail_id: self._cleanup(mid))
        self._workers[mail_id] = worker
        worker.start()
        return True

    def _on_fetched(self, mail_id: str, text: str, html: str) -> None:
        self.bus.mail_updated.emit(mail_id)

    def _on_failed(self, mail_id: str, error: str) -> None:
        log.warning("正文补拉失败 mail=%s: %s", mail_id[:8], error)

    def _cleanup(self, mail_id: str) -> None:
        worker = self._workers.pop(mail_id, None)
        if worker is not None:
            worker.deleteLater()
        # 失败的不保留在 requested 中，允许用户重试
        self._requested.discard(mail_id)

    def stop_all(self) -> None:
        for worker in list(self._workers.values()):
            if worker.isRunning():
                worker.wait(3000)

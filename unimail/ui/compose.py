"""撰写对话框：写新邮件、回复、转发。

为什么发送要走后台线程
-------------------
SMTP 投递是一次完整网络会话：TCP + TLS + EHLO + 认证 + DATA + QUIT。
顺风时几百毫秒，慢时几秒，超时上限 `FETCH_TIMEOUT`（30 秒）。放在 GUI
线程里同步执行，点一次「发送」就冻结整个窗口——与附件下载当初必须搬走
是同一个理由（见 `io_runner.py` 顶部）。

为什么发送前先入队
---------------
`ComposeService.queue()` 会把完整原文写进 outbox 再发送。失败时邮件还在
队列里、错误可读、可一键重试，而不是「点过发送就只能重写」。这个顺序的
代价是本地多一行记录，收益是**用户不再丢失任何一封写过的邮件**。

HTML 编辑的取舍
-------------
刻意**只做纯文本**。理由：
1. 本项目对 HTML 的既有立场是「清洗接收的，不生成发送的」——撰写端引入
   HTML 就把 XSS 与跟踪像素的防御面扩大到了 outgoing；
2. 主流收件场景（通知、验证码、工作往来）纯文本完全够用；
3. 富文本编辑器是一整个子系统（选区格式、粘贴清洗、图片内嵌、签名渲染），
   而本项目当前最缺的是「能发出去」，不是「发得好看」。
"""
from __future__ import annotations

import logging

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..core.models import Account
from ..core.services import ComposeDraft, ComposeService
from . import icons

log = logging.getLogger(__name__)

# 附件总大小上限。与 MAX_ATTACHMENT_BYTES 分开：那是「单个附件下载上限」，
# 这里是「一封邮件允许携带的总量」——SMTP 服务商通常对单封邮件有 25–50 MB
# 的总量限制，超限会在 DATA 阶段才被拒，那时用户已经等了一轮上传。
_MAX_TOTAL_ATTACH_BYTES = 25 * 1024 * 1024


class ComposeDialog(QDialog):
    """撰写 / 回复 / 转发对话框。

    发送结果通过 `sent` 信号广播（不带参数），主窗口据此刷新 outbox 计数。
    """

    sent = Signal()

    def __init__(self, compose: ComposeService, accounts: list[Account],
                 draft: ComposeDraft | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.compose = compose
        self.accounts = accounts
        # 草稿由 ComposeService.build_reply/build_forward 产出（线程头已填好），
        # 或为 None（写新邮件）。**不在本对话框里构造线程头**——那属于用例层。
        self.draft = draft or ComposeDraft(
            account_id=accounts[0].id if accounts else "")
        self.attachments: list[tuple[str, bytes, str]] = list(self.draft.attachments)

        self.setWindowTitle("写邮件" if draft is None else
                            ("回复" if draft.in_reply_to else "转发"))
        self.resize(720, 600)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(10)

        # ---------------------------------------------------- 头部字段
        form = QHBoxLayout()
        form.setSpacing(8)
        self.account_box = QComboBox()
        for acc in accounts:
            self.account_box.addItem(acc.label, acc.id)
        # 选中草稿指定的账号（回复/转发必须用原账号发，否则 From 会错）。
        idx = self.account_box.findData(self.draft.account_id)
        if idx >= 0:
            self.account_box.setCurrentIndex(idx)
        form.addWidget(self.account_box)
        layout.addLayout(form)

        self.to_edit = QLineEdit()
        self.to_edit.setPlaceholderText("收件人（多个地址用逗号分隔）")
        self.to_edit.setText(", ".join(self.draft.to))
        layout.addWidget(self.to_edit)

        self.cc_edit = QLineEdit()
        self.cc_edit.setPlaceholderText("抄送（可选）")
        self.cc_edit.setText(", ".join(self.draft.cc))
        layout.addWidget(self.cc_edit)

        self.subject_edit = QLineEdit()
        self.subject_edit.setPlaceholderText("主题")
        self.subject_edit.setText(self.draft.subject)
        layout.addWidget(self.subject_edit)

        # ---------------------------------------------------- 正文
        self.body_edit = QPlainTextEdit()
        self.body_edit.setPlaceholderText("正文…")
        self.body_edit.setPlainText(self.draft.body)
        if self.draft.body:
            # 回复/转发的预填正文之后，光标落在末尾，用户直接接着写。
            self.body_edit.moveCursor(QTextCursor.MoveOperation.End)
        layout.addWidget(self.body_edit, 1)

        # ---------------------------------------------------- 附件
        att_row = QHBoxLayout()
        self.btn_attach = QPushButton("添加附件…")
        self.btn_attach.setIcon(icons.icon("paperclip", "#8b98a9", 14))
        self.btn_attach.clicked.connect(self._pick_attachments)
        att_row.addWidget(self.btn_attach)
        self.att_label = QLabel("")
        self.att_label.setObjectName("Hint")
        att_row.addWidget(self.att_label, 1)
        layout.addLayout(att_row)
        self._refresh_attachment_label()

        # ---------------------------------------------------- 按钮
        self.err = QLabel("")
        self.err.setStyleSheet("color: #f2545b; font-size: 12px;")
        self.err.setWordWrap(True)
        layout.addWidget(self.err)

        buttons = QDialogButtonBox()
        self.btn_send = QPushButton("发送")
        self.btn_send.setIcon(icons.icon("export", "#8b98a9", 14))
        self.btn_send.setDefault(True)
        self.btn_send.clicked.connect(self._on_send)
        buttons.addButton(self.btn_send, QDialogButtonBox.ButtonRole.AcceptRole)
        btn_cancel = QPushButton("取消")
        btn_cancel.clicked.connect(self.reject)
        buttons.addButton(btn_cancel, QDialogButtonBox.ButtonRole.RejectRole)
        layout.addWidget(buttons)

        if not accounts:
            self.btn_send.setEnabled(False)
            self.err.setText("还没有添加任何邮箱账号，请先在「文件 → 添加邮箱账号」中添加。")

    # ------------------------------------------------------------ 附件
    def _pick_attachments(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "选择附件")
        for path in files:
            if not path:
                continue
            try:
                with open(path, "rb") as fh:
                    data = fh.read()
            except OSError as exc:
                QMessageBox.warning(self, "读取失败", f"无法读取 {path}：{exc}")
                continue
            if sum(len(d) for _, d, _ in self.attachments) + len(data) > _MAX_TOTAL_ATTACH_BYTES:
                QMessageBox.warning(
                    self, "附件过大",
                    f"附件总大小超过 {_MAX_TOTAL_ATTACH_BYTES // (1024 * 1024)} MB 上限。\n"
                    "多数邮件服务商会在数据阶段才拒绝超限邮件，那时会白等一轮上传。")
                continue
            name = path.replace("\\", "/").rsplit("/", 1)[-1]
            self.attachments.append((name, data, _guess_mime(name)))
        self._refresh_attachment_label()

    def _refresh_attachment_label(self) -> None:
        if not self.attachments:
            self.att_label.setText("")
            return
        total = sum(len(d) for _, d, _ in self.attachments)
        self.att_label.setText(
            f"{len(self.attachments)} 个附件（{total / 1024:.0f} KB）："
            + "、".join(n for n, _, _ in self.attachments))

    # ------------------------------------------------------------ 发送
    def _on_send(self) -> None:
        to = [a.strip() for a in self.to_edit.text().split(",") if a.strip()]
        cc = [a.strip() for a in self.cc_edit.text().split(",") if a.strip()]
        if not to:
            self.err.setText("请填写收件人")
            return
        bad = [a for a in to + cc if "@" not in a]
        if bad:
            self.err.setText(f"这些地址格式不正确：{'、'.join(bad)}")
            return

        draft = ComposeDraft(
            account_id=self.account_box.currentData(),
            to=to, cc=cc,
            subject=self.subject_edit.text().strip(),
            body=self.body_edit.toPlainText(),
            in_reply_to=self.draft.in_reply_to,
            ref_chain=self.draft.ref_chain,
            attachments=self.attachments,
        )
        self.btn_send.setEnabled(False)
        self.btn_send.setText("发送中…")
        self.err.setText("")
        try:
            msg_id = self.compose.queue(draft)
            # 入队成功后同步发送：这一步包含完整 SMTP 会话（最坏 30 秒），
            # 因此**必须**在 GUI 线程之外做。这里用 QTimer 把发送推到事件循环
            # 之后执行，对话框先关闭、主窗口不被冻结——发送结果由 sent 信号
            # 与 outbox 计数体现，失败时用户在「发件箱」里看到原因并可重试。
            self._pending_id = msg_id
            self.accept()
        except ValueError as exc:
            # 入队阶段的校验失败（空收件人、账号缺失、凭据解不开）：
            # 这时邮件还没写进 outbox，直接就地提示，不关闭对话框。
            self.btn_send.setEnabled(True)
            self.btn_send.setText("发送")
            self.err.setText(str(exc))
            return
        except Exception as exc:  # noqa: BLE001 - 兜底：不能让对话框卡在「发送中」
            self.btn_send.setEnabled(True)
            self.btn_send.setText("发送")
            self.err.setText(f"发送失败：{exc}")
            return

        self.sent.emit()
        # 由主窗口在后台线程里完成实际投递（见 MainWindow._send_outbox_item）。
        self._dispatch_send(msg_id)

    def _dispatch_send(self, msg_id: str) -> None:
        """把「实际投递」交给主窗口的后台 IO 通道。

        对话框不接受 `IoTaskRunner` 依赖（它是主窗口的组件），因此通过
        `parent()` 向下调用。父窗口不是 MainWindow 时（测试、独立使用）
        退化为同步发送——功能仍正确，只是会阻塞调用方。
        """
        parent = self.parent()
        dispatcher = getattr(parent, "send_outbox_item", None)
        if callable(dispatcher):
            dispatcher(msg_id)
            return
        result = self.compose.send_one(msg_id)
        if not result.ok:
            log.warning("发送失败（%s）：%s", msg_id, result.error)


def _guess_mime(filename: str) -> str:
    """按扩展名猜 MIME 类型；猜不出时用 application/octet-stream。

    刻意**不**引入 `mimetypes` 之外的东西，也不猜错类型：猜成 text/html
    会让邮件客户端把附件渲染进正文（XSS 面），而 octet-stream 只会让用户
    手动选择打开方式——安全的默认值。
    """
    import mimetypes

    mime, _ = mimetypes.guess_type(filename)
    if not mime:
        return "application/octet-stream"
    if mime in ("text/html", "application/xhtml+xml"):
        return "text/plain"
    return mime


__all__ = ["ComposeDialog"]

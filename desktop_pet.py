from __future__ import annotations

import argparse
import asyncio
import html
import os
import re
import signal
import subprocess
import sys
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from PySide6.QtCore import (
    QEasingCurve,
    QObject,
    QPoint,
    QPropertyAnimation,
    QRect,
    QSize,
    Qt,
    QThread,
    QTimer,
    Signal,
)
from PySide6.QtGui import QColor, QCursor, QFont, QPainter, QPen, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QAbstractItemView,
    QSizePolicy,
    QStackedWidget,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from examples.model_factory import resolve_default_model, resolve_provider
from harness.prompts import DEFAULT_EMAIL, HELP_TEXT, build_analysis_prompt
from harness.runtime import (
    EmailAgentRuntime,
    is_quota_error,
    latest_ai_message,
    summarize_invoked_tools,
    summarize_tool_messages,
)
from harness.ui import (
    configure_quiet_logging,
    render_chat_response,
    render_error,
    render_trace,
)
from skills.imap_monitor.schemas import BindImapMailboxInput
from skills.imap_monitor.skill import (
    BindImapMailboxSkill,
    _connect_imap,
    _fetch_message_bytes,
    _get_all_uids,
)
from skills.imap_monitor.storage import get_mailbox, list_mailboxes


PROJECT_ROOT = Path(__file__).resolve().parent
BALL_SIZE = 72
PANEL_SIZE = QSize(1180, 680)
DRAG_HOLD_MS = 250
EMAIL_PAGE_SIZE = 10


def _child_pids(parent: int) -> list[int]:
    try:
        proc = subprocess.run(
            ["pgrep", "-P", str(parent)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    out: list[int] = []
    for token in proc.stdout.split():
        if token.isdigit():
            out.append(int(token))
    return out


def _gather_descendant_pids(root: int) -> list[int]:
    """All descendant processes of root (post-order: deeper children first)."""
    ordered: list[int] = []
    for child in _child_pids(root):
        ordered.extend(_gather_descendant_pids(child))
        ordered.append(child)
    return ordered


def _sigterm_pid(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass


def terminate_stack_child_pids_from_env() -> None:
    """End mock rspamd / ollama started by scripts/start_full_stack.sh (sibling processes)."""
    raw = os.environ.get("EMAIL_AGENT_STACK_CHILD_PIDS", "").strip()
    if not raw:
        return
    for part in raw.replace(",", " ").split():
        if part.isdigit():
            _sigterm_pid(int(part))


def terminate_own_subprocesses() -> None:
    """End OS child processes of this interpreter (e.g. MCP stdio servers)."""
    me = os.getpid()
    for pid in reversed(_gather_descendant_pids(me)):
        _sigterm_pid(pid)


class ReadableHTMLParser(HTMLParser):
    block_tags = {
        "address",
        "article",
        "aside",
        "blockquote",
        "br",
        "div",
        "footer",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "header",
        "li",
        "p",
        "section",
        "table",
        "td",
        "th",
        "tr",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        tag = tag.lower()
        if tag in {"script", "style", "head"}:
            self.skip_depth += 1
            return
        if tag in self.block_tags:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in {"script", "style", "head"} and self.skip_depth:
            self.skip_depth -= 1
            return
        if tag in self.block_tags:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self.skip_depth:
            return
        text = " ".join(data.split())
        if text:
            self.parts.append(text)
            self.parts.append(" ")

    def text(self) -> str:
        raw = html.unescape("".join(self.parts))
        raw = re.sub(r"[ \t\r\f\v]+", " ", raw)
        raw = re.sub(r"\n[ \t]+", "\n", raw)
        raw = re.sub(r"\n{3,}", "\n\n", raw)
        return raw.strip()


def load_local_env(project_root: Path) -> None:
    env_path = project_root / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or key in os.environ:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ[key] = value


def read_text_file(path_text: str) -> str:
    return Path(path_text).expanduser().read_text(encoding="utf-8")


def _compact_mail_text(text: str, limit: int = 360) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1].rstrip() + "..."


def _html_escape_text(text: str) -> str:
    return html.escape(text).replace("\n", "<br>")


def _looks_like_html(text: str) -> bool:
    lowered = text.lower()
    if any(marker in lowered for marker in ("<html", "<body", "<!doctype", "<table", "<style", "<div", "<span", "<td", "<tr")):
        return True
    return bool(re.search(r"</?[a-z][a-z0-9]*(?:\s+[^>]*)?>", text, flags=re.IGNORECASE))


def _clean_readable_mail_text(text: str) -> str:
    text = text.replace("\u200c", " ").replace("\u200d", " ").replace("\ufeff", " ")
    text = text.replace("\xa0", " ").replace("\u034f", " ")
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = re.sub(r"(?:\s*[\u200b\u200c\u200d\xa0]\s*)+", " ", text)
    text = re.sub(r"\n[ \t]+", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _html_to_readable_text(raw_html: str) -> str:
    parser = ReadableHTMLParser()
    try:
        parser.feed(raw_html)
        parser.close()
    except Exception:
        return ""
    return _clean_readable_mail_text(parser.text())


def _part_content_text(part) -> str:
    try:
        content = part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        if isinstance(payload, bytes):
            charset = part.get_content_charset() or "utf-8"
            content = payload.decode(charset, errors="replace")
        else:
            content = str(payload)
    return str(content)


def _mail_body_text(raw_bytes: bytes) -> str:
    parsed = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    plain_body = parsed.get_body(preferencelist=("plain",))
    if plain_body is not None:
        text = _part_content_text(plain_body).strip()
        if text:
            if _looks_like_html(text):
                readable = _html_to_readable_text(text)
                if readable:
                    return readable
            return _clean_readable_mail_text(text)

    html_body = parsed.get_body(preferencelist=("html",))
    if html_body is not None:
        text = _html_to_readable_text(_part_content_text(html_body))
        if text:
            return text

    payload = parsed.get_payload(decode=True) or b""
    if isinstance(payload, bytes):
        text = payload.decode(parsed.get_content_charset() or "utf-8", errors="replace")
    else:
        text = str(payload)
    if _looks_like_html(text):
        readable = _html_to_readable_text(text)
        if readable:
            return readable
    return _clean_readable_mail_text(text)


def _message_preview(raw_bytes: bytes) -> dict[str, str]:
    parsed = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    full_text = _mail_body_text(raw_bytes)
    return {
        "subject": str(parsed.get("Subject") or "(no subject)"),
        "from": str(parsed.get("From") or "unknown"),
        "date": str(parsed.get("Date") or "unknown date"),
        "preview": _compact_mail_text(full_text, limit=160),
        "full_text": full_text or "(No readable plain text body.)",
    }


def build_referenced_email_prompt(question: str, referenced_emails: list[dict[str, str]]) -> str:
    if len(referenced_emails) == 1:
        item = referenced_emails[0]
        raw_email = "\n".join(
            [
                f"From: {item.get('from', 'unknown')}",
                f"Date: {item.get('date', 'unknown date')}",
                f"Subject: {item.get('subject', '(no subject)')}",
                "",
                str(item.get("full_text", "")),
            ]
        )
        return build_analysis_prompt(
            question
            + "\nGive a final answer even if some tools are unavailable. Use plain language for a normal user.",
            raw_email=raw_email,
        )

    sections = [
        question,
        "There are multiple referenced emails below. Do not treat them as one combined email.",
        "Analyze each referenced email separately for phishing, spam, sender authenticity, urgency, and suspicious links.",
        "Your final answer must contain one labeled section per email: Email 1, Email 2, Email 3 as applicable.",
        "For each email, include verdict, confidence, key evidence, and recommended user action.",
        "If tools are unavailable or only one tool runs, still provide a plain-language assessment for every referenced email from the visible content.",
        "",
        "Required workflow: first call `list_error_patterns`, then run the normal security tools where possible, then call `error_pattern_memory_check` before the final verdict.",
    ]
    for index, item in enumerate(referenced_emails, 1):
        sections.extend(
            [
                "",
                f"Referenced email {index}:",
                f"From: {item.get('from', 'unknown')}",
                f"Date: {item.get('date', 'unknown date')}",
                f"Subject: {item.get('subject', '(no subject)')}",
                "",
                str(item.get("full_text", "")),
            ]
        )
    return "\n".join(sections)


class AgentWorker(QObject):
    ready = Signal(str)
    progress = Signal(str)
    result = Signal(str)
    failed = Signal(str)
    finished = Signal()

    def __init__(
        self,
        *,
        provider: str,
        model: str,
        rspamd_base_url: str,
        ollama_base_url: str,
        prompt: str,
        reset: bool,
        trace: bool,
        runtime: EmailAgentRuntime | None,
        setup_only: bool = False,
        prefer_ai_response: bool = False,
    ) -> None:
        super().__init__()
        self.provider = provider
        self.model = model
        self.rspamd_base_url = rspamd_base_url
        self.ollama_base_url = ollama_base_url
        self.prompt = prompt
        self.reset = reset
        self.trace = trace
        self.runtime = runtime
        self.updated_runtime: EmailAgentRuntime | None = runtime
        self.setup_only = setup_only
        self.prefer_ai_response = prefer_ai_response

    def run(self) -> None:
        try:
            asyncio.run(self._run())
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.finished.emit()

    async def _run(self) -> None:
        if self.runtime is None:
            self.progress.emit("Initializing Email Guardian runtime")
            self.runtime = EmailAgentRuntime(
                provider=self.provider,
                model_name=self.model,
                rspamd_base_url=self.rspamd_base_url,
                ollama_base_url=self.ollama_base_url,
                show_messages=self.trace,
            )
            await self.runtime.setup()
            self.updated_runtime = self.runtime
            self.ready.emit(f"{self.provider} / {self.model}")

        if self.setup_only:
            return

        self.runtime.show_messages = self.trace
        if self.reset:
            self.runtime.reset()
            self.progress.emit("Conversation history cleared")

        start_idx = len(self.runtime.history)
        try:
            messages, start_idx = await self.runtime.ask(
                self.prompt,
                progress_callback=self.progress.emit,
            )
        except Exception as exc:
            tool_summary = summarize_tool_messages(self.runtime.history, start_idx)
            self.result.emit(
                render_error(
                    exc,
                    quota=is_quota_error(exc),
                    tool_summary=tool_summary,
                )
            )
            return

        if self.trace:
            self.result.emit(render_trace(messages, start_idx))
        elif self.prefer_ai_response:
            body = latest_ai_message(messages).strip()
            tool_list = summarize_invoked_tools(messages, start_idx)
            if body:
                rendered = body
                if tool_list:
                    rendered = f"Tools: {tool_list}\n\n{body}"
                self.result.emit(rendered)
            else:
                self.result.emit(render_chat_response(messages, start_idx))
        else:
            self.result.emit(render_chat_response(messages, start_idx))


class MailboxWorker(QObject):
    progress = Signal(str)
    mailboxes_ready = Signal(object)
    emails_ready = Signal(str, int, object)
    bound = Signal(str)
    failed = Signal(str)
    finished = Signal()

    def __init__(
        self,
        *,
        action: str,
        email_address: str = "",
        offset: int = 0,
        limit: int = EMAIL_PAGE_SIZE,
        bind_payload: dict[str, Any] | None = None,
    ) -> None:
        super().__init__()
        self.action = action
        self.email_address = email_address
        self.offset = offset
        self.limit = limit
        self.bind_payload = bind_payload or {}

    def run(self) -> None:
        try:
            if self.action == "list":
                self.mailboxes_ready.emit([item["email_address"] for item in list_mailboxes(enabled_only=False)])
            elif self.action == "bind":
                self._bind_mailbox()
            elif self.action == "fetch":
                self._fetch_emails()
            else:
                raise RuntimeError(f"Unknown mailbox action: {self.action}")
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.finished.emit()

    def _bind_mailbox(self) -> None:
        self.progress.emit("Binding mailbox")
        result = BindImapMailboxSkill().run(
            BindImapMailboxInput(
                email_address=str(self.bind_payload.get("email_address") or ""),
                username=str(self.bind_payload.get("username") or "") or None,
                app_password=str(self.bind_payload.get("app_password") or ""),
                imap_host=str(self.bind_payload.get("imap_host") or "imap.gmail.com"),
                imap_port=int(self.bind_payload.get("imap_port") or 993),
                folder=str(self.bind_payload.get("folder") or "INBOX"),
                poll_interval_seconds=30,
                use_ssl=True,
                enabled=True,
            )
        )
        if not result.ok or result.data is None:
            raise RuntimeError(result.error.message if result.error else "Mailbox bind failed")
        self.bound.emit(result.data.mailbox.email_address)

    def _fetch_emails(self) -> None:
        if not self.email_address:
            raise RuntimeError("Choose a bound mailbox first")
        mailbox = get_mailbox(self.email_address)
        if mailbox is None:
            raise RuntimeError(f"Mailbox {self.email_address} is not bound")

        self.progress.emit(f"Loading messages {self.offset + 1}-{self.offset + self.limit}")
        client = _connect_imap(mailbox)
        try:
            all_uids = sorted(_get_all_uids(client), reverse=True)
            selected_uids = all_uids[self.offset : self.offset + self.limit]
            rows: list[dict[str, str]] = []
            for uid in selected_uids:
                raw_bytes = _fetch_message_bytes(client, uid)
                item = _message_preview(raw_bytes)
                item["uid"] = str(uid)
                rows.append(item)
            self.emails_ready.emit(self.email_address, self.offset, rows)
        finally:
            try:
                client.logout()
            except Exception:
                pass


class BallWidget(QWidget):
    clicked = Signal()
    drag_started = Signal()

    def __init__(self) -> None:
        super().__init__()
        self.setFixedSize(BALL_SIZE, BALL_SIZE)
        self.status = "starting"
        self._press_global: QPoint | None = None
        self._dragging = False
        self._drag_enabled = False
        self._hold_timer = QTimer(self)
        self._hold_timer.setSingleShot(True)
        self._hold_timer.timeout.connect(self._enable_drag)
        self.setCursor(QCursor(Qt.PointingHandCursor))

    def set_status(self, status: str) -> None:
        self.status = status
        self.update()

    def _enable_drag(self) -> None:
        self._drag_enabled = True
        self.drag_started.emit()

    def mousePressEvent(self, event) -> None:  # type: ignore[override]
        if event.button() != Qt.LeftButton:
            return
        self._press_global = event.globalPosition().toPoint()
        self._dragging = False
        self._drag_enabled = False
        self._hold_timer.start(DRAG_HOLD_MS)

    def mouseMoveEvent(self, event) -> None:  # type: ignore[override]
        if self._press_global is None or not self._drag_enabled:
            return
        current = event.globalPosition().toPoint()
        delta = current - self._press_global
        if delta.manhattanLength() > 2:
            self._dragging = True
            window = self.window()
            window.move(window.pos() + delta)
            self._press_global = current

    def mouseReleaseEvent(self, event) -> None:  # type: ignore[override]
        if event.button() != Qt.LeftButton:
            return
        self._hold_timer.stop()
        if not self._dragging:
            self.clicked.emit()
        self._press_global = None
        self._dragging = False
        self._drag_enabled = False

    def paintEvent(self, event) -> None:  # type: ignore[override]
        del event
        colors = {
            "starting": ("#7b8794", "#d0d7de"),
            "ready": ("#2f9e44", "#b2f2bb"),
            "busy": ("#f08c00", "#ffec99"),
            "error": ("#c92a2a", "#ffc9c9"),
        }
        base, highlight = colors.get(self.status, colors["starting"])
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        rect = self.rect().adjusted(5, 5, -5, -5)
        painter.setPen(QPen(QColor("#ffffff"), 2))
        painter.setBrush(QColor(base))
        painter.drawEllipse(rect)

        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(highlight))
        painter.drawEllipse(21, 14, 18, 12)

        painter.setPen(QPen(QColor("#ffffff"), 3))
        painter.drawArc(rect.adjusted(15, 18, -15, -16), 210 * 16, 120 * 16)


class PetWindow(QMainWindow):
    def __init__(self, args: argparse.Namespace) -> None:
        super().__init__()
        self.args = args
        self._shutting_down = False
        self.runtime: EmailAgentRuntime | None = None
        self.thread: QThread | None = None
        self.worker: AgentWorker | None = None
        self.mail_thread: QThread | None = None
        self.mail_worker: MailboxWorker | None = None
        self.loaded_email_count = 0
        self.referenced_emails: list[dict[str, str]] = []
        self.expanded = False

        self.setWindowTitle("Email Guardian")
        self.setWindowFlags(
            Qt.FramelessWindowHint
            | Qt.WindowStaysOnTopHint
            | Qt.Tool
        )
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setMinimumSize(BALL_SIZE, BALL_SIZE)

        self.container = QWidget()
        self.container.setObjectName("container")
        self.setCentralWidget(self.container)

        root = QVBoxLayout(self.container)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.stack = QStackedWidget()
        root.addWidget(self.stack)

        self.ball_page = QWidget()
        ball_layout = QVBoxLayout(self.ball_page)
        ball_layout.setContentsMargins(0, 0, 0, 0)
        ball_layout.setAlignment(Qt.AlignCenter)
        self.ball = BallWidget()
        self.ball.clicked.connect(self.expand_panel)
        ball_layout.addWidget(self.ball)
        self.stack.addWidget(self.ball_page)

        self.panel = self._build_panel()
        self.stack.addWidget(self.panel)
        self.stack.setCurrentWidget(self.ball_page)

        self._apply_styles()
        self.resize(BALL_SIZE, BALL_SIZE)
        self._place_bottom_right()
        self.refresh_mailboxes()
        QTimer.singleShot(250, self.initialize_runtime)

    def _build_panel(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("panel")
        shadow = QGraphicsDropShadowEffect(panel)
        shadow.setBlurRadius(22)
        shadow.setOffset(0, 8)
        shadow.setColor(QColor(0, 0, 0, 80))
        panel.setGraphicsEffect(shadow)

        layout = QHBoxLayout(panel)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(230)
        side_layout = QVBoxLayout(sidebar)
        side_layout.setContentsMargins(10, 10, 10, 10)
        side_layout.setSpacing(8)

        self.header_ball = BallWidget()
        self.header_ball.clicked.connect(self.collapse_panel)
        self.header_ball.setFixedSize(52, 52)
        title = QLabel("Email Guardian")
        title.setObjectName("title")
        self.status_label = QLabel("Starting")
        self.status_label.setObjectName("status")
        self.status_label.setWordWrap(True)
        side_layout.addWidget(self.header_ball, alignment=Qt.AlignHCenter)
        side_layout.addWidget(title)
        side_layout.addWidget(self.status_label)

        model_label = QLabel("Model")
        model_label.setObjectName("sectionLabel")
        self.provider_combo = QComboBox()
        self.provider_combo.addItems(["gemini", "ollama"])
        self.provider_combo.setCurrentText(self.args.provider)
        self.provider_combo.currentTextChanged.connect(self.update_model_default)
        self.model_input = QLineEdit(self.args.model)
        self.model_input.setPlaceholderText("model name")
        self.switch_model_button = QPushButton("Switch Model")
        self.switch_model_button.clicked.connect(self.switch_model)
        side_layout.addWidget(model_label)
        side_layout.addWidget(self.provider_combo)
        side_layout.addWidget(self.model_input)
        side_layout.addWidget(self.switch_model_button)

        mailbox_label = QLabel("Mailboxes")
        mailbox_label.setObjectName("sectionLabel")
        self.mailbox_combo = QComboBox()
        self.mailbox_combo.setPlaceholderText("No bound mailbox")
        refresh_mailboxes_button = QPushButton("Refresh Mailboxes")
        refresh_mailboxes_button.clicked.connect(self.refresh_mailboxes)
        show_mail_button = QPushButton("Show Latest 10")
        show_mail_button.clicked.connect(self.show_latest_mail)
        load_more_button = QPushButton("Load 10 More")
        load_more_button.clicked.connect(self.load_more_mail)
        self.bind_email_input = QLineEdit()
        self.bind_email_input.setPlaceholderText("email address")
        self.bind_username_input = QLineEdit()
        self.bind_username_input.setPlaceholderText("username, optional")
        self.bind_password_input = QLineEdit()
        self.bind_password_input.setPlaceholderText("IMAP/app password")
        self.bind_password_input.setEchoMode(QLineEdit.Password)
        self.bind_host_input = QLineEdit("imap.gmail.com")
        self.bind_host_input.setPlaceholderText("imap host")
        self.bind_folder_input = QLineEdit("INBOX")
        self.bind_folder_input.setPlaceholderText("folder")
        bind_button = QPushButton("Bind Mailbox")
        bind_button.clicked.connect(self.bind_mailbox)

        for widget in (
            mailbox_label,
            self.mailbox_combo,
            refresh_mailboxes_button,
            show_mail_button,
            load_more_button,
            self.bind_email_input,
            self.bind_username_input,
            self.bind_password_input,
            self.bind_host_input,
            self.bind_folder_input,
            bind_button,
        ):
            side_layout.addWidget(widget)

        functions_label = QLabel("Functions")
        functions_label.setObjectName("sectionLabel")
        side_layout.addWidget(functions_label)

        chat_view_button = QPushButton("Chat View")
        chat_view_button.clicked.connect(self.show_chat_view)
        sample_button = QPushButton("Sample Email")
        sample_button.clicked.connect(self.run_sample)
        email_file_button = QPushButton("Email File")
        email_file_button.clicked.connect(self.run_email_file)
        headers_file_button = QPushButton("Headers File")
        headers_file_button.clicked.connect(self.run_headers_file)
        paste_email_button = QPushButton("Paste Email")
        paste_email_button.clicked.connect(self.run_pasted_email)
        paste_headers_button = QPushButton("Paste Headers")
        paste_headers_button.clicked.connect(self.run_pasted_headers)
        reset_button = QPushButton("Reset")
        reset_button.setObjectName("secondaryButton")
        reset_button.clicked.connect(self.reset_chat)
        help_button = QPushButton("Help")
        help_button.setObjectName("secondaryButton")
        help_button.clicked.connect(self.show_help)
        quit_all_button = QPushButton("Quit and shut down all")
        quit_all_button.setObjectName("dangerQuitButton")
        quit_all_button.setToolTip(
            "Close the window and terminate MCP child processes; "
            "if launched via start_full_stack.sh, also stop mock Rspamd / Ollama."
        )
        quit_all_button.clicked.connect(self.confirm_quit_all)

        for button in (
            chat_view_button,
            sample_button,
            email_file_button,
            headers_file_button,
            paste_email_button,
            paste_headers_button,
            reset_button,
            help_button,
            quit_all_button,
        ):
            side_layout.addWidget(button)

        self.trace_check = QCheckBox("Trace")
        side_layout.addWidget(self.trace_check)
        side_layout.addStretch()

        collapse = QPushButton("Collapse")
        collapse.setObjectName("secondaryButton")
        collapse.clicked.connect(self.collapse_panel)
        side_layout.addWidget(collapse)

        side_scroll = QScrollArea()
        side_scroll.setObjectName("sideScroll")
        side_scroll.setWidgetResizable(True)
        side_scroll.setFrameShape(QFrame.NoFrame)
        side_scroll.setFixedWidth(246)
        side_scroll.setWidget(sidebar)
        layout.addWidget(side_scroll)

        self.mail_panel = QFrame()
        self.mail_panel.setObjectName("mailPane")
        self.mail_panel.setFixedWidth(360)
        self.mail_panel.hide()
        mail_panel_layout = QVBoxLayout(self.mail_panel)
        mail_panel_layout.setContentsMargins(0, 0, 0, 0)
        mail_panel_layout.setSpacing(10)
        mail_title = QLabel("Mailbox")
        mail_title.setObjectName("chatTitle")
        self.mailbox_status_label = QLabel("Choose a bound mailbox and load messages.")
        self.mailbox_status_label.setObjectName("status")
        self.mailbox_status_label.setWordWrap(True)
        self.mail_list = QListWidget()
        self.mail_list.setObjectName("mailList")
        self.mail_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.mail_list.currentItemChanged.connect(self.show_selected_email)
        self.mail_detail = QTextEdit()
        self.mail_detail.setObjectName("mailDetail")
        self.mail_detail.setReadOnly(True)
        self.mail_detail.setPlaceholderText("Click a message to read the full email.")
        self.quote_mail_button = QPushButton("Use Selected Emails In Chat")
        self.quote_mail_button.clicked.connect(self.quote_selected_email_to_chat)
        mail_panel_layout.addWidget(mail_title)
        mail_panel_layout.addWidget(self.mailbox_status_label)
        mail_panel_layout.addWidget(self.mail_list, stretch=1)
        mail_panel_layout.addWidget(self.mail_detail, stretch=1)
        mail_panel_layout.addWidget(self.quote_mail_button)
        layout.addWidget(self.mail_panel)

        main = QFrame()
        main.setObjectName("mainPane")
        main_layout = QVBoxLayout(main)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(10)

        chat_title = QLabel("Chat")
        chat_title.setObjectName("chatTitle")
        main_layout.addWidget(chat_title)

        self.progress = QTextEdit()
        self.progress.setObjectName("progress")
        self.progress.setProperty("state", "busy")
        self.progress.setReadOnly(True)
        self.progress.setFixedHeight(82)
        self.progress.setPlaceholderText("Progress")
        main_layout.addWidget(self.progress)

        self.output = QTextBrowser()
        self.output.setObjectName("output")
        self.output.setOpenExternalLinks(True)
        self.output.setHtml("")
        main_layout.addWidget(self.output, stretch=1)

        self.input = QTextEdit()
        self.input.setObjectName("input")
        self.input.setFixedHeight(92)
        self.input.setPlaceholderText("Ask anything, or paste a raw email/header here.")
        self.reference_bar = QFrame()
        self.reference_bar.setObjectName("referenceBar")
        self.reference_bar.hide()
        reference_layout = QHBoxLayout(self.reference_bar)
        reference_layout.setContentsMargins(10, 7, 10, 7)
        reference_layout.setSpacing(8)
        self.reference_slots: list[QLabel] = []
        for index in range(3):
            slot = QLabel(f"Email {index + 1}\nNo email selected")
            slot.setObjectName("referenceSlot")
            slot.setProperty("filled", "false")
            slot.setWordWrap(True)
            slot.setMinimumHeight(62)
            slot.setAlignment(Qt.AlignTop | Qt.AlignLeft)
            self.reference_slots.append(slot)
            reference_layout.addWidget(slot, stretch=1)
        clear_reference_button = QPushButton("Clear")
        clear_reference_button.setObjectName("secondaryButton")
        clear_reference_button.clicked.connect(self.clear_referenced_email)
        reference_layout.addWidget(clear_reference_button)
        main_layout.addWidget(self.reference_bar)
        main_layout.addWidget(self.input)

        chat_actions = QHBoxLayout()
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_chat)
        chat_actions.addStretch()
        chat_actions.addWidget(self.send_button)
        main_layout.addLayout(chat_actions)
        layout.addWidget(main, stretch=1)

        for button in panel.findChildren(QPushButton):
            button.setCursor(QCursor(Qt.PointingHandCursor))
            button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        return panel

    def _apply_styles(self) -> None:
        self.setStyleSheet(
            """
            QWidget {
                font-family: Inter, Ubuntu, Arial, sans-serif;
                font-size: 13px;
                color: #17202a;
                selection-background-color: #bfdbfe;
                selection-color: #111827;
            }
            #panel {
                background: #f8fafc;
                border: 1px solid #d8dee9;
                border-radius: 8px;
            }
            #title {
                font-size: 18px;
                font-weight: 700;
            }
            #chatTitle {
                font-size: 17px;
                font-weight: 700;
            }
            #sectionLabel {
                color: #52616f;
                font-size: 12px;
                font-weight: 700;
                margin-top: 8px;
            }
            #status {
                color: #52616f;
            }
            #sidebar {
                background: #eef3f7;
                border: 1px solid #d8dee9;
                border-radius: 8px;
            }
            #sideScroll {
                background: transparent;
                border: 0;
            }
            #referenceBar {
                background: #eef6ff;
                border: 1px solid #60a5fa;
                border-left: 6px solid #2563eb;
                border-radius: 8px;
            }
            #referenceSlot {
                background: #ffffff;
                border: 1px solid #93c5fd;
                border-radius: 8px;
                padding: 7px;
                color: #1e3a8a;
                font-weight: 700;
            }
            #referenceSlot[filled="false"] {
                background: #f8fbff;
                border: 1px dashed #93c5fd;
                color: #64748b;
                font-weight: 600;
            }
            #mailPane {
                background: #f2f6f8;
                border: 1px solid #d8dee9;
                border-radius: 8px;
                padding: 10px;
            }
            QTextEdit {
                background: #ffffff;
                border: 1px solid #ccd4dd;
                border-radius: 8px;
                padding: 8px;
                selection-background-color: #bfdbfe;
                selection-color: #111827;
            }
            QTextBrowser {
                background: #ffffff;
                border: 1px solid #ccd4dd;
                border-radius: 8px;
                padding: 8px;
                selection-background-color: #bfdbfe;
                selection-color: #111827;
            }
            QListWidget {
                background: #ffffff;
                border: 1px solid #ccd4dd;
                border-radius: 8px;
                padding: 6px;
                selection-background-color: #dbeafe;
                selection-color: #111827;
            }
            QListWidget::item {
                border-bottom: 1px solid #edf1f5;
                padding: 8px;
            }
            QListWidget::item:selected {
                background: #d6eef5;
                color: #17202a;
            }
            QComboBox,
            QLineEdit {
                background: #ffffff;
                border: 1px solid #ccd4dd;
                border-radius: 8px;
                padding: 7px 8px;
                selection-background-color: #bfdbfe;
                selection-color: #111827;
            }
            QComboBox QAbstractItemView {
                background: #ffffff;
                color: #17202a;
                selection-background-color: #dbeafe;
                selection-color: #111827;
                outline: 0;
            }
            #output {
                font-family: Ubuntu, Arial, sans-serif;
                font-size: 13px;
            }
            #progress {
                border-radius: 8px;
                font-family: Ubuntu Mono, DejaVu Sans Mono, monospace;
                font-size: 13px;
                font-weight: 700;
            }
            #progress[state="busy"] {
                background: #fff7ed;
                border: 2px solid #f59e0b;
                border-left: 8px solid #d97706;
                color: #92400e;
            }
            #progress[state="success"] {
                background: #ecfdf3;
                border: 2px solid #22c55e;
                border-left: 8px solid #16a34a;
                color: #166534;
            }
            #progress[state="error"] {
                background: #fff1f2;
                border: 2px solid #ef4444;
                border-left: 8px solid #dc2626;
                color: #b91c1c;
            }
            #mailDetail {
                font-family: Ubuntu, Arial, sans-serif;
                font-size: 13px;
            }
            QPushButton {
                background: #16697a;
                color: #ffffff;
                border: 0;
                border-radius: 8px;
                padding: 8px 10px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #0f5260;
            }
            QPushButton:disabled {
                background: #9aa7b2;
            }
            #secondaryButton {
                background: #e9eef3;
                color: #17202a;
            }
            #secondaryButton:hover {
                background: #dbe3ea;
            }
            #dangerQuitButton {
                background: #b91c1c;
            }
            #dangerQuitButton:hover {
                background: #991b1b;
            }
            QCheckBox {
                padding-left: 6px;
            }
            """
        )
        font = QFont()
        font.setPointSize(10)
        self.setFont(font)

    def _place_bottom_right(self) -> None:
        screen = QApplication.primaryScreen()
        if screen is None:
            return
        area = screen.availableGeometry()
        self.move(area.right() - BALL_SIZE - 40, area.bottom() - BALL_SIZE - 40)

    def set_status(self, status: str, text: str) -> None:
        self.ball.set_status(status)
        self.header_ball.set_status(status)
        self.status_label.setText(text)

    def initialize_runtime(self) -> None:
        self._run_agent("", hidden=True, setup_only=True)

    def expand_panel(self) -> None:
        if self.expanded:
            return
        self.expanded = True
        old_geo = self.geometry()
        self.stack.setCurrentWidget(self.panel)
        self._animate_geometry(QRect(old_geo.x(), old_geo.y(), PANEL_SIZE.width(), PANEL_SIZE.height()))

    def collapse_panel(self) -> None:
        if not self.expanded:
            return
        self.expanded = False
        old_geo = self.geometry()
        target = QRect(old_geo.x(), old_geo.y(), BALL_SIZE, BALL_SIZE)
        self._animate_geometry(target, after=lambda: self.stack.setCurrentWidget(self.ball_page))

    def _animate_geometry(self, target: QRect, after=None) -> None:
        animation = QPropertyAnimation(self, b"geometry", self)
        animation.setDuration(180)
        animation.setEasingCurve(QEasingCurve.OutCubic)
        animation.setStartValue(self.geometry())
        animation.setEndValue(target)
        if after is not None:
            animation.finished.connect(after)
        animation.start()
        self._geometry_animation = animation

    def append_progress(self, text: str) -> None:
        self.progress.append(f"- {text}")

    def set_progress_state(self, state: str) -> None:
        self.progress.setProperty("state", state)
        self.progress.style().unpolish(self.progress)
        self.progress.style().polish(self.progress)
        self.progress.update()

    def append_chat_bubble(self, role: str, text: str) -> None:
        escaped = _html_escape_text(text)
        if role == "user":
            html_block = f"""
            <table width="100%" cellspacing="0" cellpadding="0" style="margin-top:10px; margin-bottom:10px;">
              <tr>
                <td width="22%"></td>
                <td align="right">
                  <table cellspacing="0" cellpadding="8" style="background:#dbeafe; border:1px solid #93c5fd; border-radius:8px;">
                    <tr><td style="color:#17202a;"><b>You</b><br>{escaped}</td></tr>
                  </table>
                </td>
                <td width="34" align="right" style="color:white; background:#2563eb; font-weight:bold;">Y</td>
              </tr>
            </table>
            """
        elif role == "assistant":
            html_block = f"""
            <table width="100%" cellspacing="0" cellpadding="0" style="margin-top:10px; margin-bottom:10px;">
              <tr>
                <td width="34" align="center" style="color:white; background:#166534; font-weight:bold;">AI</td>
                <td align="left">
                  <table cellspacing="0" cellpadding="8" style="background:#ecfdf3; border:1px solid #86efac; border-radius:8px;">
                    <tr><td style="color:#17202a;"><b>Guardian</b><br>{escaped}</td></tr>
                  </table>
                </td>
                <td width="22%"></td>
              </tr>
            </table>
            """
        elif role == "error":
            html_block = f"""
            <table width="100%" cellspacing="0" cellpadding="0" style="margin-top:10px; margin-bottom:10px;">
              <tr>
                <td width="34" align="center" style="color:white; background:#b91c1c; font-weight:bold;">!</td>
                <td align="left">
                  <table cellspacing="0" cellpadding="8" style="background:#fff1f2; border:1px solid #fca5a5; border-radius:8px;">
                    <tr><td style="color:#7f1d1d;"><b>Error</b><br>{escaped}</td></tr>
                  </table>
                </td>
                <td width="22%"></td>
              </tr>
            </table>
            """
        else:
            html_block = f"""
            <table width="100%" cellspacing="0" cellpadding="0" style="margin-top:10px; margin-bottom:10px;">
              <tr>
                <td width="20%"></td>
                <td align="center" style="background:#eef3f7; color:#52616f; border:1px solid #d8dee9;">
                  {escaped}
                </td>
                <td width="20%"></td>
              </tr>
            </table>
            """
        cursor = self.output.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertHtml(html_block)
        cursor.insertBlock()
        self.output.verticalScrollBar().setValue(self.output.verticalScrollBar().maximum())

    def show_chat_view(self) -> None:
        self.mail_panel.hide()

    def show_mail_view(self) -> None:
        self.mail_panel.show()

    def show_selected_email(self, current: QListWidgetItem | None, _previous: QListWidgetItem | None) -> None:
        if current is None:
            return
        data = current.data(Qt.UserRole)
        if not isinstance(data, dict):
            return
        self.mail_detail.setPlainText(
            "\n".join(
                [
                    str(data.get("subject", "(no subject)")),
                    "",
                    f"From: {data.get('from', 'unknown')}",
                    f"Date: {data.get('date', 'unknown date')}",
                    "",
                    str(data.get("full_text", "")),
                ]
            )
        )

    def quote_selected_email_to_chat(self) -> None:
        selected_items = self.mail_list.selectedItems()
        if not selected_items:
            current = self.mail_list.currentItem()
            selected_items = [current] if current is not None else []
        if not selected_items:
            QMessageBox.information(self, "Choose email", "Choose up to 3 emails from the mailbox list first.")
            return
        candidates: list[dict[str, str]] = []
        for item in selected_items:
            data = item.data(Qt.UserRole)
            if not isinstance(data, dict):
                continue
            candidates.append(
                {
                    "subject": str(data.get("subject", "(no subject)")),
                    "from": str(data.get("from", "unknown")),
                    "date": str(data.get("date", "unknown date")),
                    "full_text": str(data.get("full_text", "")),
                }
            )
        if not candidates:
            QMessageBox.information(self, "Choose email", "The selected emails could not be read.")
            return

        added = 0
        existing_keys = {
            (item["subject"], item["from"], item["date"])
            for item in self.referenced_emails
        }
        for item in candidates:
            if len(self.referenced_emails) >= 3:
                break
            key = (item["subject"], item["from"], item["date"])
            if key in existing_keys:
                continue
            self.referenced_emails.append(item)
            existing_keys.add(key)
            added += 1

        if added == 0 and len(self.referenced_emails) >= 3:
            QMessageBox.information(self, "Email limit", "You already have 3 referenced emails. Clear them before adding more.")
        elif added == 0:
            QMessageBox.information(self, "Already referenced", "The selected email is already referenced.")
        elif len(candidates) > added:
            QMessageBox.information(self, "Email limit", "Only 3 emails can be referenced. Extra selections were ignored.")

        self.update_reference_slots()
        self.reference_bar.show()
        if not self.input.toPlainText().strip():
            self.input.setPlainText("Analyze the referenced emails.")

    def update_reference_slots(self) -> None:
        for index, slot in enumerate(self.reference_slots):
            if index < len(self.referenced_emails):
                item = self.referenced_emails[index]
                slot.setText(
                    "\n".join(
                        [
                            f"Email {index + 1}",
                            item["subject"],
                            item["from"],
                        ]
                    )
                )
                slot.setProperty("filled", "true")
            else:
                slot.setText(f"Email {index + 1}\nNo email selected")
                slot.setProperty("filled", "false")
            slot.style().unpolish(slot)
            slot.style().polish(slot)
            slot.show()

    def clear_referenced_email(self) -> None:
        self.referenced_emails = []
        self.update_reference_slots()
        self.reference_bar.hide()

    def refresh_mailboxes(self) -> None:
        self._run_mailbox_action("list")

    def bind_mailbox(self) -> None:
        email_address = self.bind_email_input.text().strip()
        app_password = self.bind_password_input.text().strip()
        if not email_address or not app_password:
            QMessageBox.information(self, "Bind mailbox", "Enter an email address and IMAP/app password first.")
            return
        self._run_mailbox_action(
            "bind",
            bind_payload={
                "email_address": email_address,
                "username": self.bind_username_input.text().strip(),
                "app_password": app_password,
                "imap_host": self.bind_host_input.text().strip() or "imap.gmail.com",
                "imap_port": 993,
                "folder": self.bind_folder_input.text().strip() or "INBOX",
            },
        )

    def selected_mailbox(self) -> str:
        return self.mailbox_combo.currentText().strip()

    def show_latest_mail(self) -> None:
        email_address = self.selected_mailbox()
        if not email_address:
            QMessageBox.information(self, "Mailbox", "Bind or choose a mailbox first.")
            return
        self.loaded_email_count = 0
        self.mail_list.clear()
        self.mail_detail.clear()
        self.show_mail_view()
        self._run_mailbox_action("fetch", email_address=email_address, offset=0, limit=EMAIL_PAGE_SIZE)

    def load_more_mail(self) -> None:
        email_address = self.selected_mailbox()
        if not email_address:
            QMessageBox.information(self, "Mailbox", "Bind or choose a mailbox first.")
            return
        self.show_mail_view()
        self._run_mailbox_action(
            "fetch",
            email_address=email_address,
            offset=self.loaded_email_count,
            limit=EMAIL_PAGE_SIZE,
        )

    def _run_mailbox_action(
        self,
        action: str,
        *,
        email_address: str = "",
        offset: int = 0,
        limit: int = EMAIL_PAGE_SIZE,
        bind_payload: dict[str, Any] | None = None,
    ) -> None:
        if self.mail_thread is not None:
            QMessageBox.information(self, "Busy", "Mailbox operation is still running.")
            return
        self.progress.clear()
        self.set_progress_state("busy")
        self.set_status("busy", "Mailbox working")
        self.mail_thread = QThread()
        self.mail_worker = MailboxWorker(
            action=action,
            email_address=email_address,
            offset=offset,
            limit=limit,
            bind_payload=bind_payload,
        )
        self.mail_worker.moveToThread(self.mail_thread)
        self.mail_thread.started.connect(self.mail_worker.run)
        self.mail_worker.progress.connect(self.append_progress)
        self.mail_worker.mailboxes_ready.connect(self._mailboxes_ready)
        self.mail_worker.emails_ready.connect(self._emails_ready)
        self.mail_worker.bound.connect(self._mailbox_bound)
        self.mail_worker.failed.connect(self._mailbox_failed)
        self.mail_worker.finished.connect(self.mail_worker.deleteLater)
        self.mail_worker.finished.connect(self.mail_thread.quit)
        self.mail_thread.finished.connect(self._mail_thread_finished)
        self.mail_thread.finished.connect(self.mail_thread.deleteLater)
        self.mail_thread.start()

    def _mailboxes_ready(self, mailboxes: object) -> None:
        current = self.selected_mailbox()
        self.mailbox_combo.clear()
        for email_address in mailboxes if isinstance(mailboxes, list) else []:
            self.mailbox_combo.addItem(str(email_address))
        if current:
            index = self.mailbox_combo.findText(current)
            if index >= 0:
                self.mailbox_combo.setCurrentIndex(index)
        self.append_progress(f"Loaded {self.mailbox_combo.count()} bound mailbox bindings")

    def _mailbox_bound(self, email_address: str) -> None:
        self.bind_password_input.clear()
        self.append_progress(f"Bound mailbox: {email_address}")
        index = self.mailbox_combo.findText(email_address)
        if index < 0:
            self.mailbox_combo.addItem(email_address)
            index = self.mailbox_combo.findText(email_address)
        if index >= 0:
            self.mailbox_combo.setCurrentIndex(index)

    def _emails_ready(self, email_address: str, offset: int, rows: object) -> None:
        if offset == 0:
            self.mail_list.clear()
            self.mail_detail.clear()
            self.loaded_email_count = 0
        items = rows if isinstance(rows, list) else []
        for index, item in enumerate(items, offset + 1):
            if not isinstance(item, dict):
                continue
            list_item = QListWidgetItem(
                "\n".join(
                    [
                        f"{index}. {item.get('subject', '(no subject)')}",
                        f"From {item.get('from', 'unknown')}",
                        f"{item.get('date', 'unknown date')}",
                        str(item.get("preview", "")),
                    ]
                )
            )
            list_item.setData(Qt.UserRole, item)
            self.mail_list.addItem(list_item)
        self.loaded_email_count = offset + len(items)
        if not items:
            self.mail_detail.setPlainText("No more messages.")
        elif offset == 0 and self.mail_list.count() > 0:
            self.mail_list.setCurrentRow(0)
        self.mailbox_status_label.setText(
            f"{email_address}: loaded {self.loaded_email_count} messages. Use Load 10 More to continue."
        )
        self.show_mail_view()

    def _mailbox_failed(self, text: str) -> None:
        self.set_progress_state("error")
        self.set_status("error", "Mailbox error")
        self.mailbox_status_label.setText(text)
        self.mail_detail.setPlainText(f"Mailbox request failed.\nReason: {text}\n")
        self.show_mail_view()

    def _mail_thread_finished(self) -> None:
        self.mail_thread = None
        self.mail_worker = None
        if self.status_label.text() == "Mailbox working":
            self.set_progress_state("success")
            self.set_status("ready", f"Ready: {self.args.provider} / {self.args.model}")

    def update_model_default(self, provider: str) -> None:
        self.model_input.setText(resolve_default_model(provider))

    def switch_model(self) -> None:
        if self.thread is not None:
            QMessageBox.information(self, "Busy", "Wait for the current request to finish before switching models.")
            return

        provider = self.provider_combo.currentText().strip()
        model = self.model_input.text().strip()
        if provider not in {"gemini", "ollama"}:
            QMessageBox.warning(self, "Invalid provider", "Choose gemini or ollama.")
            return
        if not model:
            QMessageBox.warning(self, "Missing model", "Enter a model name before switching.")
            return

        self.args.provider = provider
        self.args.model = model
        self.runtime = None
        self.progress.clear()
        self.set_progress_state("busy")
        self.append_progress(f"Switching to {provider} / {model}")
        self.set_status("starting", "Starting")
        self.initialize_runtime()

    def send_chat(self) -> None:
        prompt = self.input.toPlainText().strip()
        if not prompt:
            return
        self.input.clear()
        prompt_to_send = prompt
        prefer_ai_response = False
        if self.referenced_emails:
            prompt_to_send = build_referenced_email_prompt(prompt, self.referenced_emails)
            prefer_ai_response = True
            self.clear_referenced_email()
        self._run_agent(prompt_to_send, display_prompt=prompt, prefer_ai_response=prefer_ai_response)

    def run_sample(self) -> None:
        prompt = build_analysis_prompt(
            "Analyze this email and decide whether it is benign, suspicious, spam, or phishing.",
            raw_email=DEFAULT_EMAIL,
        )
        self._run_agent(prompt)

    def run_email_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose raw email file", str(PROJECT_ROOT))
        if not path:
            return
        try:
            raw_email = read_text_file(path)
        except OSError as exc:
            QMessageBox.warning(self, "Could not read file", str(exc))
            return
        prompt = build_analysis_prompt(
            "Analyze this email and decide whether it is benign, suspicious, spam, or phishing.",
            raw_email=raw_email,
        )
        self._run_agent(prompt)

    def run_headers_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose headers file", str(PROJECT_ROOT))
        if not path:
            return
        try:
            raw_headers = read_text_file(path)
        except OSError as exc:
            QMessageBox.warning(self, "Could not read file", str(exc))
            return
        prompt = build_analysis_prompt(
            "Analyze these headers for SPF, DKIM, DMARC, ARC, routing anomalies, and sender-domain mismatches.",
            raw_headers=raw_headers,
        )
        self._run_agent(prompt)

    def run_pasted_email(self) -> None:
        raw_email = self.input.toPlainText().strip()
        if not raw_email:
            QMessageBox.information(self, "Paste email", "Paste a raw RFC822 email into the input box first.")
            return
        self.input.clear()
        prompt = build_analysis_prompt(
            "Analyze this email and decide whether it is benign, suspicious, spam, or phishing.",
            raw_email=raw_email,
        )
        self._run_agent(prompt)

    def run_pasted_headers(self) -> None:
        raw_headers = self.input.toPlainText().strip()
        if not raw_headers:
            QMessageBox.information(self, "Paste headers", "Paste raw headers into the input box first.")
            return
        self.input.clear()
        prompt = build_analysis_prompt(
            "Analyze these headers for SPF, DKIM, DMARC, ARC, routing anomalies, and sender-domain mismatches.",
            raw_headers=raw_headers,
        )
        self._run_agent(prompt)

    def reset_chat(self) -> None:
        if self.runtime is not None:
            self.runtime.reset()
        self.output.clear()
        self.progress.clear()
        self.set_progress_state("success")
        self.append_progress("Conversation history cleared")

    def show_help(self) -> None:
        self.append_chat_bubble("system", HELP_TEXT)

    def _run_agent(
        self,
        prompt: str,
        *,
        hidden: bool = False,
        setup_only: bool = False,
        display_prompt: str | None = None,
        prefer_ai_response: bool = False,
    ) -> None:
        if self.thread is not None:
            QMessageBox.information(self, "Busy", "Email Guardian is still working on the current request.")
            return

        self.set_status("busy", "Working")
        self.send_button.setEnabled(False)
        if not hidden:
            self.append_chat_bubble("user", display_prompt if display_prompt is not None else prompt)
        self.progress.clear()
        self.set_progress_state("busy")

        self.thread = QThread()
        self.worker = AgentWorker(
            provider=self.args.provider,
            model=self.args.model,
            rspamd_base_url=self.args.base_url,
            ollama_base_url=self.args.ollama_base_url,
            prompt=prompt,
            reset=False,
            trace=self.trace_check.isChecked(),
            runtime=self.runtime,
            setup_only=setup_only,
            prefer_ai_response=prefer_ai_response,
        )
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.ready.connect(self._runtime_ready_text)
        self.worker.progress.connect(self.append_progress)
        if hidden:
            self.worker.result.connect(lambda _text: None)
        else:
            self.worker.result.connect(self._append_result)
        self.worker.failed.connect(self._show_failure)
        self.worker.finished.connect(self._worker_finished)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.finished.connect(self.thread.quit)
        self.thread.finished.connect(self._thread_finished)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    def _runtime_ready_text(self, text: str) -> None:
        self.set_status("ready", f"Ready: {text}")

    def _append_result(self, text: str) -> None:
        if text.startswith("Request failed."):
            self.set_progress_state("error")
            self.set_status("error", "Error")
        else:
            self.set_progress_state("success")
        self.append_chat_bubble("assistant", text)

    def _show_failure(self, text: str) -> None:
        self.set_progress_state("error")
        self.set_status("error", "Error")
        self.append_chat_bubble("error", f"Request failed.\nReason: {text}")

    def _worker_finished(self) -> None:
        if self.worker and self.worker.updated_runtime is not None:
            self.runtime = self.worker.updated_runtime
        self.send_button.setEnabled(True)
        if self.status_label.text() == "Working":
            if self.progress.property("state") != "error":
                self.set_progress_state("success")
            self.set_status("ready", f"Ready: {self.args.provider} / {self.args.model}")

    def _thread_finished(self) -> None:
        self.thread = None
        self.worker = None

    def _drain_worker_threads(self, timeout_ms: int = 2500) -> None:
        if self.thread is not None:
            self.thread.quit()
            self.thread.wait(timeout_ms)
        if self.mail_thread is not None:
            self.mail_thread.quit()
            self.mail_thread.wait(timeout_ms)

    def _full_shutdown_cleanup(self) -> None:
        self._drain_worker_threads(3000)
        terminate_stack_child_pids_from_env()
        terminate_own_subprocesses()

    def confirm_quit_all(self) -> None:
        msg = QMessageBox(self)
        msg.setWindowTitle("Confirm exit")
        msg.setIcon(QMessageBox.Warning)
        msg.setText("Quit Email Guardian?")
        lines = [
            "This closes the window and terminates child processes started by this app "
            "(for example Python processes backing MCP tools).",
        ]
        if os.environ.get("EMAIL_AGENT_STACK_CHILD_PIDS", "").strip():
            lines.append(
                "Launch script PIDs were detected: exiting will also send SIGTERM to those "
                "background services (mock Rspamd / ollama serve, etc.)."
            )
        else:
            lines.append(
                "No launch-script PIDs were registered. If you started Rspamd or Ollama separately, "
                "stop those services yourself."
            )
        lines.append(
            "This does not stop system-wide redis-server or rspamd services managed by systemd."
        )
        msg.setInformativeText("\n".join(lines))
        yes_btn = msg.addButton("Quit and shut down all", QMessageBox.AcceptRole)
        msg.addButton("Cancel", QMessageBox.RejectRole)
        msg.exec()
        if msg.clickedButton() != yes_btn:
            return
        self._shutting_down = True
        self._full_shutdown_cleanup()
        app = QApplication.instance()
        if app is not None:
            app.quit()

    def closeEvent(self, event) -> None:  # type: ignore[override]
        if self._shutting_down:
            event.accept()
            return
        self._shutting_down = True
        self._full_shutdown_cleanup()
        event.accept()


def parse_args() -> argparse.Namespace:
    load_local_env(PROJECT_ROOT)
    default_provider = resolve_provider()
    parser = argparse.ArgumentParser(description="Run Email Guardian as a desktop pet.")
    parser.add_argument("--provider", default=default_provider, choices=["ollama", "gemini"])
    parser.add_argument("--model", default=resolve_default_model(default_provider))
    parser.add_argument("--ollama-base-url", default=os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434"))
    parser.add_argument("--base-url", default=os.getenv("RSPAMD_BASE_URL", "http://127.0.0.1:11333"))
    return parser.parse_args()


def main() -> int:
    configure_quiet_logging()
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(True)
    window = PetWindow(parse_args())
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

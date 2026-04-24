from __future__ import annotations

import argparse
import asyncio
import csv
import html
import json
import os
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import (
    QEasingCurve,
    QObject,
    QPoint,
    QPropertyAnimation,
    QRect,
    QRectF,
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
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QScrollArea,
    QAbstractItemView,
    QSizePolicy,
    QSpinBox,
    QStackedWidget,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

from examples.model_factory import build_chat_model, resolve_default_model, resolve_provider
from harness.prompts import DEFAULT_EMAIL, HELP_TEXT, build_analysis_prompt
from harness.runtime import (
    EmailAgentRuntime,
    is_quota_error,
    latest_ai_message,
    render_content,
    summarize_invoked_tools,
    summarize_tool_messages,
)
from harness.ui import (
    _friendly_email_type,
    _required_decision_label,
    configure_quiet_logging,
    render_chat_response,
    render_error,
    render_trace,
)
from skills.error_patterns.schemas import ErrorPatternMemoryCheckInput, ListErrorPatternsInput
from skills.error_patterns.skill import ErrorPatternMemoryCheckSkill, ListErrorPatternsSkill
from skills.header_auth.schemas import EmailHeaderAuthCheckInput
from skills.header_auth.skill import EmailHeaderAuthCheckSkill
from skills.content_model.schemas import ContentModelCheckInput
from skills.content_model.skill import ContentModelCheckSkill
from skills.rspamd.schemas import RspamdScanEmailInput
from skills.rspamd.skill import RspamdScanEmailSkill
from skills.scam_indicators.schemas import ScamIndicatorCheckInput
from skills.scam_indicators.skill import ScamIndicatorCheckSkill
from skills.spam_campaign.schemas import SpamCampaignCheckInput
from skills.spam_campaign.skill import SpamCampaignCheckSkill
from skills.urgency.schemas import UrgencyCheckInput
from skills.urgency.skill import UrgencyCheckSkill
from skills.url_reputation.schemas import UrlReputationInput
from skills.url_reputation.skill import UrlReputationSkill
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
PUTER_PROVIDER = "puter-openai"
TOKENROUTER_PROVIDER = "tokenrouter"
TOKENROUTER_MODELS = [
    "openai/gpt-5-mini",
    "openai/gpt-5.4",
    "anthropic/claude-haiku-4.5",
]
PUTER_WEB_PORT = 8765
PUTER_BRIDGE_LOG = "/tmp/email_agent_puter_bridge.log"
DEVELOPER_RUNS_DIR = PROJECT_ROOT / "dataset" / "reports" / "developer_runs"
DEVELOPER_SLOT_COUNT = 4

csv.field_size_limit(sys.maxsize)


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


def _desktop_model_default(provider: str) -> str:
    if provider == PUTER_PROVIDER:
        return "gpt-5.4"
    if provider == TOKENROUTER_PROVIDER:
        return TOKENROUTER_MODELS[0]
    return resolve_default_model(provider)


def _format_dev_timestamp(value: float | None) -> str:
    if value is None:
        return "n/a"
    return time.strftime("%H:%M:%S", time.localtime(value))


def _format_dev_duration(seconds: float | None) -> str:
    if seconds is None or seconds < 0:
        return "n/a"
    total = int(seconds)
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def _model_selector_text(widget: Any) -> str:
    if isinstance(widget, QComboBox):
        return widget.currentText().strip()
    if isinstance(widget, QLineEdit):
        return widget.text().strip()
    return str(widget).strip()


def _set_model_selector_text(widget: Any, value: str) -> None:
    if isinstance(widget, QComboBox):
        if widget.isEditable():
            widget.setEditText(value)
        else:
            idx = widget.findText(value)
            if idx >= 0:
                widget.setCurrentIndex(idx)
            elif widget.count():
                widget.setCurrentIndex(0)
        return
    if isinstance(widget, QLineEdit):
        widget.setText(value)


def _developer_dashboard_model_label(provider: str, model: str) -> str:
    provider = (provider or "").strip().lower()
    model = (model or "").strip()
    model_key = model.lower()
    if provider == "ollama" and model_key.startswith("qwen3"):
        return "Qwen3 Local"
    if model_key == "openai/gpt-5-mini":
        return "GPT-5 Mini"
    if model_key == "openai/gpt-5.4":
        return "GPT-5.4"
    if model_key == "anthropic/claude-haiku-4.5":
        return "Claude Haiku 4.5"
    if "/" in model:
        return model.split("/", 1)[1]
    return model or provider or "Unknown"


def _developer_export_dashboard_image(runs: list[dict[str, Any]], out_path: Path) -> Path:
    if len(runs) < 2:
        raise ValueError("At least 2 finished tests are required to generate a dashboard.")
    exporter = PROJECT_ROOT / "tools" / "export_developer_dashboard.py"
    if not exporter.exists():
        raise FileNotFoundError(f"Dashboard exporter script not found: {exporter}")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload_path = DEVELOPER_RUNS_DIR / "_dashboard_export_payload.json"
    payload_path.write_text(json.dumps(runs, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        proc = subprocess.run(
            ["/usr/bin/python3", str(exporter), "--input", str(payload_path), "--output", str(out_path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
    finally:
        try:
            payload_path.unlink(missing_ok=True)
        except OSError:
            pass
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        message = stderr or stdout or "Unknown export error."
        raise RuntimeError(message)
    return out_path


def _configure_model_selector(widget: QComboBox, provider: str, selected: str = "") -> None:
    current = selected.strip() or _model_selector_text(widget) or _desktop_model_default(provider)
    widget.blockSignals(True)
    widget.clear()
    if provider == TOKENROUTER_PROVIDER:
        widget.setEditable(False)
        for model_name in TOKENROUTER_MODELS:
            widget.addItem(model_name)
        idx = widget.findText(current)
        widget.setCurrentIndex(idx if idx >= 0 else 0)
    else:
        widget.setEditable(True)
        widget.addItem(current)
        widget.setCurrentText(current)
    widget.blockSignals(False)


def _port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.25)
        return sock.connect_ex((host, port)) == 0


def _wait_for_port(host: str, port: int, timeout_s: float = 10.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _port_open(host, port):
            return True
        time.sleep(0.1)
    return False


class PuterBridgeController(QObject):
    ready = Signal()
    chunk = Signal(int, str, str)
    completed = Signal(int, str)
    failed = Signal(int, str)
    auth_required = Signal(int, str)

    def __init__(self, bridge_url: str, profile=None, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._bridge_url = bridge_url
        self._profile = profile
        self._page = None
        self._ready = False
        self._pending_submission: tuple[list[dict[str, str]], str, int] | None = None

    @property
    def is_ready(self) -> bool:
        return self._ready

    def ensure_loaded(self) -> None:
        if self._page is not None:
            return

        try:
            from PySide6.QtCore import QUrl
            from PySide6.QtWebEngineCore import QWebEnginePage
            from PySide6.QtWebEngineCore import QWebEngineSettings
        except Exception as exc:
            self.failed.emit(0, f"Qt WebEngine is unavailable: {exc}")
            return

        controller = self

        class _BridgePage(QWebEnginePage):
            def javaScriptConsoleMessage(self, level, message, line_number, source_id):  # type: ignore[override]
                del level, line_number, source_id
                controller._handle_console_message(message)

        if self._profile is not None:
            self._page = _BridgePage(self._profile, self)
        else:
            self._page = _BridgePage(self)
        self._page.settings().setAttribute(
            QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls,
            True,
        )
        self._page.load(QUrl(self._bridge_url))

    def reload(self) -> None:
        self._ready = False
        self._pending_submission = None
        if self._page is not None:
            self._page.triggerAction(self._page.WebAction.ReloadAndBypassCache)

    def submit(self, messages: list[dict[str, str]], model: str, request_id: int) -> None:
        self.ensure_loaded()
        if self._page is None:
            return
        if not self._ready:
            self._pending_submission = (messages, model, request_id)
            return
        payload = {
            "messages": messages,
            "model": model,
            "request_id": request_id,
        }
        script = f"window.__puterBridgeSubmit({json.dumps(payload)});"
        self._page.runJavaScript(script)

    def sign_out(self) -> None:
        self.ensure_loaded()
        if self._page is None:
            return
        script = """
        (async () => {
          try {
            if (window.puter && window.puter.auth && typeof window.puter.auth.signOut === "function") {
              await window.puter.auth.signOut();
            }
          } catch (_error) {}
          try { window.localStorage.clear(); } catch (_error) {}
          try { window.sessionStorage.clear(); } catch (_error) {}
          if (window.indexedDB && typeof window.indexedDB.databases === "function") {
            try {
              const databases = await window.indexedDB.databases();
              for (const db of databases) {
                if (db && db.name) {
                  window.indexedDB.deleteDatabase(db.name);
                }
              }
            } catch (_error) {}
          }
        })();
        """
        self._page.runJavaScript(script)

    def _handle_console_message(self, message: str) -> None:
        prefix = "__PUTER_EVENT__"
        if not message.startswith(prefix):
            return
        try:
            payload = json.loads(message[len(prefix):])
        except json.JSONDecodeError:
            return
        event_type = str(payload.get("type", ""))
        request_id = int(payload.get("request_id", 0) or 0)
        if event_type == "ready":
            self._ready = True
            self.ready.emit()
            if self._pending_submission is not None:
                messages, model, pending_request_id = self._pending_submission
                self._pending_submission = None
                self.submit(messages, model, pending_request_id)
            return
        if event_type == "chunk":
            self.chunk.emit(
                request_id,
                str(payload.get("text", "")),
                str(payload.get("full_text", "")),
            )
            return
        if event_type == "complete":
            self.completed.emit(request_id, str(payload.get("text", "")))
            return
        if event_type == "auth_required":
            self.auth_required.emit(request_id, str(payload.get("message", "ChatGPT login required")))
            return
        if event_type == "error":
            self.failed.emit(request_id, str(payload.get("message", "Unknown ChatGPT error")))


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
    rendered_lines: list[str] = []
    for raw_line in text.splitlines():
        escaped = html.escape(raw_line)
        stripped = raw_line.strip()
        if stripped.lower().startswith("verdict:"):
            if "normal" in stripped.lower() or "benign" in stripped.lower():
                color = "#15803d"
            elif "phishing" in stripped.lower():
                color = "#b91c1c"
            elif "spam" in stripped.lower():
                color = "#b45309"
            else:
                color = "#374151"
            escaped = f'<span style="color:{color}; font-weight:bold;">{escaped}</span>'
        rendered_lines.append(escaped)
    return "<br>".join(rendered_lines)


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
    raw_email = raw_bytes.decode("utf-8", errors="replace")
    return {
        "subject": str(parsed.get("Subject") or "(no subject)"),
        "from": str(parsed.get("From") or "unknown"),
        "date": str(parsed.get("Date") or "unknown date"),
        "preview": _compact_mail_text(full_text, limit=160),
        "full_text": full_text or "(No readable plain text body.)",
        "raw_email": raw_email,
    }


def _fetch_raw_email_reference(email_address: str, uid_text: str) -> dict[str, str]:
    if not email_address:
        raise RuntimeError("Referenced email is missing its mailbox address")
    if not uid_text:
        raise RuntimeError("Referenced email is missing its IMAP UID")
    mailbox = get_mailbox(email_address)
    if mailbox is None:
        raise RuntimeError(f"Mailbox {email_address} is not bound")

    client = _connect_imap(mailbox)
    try:
        raw_bytes = _fetch_message_bytes(client, int(uid_text))
        item = _message_preview(raw_bytes)
        item["email_address"] = email_address
        item["uid"] = str(uid_text)
        return item
    finally:
        try:
            client.logout()
        except Exception:
            pass


def resolve_referenced_email_originals(referenced_emails: list[dict[str, str]]) -> list[dict[str, str]]:
    resolved: list[dict[str, str]] = []
    for item in referenced_emails:
        email_address = str(item.get("email_address") or "")
        uid_text = str(item.get("uid") or "")
        if email_address and uid_text:
            resolved.append(_fetch_raw_email_reference(email_address, uid_text))
            continue
        if item.get("raw_email"):
            resolved.append(item)
            continue
        raise RuntimeError(f"Referenced email {item.get('subject', '(no subject)')} cannot be fetched from IMAP")
    return resolved


def build_referenced_email_prompt(question: str, referenced_emails: list[dict[str, str]]) -> str:
    if len(referenced_emails) == 1:
        item = referenced_emails[0]
        raw_email = str(item.get("raw_email") or "").strip()
        if not raw_email:
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
            + "\nWorkflow: first call rspamd_scan_email with raw_email. If the Rspamd score is greater than 7, choose any additional relevant MCP tools before the final verdict."
            + "\nUse the short four-part template: Email, Type, Verdict, Evidence. "
            "The Verdict line must be exactly one of Normal, Spam, Phishing. "
            "Call rspamd_scan_email with raw_email equal to the complete raw RFC822 block; do not pass a summary, body-only text, JSON object, extracted fields, or email_text to rspamd_scan_email. "
            "Use email_text only for url_reputation_check and urgency_check. "
            "When extra checks are needed, prefer URL reputation, urgency, header authentication, and error-pattern memory. "
            "Use header authentication only if you can pass the complete raw RFC822 block as a string. "
            "Keep it brief unless the user asks for more detail.",
            raw_email=f"BEGIN RAW RFC822\n{raw_email}\nEND RAW RFC822",
        )

    sections = [
        question,
        "Workflow: for each raw RFC822 email, first call rspamd_scan_email. If its Rspamd score is greater than 7, choose any additional relevant MCP tools before the final verdict.",
        "There are multiple referenced emails below. Do not treat them as one combined email.",
        "Analyze each referenced email separately for phishing, spam, sender authenticity, urgency, and suspicious links.",
        "Your final answer must contain one short labeled section per email: Email 1, Email 2, Email 3 as applicable.",
        "For each email, use exactly this template:",
        "Email: <subject or short name>",
        "Type: <business/school/recruiting/financial/account security/delivery/marketing/general notification/etc.>",
        "Verdict: <Normal | Spam | Phishing>",
        "Why this conclusion:",
        "- <plain-language reason a non-technical user can understand>",
        "- <another short reason if needed>",
        "The Verdict line must choose exactly one of Normal, Spam, Phishing.",
        "Call rspamd_scan_email with raw_email equal to the complete raw RFC822 block; do not pass a summary, body-only text, JSON object, extracted fields, or email_text to rspamd_scan_email.",
        "Use email_text only for url_reputation_check and urgency_check.",
        "When extra checks are needed, prefer URL reputation, urgency, header authentication, and error-pattern memory.",
        "Use header authentication only if you can pass the complete raw RFC822 block as a string.",
        "Keep the answer brief. Do not write a long security report unless the user asks follow-up questions.",
        "Only mention tools/skills that were actually called or are available locally.",
        "If tools are unavailable or only one tool runs, still provide a plain-language assessment for every referenced email from the visible content.",
    ]
    for index, item in enumerate(referenced_emails, 1):
        raw_email = str(item.get("raw_email") or "").strip()
        if not raw_email:
            raw_email = "\n".join(
                [
                    f"From: {item.get('from', 'unknown')}",
                    f"Date: {item.get('date', 'unknown date')}",
                    f"Subject: {item.get('subject', '(no subject)')}",
                    "",
                    str(item.get("full_text", "")),
                ]
            )
        sections.extend(
            [
                "",
                f"Referenced email {index}:",
                "BEGIN RAW RFC822",
                raw_email,
                "END RAW RFC822",
            ]
        )
    return "\n".join(sections)


def _skill_error_text(name: str, result: Any) -> str:
    error = getattr(result, "error", None)
    message = getattr(error, "message", None) if error is not None else None
    return f"{name} failed: {message or 'unknown error'}"


def _looks_like_raw_email_input(text: str) -> bool:
    lowered = text.lower()
    has_header = bool(re.search(r"(?im)^(from|subject|date|to|return-path|message-id):\s+.", text))
    has_body_marker = any(token in lowered for token in ("unsubscribe", "view in browser", "<html", "<table", "http://", "https://"))
    return has_header and has_body_marker


def _email_item_from_raw_text(raw_email: str) -> dict[str, str]:
    parsed = BytesParser(policy=policy.default).parsebytes(raw_email.encode("utf-8", errors="replace"))
    return {
        "subject": str(parsed.get("Subject") or "(pasted email)"),
        "from": str(parsed.get("From") or "unknown"),
        "date": str(parsed.get("Date") or "unknown date"),
        "full_text": _mail_body_text(raw_email.encode("utf-8", errors="replace")),
        "raw_email": raw_email,
    }


def _extra_checks_strongly_benign(
    header_data: dict[str, Any],
    url_data: dict[str, Any],
    urgency_data: dict[str, Any],
    memory_data: dict[str, Any],
) -> bool:
    header_risk = str(header_data.get("risk_level") or "").lower()
    url_risk = str(url_data.get("risk_level") or "").lower()
    urgency_risk = str(urgency_data.get("risk_contribution") or "").lower()
    urgency_label = str(urgency_data.get("urgency_label") or "").lower()
    return (
        header_risk in {"", "low", "unknown", "n/a"}
        and url_risk in {"", "low", "unknown"}
        and not bool(url_data.get("is_suspicious"))
        and urgency_risk in {"", "low", "unknown"}
        and urgency_label in {"", "not urgent", "unknown"}
        and not bool(memory_data.get("matched"))
    )


def _developer_routed_skills(
    *,
    rspamd_data: dict[str, Any],
    subject: str,
    from_address: str,
    email_text: str,
) -> list[str]:
    recommended = [str(item) for item in (rspamd_data.get("recommended_next_skills") or []) if item]
    text = f"{subject} {from_address} {email_text}".lower()
    categories = {str(item).lower() for item in (rspamd_data.get("categories") or [])}
    score = float(rspamd_data.get("score") or 0.0)

    if any(
        token in text
        for token in (
            "mailbox",
            "account",
            "verification",
            "verify",
            "password",
            "help desk",
            "suspension",
            "suspended",
            "security alert",
            "unusual activity",
            "usaa",
            "american express",
        )
    ):
        recommended.extend(
            [
                "email_header_auth_check",
                "scam_indicator_check",
                "url_reputation_check",
                "urgency_check",
            ]
        )

    if score >= 7:
        recommended.extend(
            [
                "content_model_check",
                "email_header_auth_check",
                "scam_indicator_check",
                "spam_campaign_check",
                "url_reputation_check",
                "urgency_check",
                "list_error_patterns",
            ]
        )
    if score >= 10 or categories & {"phishing", "spoofing", "suspicious_links"}:
        recommended.append("error_pattern_memory_check")
    if email_text.strip():
        recommended.insert(0, "content_model_check")

    seen: set[str] = set()
    ordered: list[str] = []
    for item in recommended:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def _developer_dataset_paths() -> list[Path]:
    processed = PROJECT_ROOT / "dataset" / "processed"
    preferred = [
        processed / "spam_binary_test_4source_all.csv",
        processed / "spam_binary_test_modern_sources.csv",
        processed / "spam_binary_test_all_sources_latest.csv",
    ]
    return [path for path in preferred if path.exists()]


def _developer_dataset_summary(path: Path) -> dict[str, Any]:
    sources: set[str] = set()
    labels: set[str] = set()
    row_count = 0
    with path.open(newline="", encoding="utf-8", errors="ignore") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        for row in reader:
            row_count += 1
            if row.get("source"):
                sources.add(str(row["source"]))
            if row.get("normalized_label"):
                labels.add(str(row["normalized_label"]))
            elif row.get("binary_label") not in (None, ""):
                labels.add(str(row["binary_label"]))
            continue
    return {
        "name": path.name,
        "path": str(path),
        "row_count": row_count,
        "row_count_is_sampled": False,
        "sources": sorted(sources),
        "labels": sorted(labels),
        "fields": fields,
    }


def _developer_preset_dataset(summary: dict[str, Any], *, name: str, preset_sources: list[str]) -> dict[str, Any]:
    item = dict(summary)
    item["name"] = name
    item["preset_sources"] = list(preset_sources)
    item["source_filter_mode"] = "preset_only"
    return item


def _developer_slot_run_dir(slot_idx: int) -> Path:
    return DEVELOPER_RUNS_DIR / f"test{slot_idx + 1}"


def _developer_prepare_run_dir(run_dir: Path, *, overwrite: bool) -> None:
    if overwrite and run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)


def _developer_load_rows(
    path: Path,
    *,
    sources: set[str],
    limit: int,
    offset: int,
    sample_mode: str = "Sequential",
    seed: int = 42,
) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    with path.open(newline="", encoding="utf-8", errors="ignore") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if sources and str(row.get("source", "")) not in sources:
                continue
            candidates.append(row)

    mode = sample_mode.strip().lower()
    if mode == "spam only":
        candidates = [row for row in candidates if _developer_actual_binary(row) == 1]
    elif mode == "ham only":
        candidates = [row for row in candidates if _developer_actual_binary(row) == 0]
    elif mode == "balanced 50/50 ham/spam":
        spam_rows = [row for row in candidates if _developer_actual_binary(row) == 1]
        ham_rows = [row for row in candidates if _developer_actual_binary(row) == 0]
        rng = random.Random(seed)
        rng.shuffle(spam_rows)
        rng.shuffle(ham_rows)
        spam_target = limit // 2 if limit else min(len(spam_rows), len(ham_rows))
        ham_target = limit - spam_target if limit else spam_target
        candidates = []
        for pair_idx in range(max(spam_target, ham_target)):
            if pair_idx < spam_target and pair_idx < len(spam_rows):
                candidates.append(spam_rows[pair_idx])
            if pair_idx < ham_target and pair_idx < len(ham_rows):
                candidates.append(ham_rows[pair_idx])
    elif mode == "random":
        rng = random.Random(seed)
        rng.shuffle(candidates)

    if offset:
        candidates = candidates[offset:]
    if limit:
        candidates = candidates[:limit]
    return candidates


def _developer_actual_binary(row: dict[str, str]) -> int | None:
    value = str(row.get("binary_label", "")).strip()
    if value in {"0", "1"}:
        return int(value)
    label = str(row.get("normalized_label") or row.get("source_label") or "").strip().lower()
    if label in {"legitimate", "benign", "ham", "normal", "0"}:
        return 0
    if label in {"spam", "phishing", "fraud", "malicious", "1"}:
        return 1
    return None


def _developer_metric_bucket(records: list[dict[str, Any]], prediction_key: str) -> dict[str, Any]:
    counts = {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "invalid": 0}
    for record in records:
        actual = record.get("actual_binary")
        pred = record.get(prediction_key)
        if actual not in {0, 1} or pred not in {0, 1}:
            counts["invalid"] += 1
        elif actual == 1 and pred == 1:
            counts["tp"] += 1
        elif actual == 0 and pred == 0:
            counts["tn"] += 1
        elif actual == 0 and pred == 1:
            counts["fp"] += 1
        elif actual == 1 and pred == 0:
            counts["fn"] += 1
    valid = counts["tp"] + counts["tn"] + counts["fp"] + counts["fn"]
    negatives = counts["tn"] + counts["fp"]
    positives = counts["tp"] + counts["fn"]
    predicted_positive = counts["tp"] + counts["fp"]
    return {
        **counts,
        "total": valid + counts["invalid"],
        "valid": valid,
        "accuracy": (counts["tp"] + counts["tn"]) / valid if valid else None,
        "fpr": counts["fp"] / negatives if negatives else None,
        "recall": counts["tp"] / positives if positives else None,
        "precision": counts["tp"] / predicted_positive if predicted_positive else None,
        "f1": (2 * counts["tp"] / (2 * counts["tp"] + counts["fp"] + counts["fn"])) if (2 * counts["tp"] + counts["fp"] + counts["fn"]) else None,
        "fnr": counts["fn"] / positives if positives else None,
    }


def _developer_metric_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    final_metrics = _developer_metric_bucket(records, "predicted_binary")
    baseline_metrics = _developer_metric_bucket(records, "baseline_predicted_binary")
    llm_used = 0
    llm_applied = 0
    llm_errors = 0
    ham_to_positive = 0
    ham_fp_rescued = 0
    positive_fn_rescued = 0
    positive_to_negative = 0
    spam_to_phishing = 0
    phishing_to_spam = 0
    source_groups: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        source = str(record.get("source") or "unknown")
        source_groups.setdefault(source, []).append(record)
        if bool(record.get("llm_review_used")):
            llm_used += 1
        if bool(record.get("llm_review_applied")):
            llm_applied += 1
        if str(record.get("llm_review_error") or "").strip():
            llm_errors += 1
        actual = record.get("actual_binary")
        baseline_pred = record.get("baseline_predicted_binary")
        final_pred = record.get("predicted_binary")
        baseline_verdict = str(record.get("baseline_verdict") or "")
        final_verdict = str(record.get("predicted_verdict") or "")
        if actual == 0 and baseline_pred == 0 and final_pred == 1:
            ham_to_positive += 1
        if actual == 0 and baseline_pred == 1 and final_pred == 0:
            ham_fp_rescued += 1
        if actual == 1 and baseline_pred == 0 and final_pred == 1:
            positive_fn_rescued += 1
        if actual == 1 and baseline_pred == 1 and final_pred == 0:
            positive_to_negative += 1
        if baseline_verdict == "Spam" and final_verdict == "Phishing":
            spam_to_phishing += 1
        if baseline_verdict == "Phishing" and final_verdict == "Spam":
            phishing_to_spam += 1
    source_metrics: dict[str, Any] = {}
    for source, source_records in sorted(source_groups.items()):
        source_metrics[source] = {
            **_developer_metric_bucket(source_records, "predicted_binary"),
            "baseline": _developer_metric_bucket(source_records, "baseline_predicted_binary"),
            "rows": len(source_records),
        }
    return {
        **final_metrics,
        "baseline": baseline_metrics,
        "delta_fpr": (
            final_metrics.get("fpr") - baseline_metrics.get("fpr")
            if final_metrics.get("fpr") is not None and baseline_metrics.get("fpr") is not None
            else None
        ),
        "delta_recall": (
            final_metrics.get("recall") - baseline_metrics.get("recall")
            if final_metrics.get("recall") is not None and baseline_metrics.get("recall") is not None
            else None
        ),
        "llm_success": llm_used,
        "llm_used": llm_used,
        "llm_applied": llm_applied,
        "llm_errors": llm_errors,
        "llm_attempts": llm_used + llm_errors,
        "llm_changed": ham_to_positive + ham_fp_rescued + positive_fn_rescued + positive_to_negative + spam_to_phishing + phishing_to_spam,
        "llm_ham_to_positive": ham_to_positive,
        "llm_ham_fp_rescued": ham_fp_rescued,
        "llm_positive_fn_rescued": positive_fn_rescued,
        "llm_positive_to_negative": positive_to_negative,
        "llm_spam_to_phishing": spam_to_phishing,
        "llm_phishing_to_spam": phishing_to_spam,
        "source_metrics": source_metrics,
    }

def _developer_format_metric(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def _developer_build_raw_email(row: dict[str, str]) -> str:
    sender = (row.get("sender") or "unknown@example.com").replace("\n", " ").replace("\r", " ")
    receiver = (row.get("receiver") or "recipient@example.com").replace("\n", " ").replace("\r", " ")
    subject = (row.get("subject") or "(no subject)").replace("\n", " ").replace("\r", " ")
    body = row.get("email_text") or ""
    return f"From: {sender}\nTo: {receiver}\nSubject: {subject}\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\n{body}"


def _developer_gray_zone_reasons(
    *,
    decision: str,
    rspamd_data: dict[str, Any],
    content_data: dict[str, Any],
    header_data: dict[str, Any],
    url_data: dict[str, Any],
    urgency_data: dict[str, Any],
    scam_data: dict[str, Any],
    campaign_data: dict[str, Any],
) -> list[str]:
    reasons: list[str] = []
    score = float(content_data.get("malicious_score") or 0.0)
    threshold = float(content_data.get("threshold") or 0.5)
    rspamd_score = float(rspamd_data.get("score") or 0.0)
    header_risk = str(header_data.get("risk_level") or "").lower()
    url_risk = str(url_data.get("risk_level") or "").lower()
    urgency_risk = str(urgency_data.get("risk_contribution") or "").lower()
    scam_matched = bool(scam_data.get("matched"))
    campaign_matched = bool(campaign_data.get("matched"))
    content_malicious = bool(content_data.get("is_malicious"))
    content_margin = abs(score - threshold)
    phish_signals = sum(
        1
        for condition in (
            header_risk in {"medium", "high"},
            url_risk in {"medium", "high"} or bool(url_data.get("is_suspicious")),
            scam_matched,
            urgency_risk in {"medium", "high"} or bool(urgency_data.get("is_urgent")),
        )
        if condition
    )

    if not content_data:
        reasons.append("content-model-missing")
    elif content_margin <= 0.18:
        reasons.append("content-near-threshold")
    if decision == "Normal" and (rspamd_score >= 8.0 or phish_signals >= 2 or campaign_matched):
        reasons.append("normal-vs-risk-signals-conflict")
    if decision == "Spam" and phish_signals >= 2:
        reasons.append("spam-vs-phishing-conflict")
    if decision == "Phishing" and phish_signals <= 1 and rspamd_score < 8.0 and not content_malicious:
        reasons.append("phishing-weak-corroboration")
    if decision != "Normal" and not content_malicious and rspamd_score < 6.0 and not campaign_matched and not scam_matched:
        reasons.append("malicious-with-weak-core-evidence")
    if decision == "Normal" and content_malicious and rspamd_score >= 6.0:
        reasons.append("content-vs-final-decision-conflict")
    return reasons


def _developer_parse_llm_verdict(text: str) -> tuple[str | None, str]:
    cleaned = text.strip()
    if not cleaned:
        return None, ""
    payload_text = cleaned
    if "{" in cleaned and "}" in cleaned:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        payload_text = cleaned[start : end + 1]
    rationale = ""
    try:
        payload = json.loads(payload_text)
        verdict = str(payload.get("verdict") or "").strip().title()
        rationale = str(payload.get("reason") or payload.get("rationale") or "").strip()
        if verdict in {"Normal", "Spam", "Phishing"}:
            return verdict, rationale
    except Exception:
        pass
    verdict_match = re.search(r"verdict\s*:\s*(normal|spam|phishing)\b", cleaned, flags=re.IGNORECASE)
    if verdict_match:
        return verdict_match.group(1).title(), rationale
    lowered = cleaned.lower()
    if "phishing" in lowered:
        return "Phishing", rationale
    if '"spam"' in lowered or re.search(r"\bspam\b", lowered):
        return "Spam", rationale
    if "normal" in lowered or "benign" in lowered:
        return "Normal", rationale
    return None, rationale


def _content_supports_spam_override(
    content_data: dict[str, Any],
    *,
    rspamd_data: dict[str, Any] | None = None,
    campaign_data: dict[str, Any] | None = None,
    subject: str = "",
    from_address: str = "",
    email_text: str = "",
) -> bool:
    score = float(content_data.get("malicious_score") or 0.0)
    threshold = float(content_data.get("threshold") or 0.0)
    margin = score - threshold
    content_risk = str(content_data.get("risk_level") or "").lower()
    rspamd_score = float((rspamd_data or {}).get("score") or 0.0)
    rspamd_risk = str((rspamd_data or {}).get("risk_level") or "").lower()
    campaign_matched = bool((campaign_data or {}).get("matched"))
    lowered = f"{subject}\n{from_address}\n{email_text}".lower()
    marketing_markers = sum(
        1
        for token in (
            "unsubscribe",
            "list-unsubscribe",
            "privacy",
            "view online",
            "manage preferences",
            "download the app",
            "book now",
            "shop deals",
            "save ",
            "offer",
            "sale",
            "overview",
            "newsletter",
        )
        if token in lowered
    )
    account_security_markers = any(
        token in lowered
        for token in (
            "verify",
            "verification",
            "password",
            "login",
            "log in",
            "sign in",
            "sign-in",
            "security alert",
            "confirm your identity",
            "account suspended",
            "gift card",
            "bitcoin",
            "cryptocurrency",
            "wallet",
        )
    )
    legit_marketing_pattern = marketing_markers >= 2 and not account_security_markers
    if legit_marketing_pattern and not campaign_matched and rspamd_score < 8.0 and rspamd_risk != "high":
        return False
    if campaign_matched or rspamd_score >= 8.0 or rspamd_risk == "high":
        return True
    if content_risk == "high" and margin >= 0.2:
        return True
    if margin >= 0.25 and rspamd_score >= 6.5:
        return True
    return False


def _looks_like_legit_marketing_email(
    *,
    rspamd_data: dict[str, Any] | None = None,
    content_data: dict[str, Any] | None = None,
    header_data: dict[str, Any] | None = None,
    url_data: dict[str, Any] | None = None,
    urgency_data: dict[str, Any] | None = None,
    scam_data: dict[str, Any] | None = None,
    campaign_data: dict[str, Any] | None = None,
    subject: str = "",
    from_address: str = "",
    email_text: str = "",
) -> bool:
    lowered = f"{subject}\n{from_address}\n{email_text}".lower()
    marketing_markers = sum(
        1
        for token in (
            "unsubscribe",
            "list-unsubscribe",
            "privacy",
            "view online",
            "manage preferences",
            "download the app",
            "book now",
            "shop deals",
            "save ",
            "offer",
            "sale",
            "deal",
            "deals",
            "travel",
            "overview",
            "newsletter",
            "performance",
            "future of",
        )
        if token in lowered
    )
    account_security_markers = any(
        token in lowered
        for token in (
            "verify",
            "verification",
            "password",
            "login",
            "log in",
            "sign in",
            "sign-in",
            "security alert",
            "confirm your identity",
            "account suspended",
            "gift card",
            "bitcoin",
            "cryptocurrency",
            "wallet",
            "wire transfer",
        )
    )
    categories = {str(item).lower() for item in ((rspamd_data or {}).get("categories") or [])}
    rspamd_score = float((rspamd_data or {}).get("score") or 0.0)
    header_risk = str((header_data or {}).get("risk_level") or "").lower()
    url_risk = str((url_data or {}).get("risk_level") or "").lower()
    urgency_risk = str((urgency_data or {}).get("risk_contribution") or "").lower()
    content_score = float((content_data or {}).get("malicious_score") or 0.0)
    content_threshold = float((content_data or {}).get("threshold") or 0.0)
    scam_matched = bool((scam_data or {}).get("matched"))
    campaign_matched = bool((campaign_data or {}).get("matched"))
    has_phish_signal = bool({"phishing", "spoofing", "suspicious_links"} & categories)
    has_spam_signal = bool("spam" in categories or "reputation_issue" in categories)
    content_margin = content_score - content_threshold

    if marketing_markers < 2 or account_security_markers:
        return False
    if scam_matched or campaign_matched or has_phish_signal:
        return False
    if header_risk not in {"", "low", "unknown", "n/a"}:
        return False
    if url_risk not in {"", "low", "unknown"}:
        return False
    if rspamd_score >= 10.5:
        return False
    if has_spam_signal and rspamd_score >= 9.5:
        return False
    if content_margin >= 0.35:
        return False
    if urgency_risk == "high" and marketing_markers < 3:
        return False
    return True


def _developer_verdict_rank(verdict: str) -> int:
    return {"Normal": 0, "Spam": 1, "Phishing": 2}.get(str(verdict or "").title(), -1)


def _developer_llm_signal_snapshot(
    *,
    decision: str,
    rspamd_data: dict[str, Any],
    content_data: dict[str, Any],
    header_data: dict[str, Any],
    url_data: dict[str, Any],
    urgency_data: dict[str, Any],
    scam_data: dict[str, Any],
    campaign_data: dict[str, Any],
    subject: str,
    from_address: str,
    email_text: str,
) -> dict[str, Any]:
    lowered = f"{subject} {from_address} {email_text}".lower()
    categories = {str(item).lower() for item in (rspamd_data.get("categories") or [])}
    symbols = {
        str(item.get("name") or "").lower()
        for item in (rspamd_data.get("symbols") or [])
        if isinstance(item, dict)
    }
    rspamd_score = float(rspamd_data.get("score") or 0.0)
    content_score = float(content_data.get("malicious_score") or 0.0)
    threshold = float(content_data.get("threshold") or 0.5)
    content_margin = content_score - threshold
    content_malicious = bool(content_data.get("is_malicious"))
    header_risk = str(header_data.get("risk_level") or "").lower()
    url_risk = str(url_data.get("risk_level") or "").lower()
    url_suspicious = bool(url_data.get("is_suspicious"))
    urgency_risk = str(urgency_data.get("risk_contribution") or "").lower()
    urgent = bool(urgency_data.get("is_urgent"))
    scam_matched = bool(scam_data.get("matched"))
    campaign_matched = bool(campaign_data.get("matched"))
    has_phish_signal = bool({"phishing", "spoofing", "suspicious_links"} & categories)
    has_spam_signal = bool("spam" in categories or any("bayes" in item for item in symbols) or "reputation_issue" in categories)
    account_context = any(
        token in lowered
        for token in (
            "account",
            "verify",
            "verification",
            "password",
            "login",
            "log in",
            "sign in",
            "security",
            "mailbox",
            "help desk",
            "invoice",
            "payment",
            "statement",
            "bank",
        )
    )
    branded_marketing = any(
        token in lowered
        for token in (
            "unsubscribe",
            "newsletter",
            "flash sale",
            "special offer",
            "limited time offer",
            "promotion",
            "promo",
            "deal",
            "shopify",
            "marketing",
        )
    )
    routine_business = any(
        token in lowered
        for token in (
            "receipt",
            "order",
            "invoice",
            "statement",
            "shipment",
            "delivery",
            "meeting",
            "calendar",
            "maintenance",
            "notice",
            "announcement",
        )
    )
    phish_corroboration = sum(
        1
        for condition in (
            header_risk in {"medium", "high"},
            url_risk in {"medium", "high"} or url_suspicious,
            scam_matched,
            urgency_risk in {"medium", "high"} or urgent,
            has_phish_signal,
            content_malicious and account_context,
        )
        if condition
    )
    benign_corroboration = sum(
        1
        for condition in (
            header_risk in {"", "low", "unknown", "n/a"},
            url_risk in {"", "low", "unknown"} and not url_suspicious,
            urgency_risk in {"", "low", "unknown"} and not urgent,
            not scam_matched,
            not campaign_matched,
            (not content_malicious) or content_margin <= 0.12,
            branded_marketing or routine_business,
        )
        if condition
    )
    locked_high_risk = bool(
        (header_risk == "high" and (url_suspicious or scam_matched))
        or (account_context and phish_corroboration >= 4 and rspamd_score >= 10.0)
    )
    strong_positive_support = sum(
        1
        for condition in (
            header_risk in {"medium", "high"},
            url_risk in {"medium", "high"} or url_suspicious,
            scam_matched,
            has_phish_signal,
            campaign_matched and has_spam_signal,
        )
        if condition
    )
    near_threshold = content_margin >= -0.02
    return {
        "decision": decision,
        "rspamd_score": rspamd_score,
        "content_score": content_score,
        "content_threshold": threshold,
        "content_margin": round(content_margin, 4),
        "content_malicious": content_malicious,
        "near_threshold": near_threshold,
        "header_risk": header_risk,
        "url_risk": url_risk,
        "url_suspicious": url_suspicious,
        "urgency_risk": urgency_risk,
        "urgent": urgent,
        "scam_matched": scam_matched,
        "campaign_matched": campaign_matched,
        "has_phish_signal": has_phish_signal,
        "has_spam_signal": has_spam_signal,
        "strong_positive_support": strong_positive_support,
        "account_context": account_context,
        "branded_marketing": branded_marketing,
        "routine_business": routine_business,
        "phish_corroboration": phish_corroboration,
        "benign_corroboration": benign_corroboration,
        "locked_high_risk": locked_high_risk,
    }


def _developer_llm_review_plan(
    *,
    decision: str,
    rspamd_data: dict[str, Any],
    content_data: dict[str, Any],
    header_data: dict[str, Any],
    url_data: dict[str, Any],
    urgency_data: dict[str, Any],
    scam_data: dict[str, Any],
    campaign_data: dict[str, Any],
    subject: str,
    from_address: str,
    email_text: str,
    gray_reasons: list[str],
    allow_positive_downgrade: bool = True,
    allow_positive_refine: bool = True,
    allow_normal_upgrade: bool = False,
) -> dict[str, Any]:
    snapshot = _developer_llm_signal_snapshot(
        decision=decision,
        rspamd_data=rspamd_data,
        content_data=content_data,
        header_data=header_data,
        url_data=url_data,
        urgency_data=urgency_data,
        scam_data=scam_data,
        campaign_data=campaign_data,
        subject=subject,
        from_address=from_address,
        email_text=email_text,
    )
    review_mode = ""
    hard_upgrade_gate = bool((snapshot["content_malicious"] or snapshot["near_threshold"]) and snapshot["strong_positive_support"] >= 2)
    if decision == "Phishing":
        if allow_positive_downgrade and not snapshot["locked_high_risk"] and snapshot["phish_corroboration"] <= 2:
            review_mode = "downgrade_fp"
    elif decision == "Spam":
        if allow_positive_refine and snapshot["account_context"] and snapshot["phish_corroboration"] >= 3:
            review_mode = "refine_positive"
        elif allow_positive_downgrade and snapshot["benign_corroboration"] >= 4 and (
            snapshot["content_margin"] <= 0.18
            or snapshot["branded_marketing"]
            or snapshot["routine_business"]
            or snapshot["rspamd_score"] < 10.0
        ):
            review_mode = "downgrade_fp"
    elif decision == "Normal" and allow_normal_upgrade:
        if hard_upgrade_gate and snapshot["account_context"] and snapshot["phish_corroboration"] >= 3:
            review_mode = "upgrade_fn"
        elif hard_upgrade_gate and snapshot["campaign_matched"] and snapshot["has_spam_signal"]:
            review_mode = "upgrade_fn"
        elif hard_upgrade_gate and snapshot["has_spam_signal"] and snapshot["rspamd_score"] >= 8.0:
            review_mode = "upgrade_fn"
    return {
        "enabled": bool(review_mode and gray_reasons),
        "mode": review_mode,
        "snapshot": snapshot,
    }

def _developer_parse_llm_review(text: str) -> dict[str, Any]:
    verdict, rationale = _developer_parse_llm_verdict(text)
    cleaned = text.strip()
    payload_text = cleaned
    confidence = ""
    evidence: dict[str, Any] = {}
    if "{" in cleaned and "}" in cleaned:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        payload_text = cleaned[start : end + 1]
    try:
        payload = json.loads(payload_text)
        confidence = str(payload.get("confidence") or "").strip().lower()
        evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
        if verdict is None:
            maybe_verdict = str(payload.get("verdict") or "").strip().title()
            if maybe_verdict in {"Normal", "Spam", "Phishing"}:
                verdict = maybe_verdict
        if not rationale:
            rationale = str(payload.get("reason") or payload.get("rationale") or "").strip()
    except Exception:
        pass
    return {
        "ok": verdict in {"Normal", "Spam", "Phishing"},
        "verdict": verdict,
        "confidence": confidence,
        "reason": rationale,
        "evidence": evidence,
        "raw_text": text,
    }


def _developer_build_llm_review_prompt(
    *,
    subject: str,
    from_address: str,
    body_text: str,
    current_decision: str,
    gray_reasons: list[str],
    signal_summary: dict[str, Any],
    review_mode: str,
) -> str:
    if review_mode == "downgrade_fp":
        review_goal = (
            "This is a false-positive review. Be skeptical of malicious interpretations. "
            "You may keep the current verdict or downgrade it only if there is a reasonable benign explanation. "
            "Marketing, billing, school, work, maintenance, and routine account notices are often legitimate."
        )
    elif review_mode == "upgrade_fn":
        review_goal = (
            "This is a false-negative review. You may keep the current verdict or upgrade it only when there is explicit malicious intent. "
            "Do not upgrade based on branding, urgency, or generic account language alone. "
            "Look for clear impersonation, credential theft, payment fraud, malicious account-action pressure, or coordinated spam language."
        )
    else:
        review_goal = (
            "This is a positive-label refinement review. Decide whether the current positive label should stay the same, be downgraded, or be upgraded to phishing. "
            "Only use Phishing when there is clear impersonation or credential/payment theft pressure."
        )
    safe_body = (body_text or "").strip()[:4000]
    return (
        "You are a constrained final-review layer for an email security benchmark.\n"
        "The first-stage classifier is already tuned for very low false positives. Your job is not to replace it. Your job is to correct only the hardest borderline cases.\n"
        f"{review_goal}\n"
        "Preserve the current verdict unless the available evidence is strong, specific, and corroborated.\n"
        "If the evidence is mixed or uncertain, return the current verdict unchanged.\n"
        "Return JSON only with keys verdict, confidence, reason, evidence.\n"
        'Allowed verdict values: "Normal", "Spam", "Phishing".\n'
        'Allowed confidence values: "low", "medium", "high".\n'
        "The evidence object should be brief booleans such as credential_theft, payment_fraud, impersonation, benign_marketing, routine_notification.\n\n"
        f"Initial verdict: {current_decision}\n"
        f"Review mode: {review_mode or 'general'}\n"
        f"Why this email was sent to final review: {', '.join(gray_reasons) or 'gray-zone'}\n"
        f"Existing structured signals: {json.dumps(signal_summary, ensure_ascii=False)}\n\n"
        f"Subject: {subject}\n"
        f"From: {from_address}\n"
        "Readable email body:\n"
        f"{safe_body or '(empty body)'}"
    )


async def _developer_llm_review_async(
    *,
    provider: str,
    model: str,
    rspamd_base_url: str,
    ollama_base_url: str,
    subject: str,
    from_address: str,
    body_text: str,
    current_decision: str,
    gray_reasons: list[str],
    signal_summary: dict[str, Any],
    review_mode: str,
) -> dict[str, Any]:
    runtime = EmailAgentRuntime(
        provider=provider,
        model_name=model,
        rspamd_base_url=rspamd_base_url,
        ollama_base_url=ollama_base_url,
        show_messages=False,
    )
    runtime.model = build_chat_model(
        provider=provider,
        model_name=model,
        temperature=0,
        ollama_base_url=ollama_base_url,
    )
    prompt = _developer_build_llm_review_prompt(
        subject=subject,
        from_address=from_address,
        body_text=body_text,
        current_decision=current_decision,
        gray_reasons=gray_reasons,
        signal_summary=signal_summary,
        review_mode=review_mode,
    )
    latest_messages = [
        SystemMessage(content=runtime.system_prompt),
        HumanMessage(content=prompt),
    ]
    timeout_s = float(os.getenv("GRAY_ZONE_REVIEW_TIMEOUT", "45"))
    ai_message = await asyncio.wait_for(
        runtime._invoke_direct_chat(
            latest_messages,
            prompt=prompt,
        ),
        timeout=timeout_s,
    )
    text = render_content(ai_message.content).strip()
    return _developer_parse_llm_review(text)


def _developer_apply_llm_review(
    *,
    current_decision: str,
    llm_review: dict[str, Any],
    review_mode: str,
    snapshot: dict[str, Any],
) -> tuple[str, bool, str]:
    proposed = str(llm_review.get("verdict") or "").title()
    confidence = str(llm_review.get("confidence") or "").lower()
    reason = str(llm_review.get("reason") or "").strip()
    current_rank = _developer_verdict_rank(current_decision)
    proposed_rank = _developer_verdict_rank(proposed)
    if proposed_rank < 0:
        return current_decision, False, "invalid-llm-verdict"

    if review_mode == "downgrade_fp":
        if proposed_rank > current_rank:
            return current_decision, False, "fp-guardrail-blocked-upgrade"
        if proposed_rank == current_rank:
            return current_decision, False, "llm-kept-current-verdict"
        if confidence not in {"medium", "high"}:
            return current_decision, False, "fp-guardrail-needs-medium-confidence"
        if snapshot.get("benign_corroboration", 0) < 4:
            return current_decision, False, "fp-guardrail-needs-benign-corroboration"
        if current_decision == "Phishing" and proposed == "Normal" and snapshot.get("phish_corroboration", 0) >= 2:
            return current_decision, False, "fp-guardrail-blocked-hard-phishing-to-normal"
        return proposed, True, reason or "llm-downgraded-borderline-positive"

    if review_mode == "refine_positive":
        if proposed_rank == current_rank:
            return current_decision, False, "llm-kept-current-verdict"
        if proposed == "Phishing":
            if confidence == "high" and snapshot.get("account_context") and snapshot.get("phish_corroboration", 0) >= 3:
                return proposed, True, reason or "llm-upgraded-spam-to-phishing"
            return current_decision, False, "positive-refine-needs-high-phish-corroboration"
        if proposed_rank < current_rank:
            if confidence in {"medium", "high"} and snapshot.get("benign_corroboration", 0) >= 4:
                return proposed, True, reason or "llm-downgraded-borderline-positive"
            return current_decision, False, "positive-refine-needs-benign-corroboration"
        return current_decision, False, "positive-refine-no-applicable-change"

    if review_mode == "upgrade_fn":
        if proposed_rank <= current_rank:
            return current_decision, False, "llm-kept-current-verdict"
        if confidence != "high":
            return current_decision, False, "fn-guardrail-needs-high-confidence"
        if not (snapshot.get("content_malicious") or snapshot.get("near_threshold")):
            return current_decision, False, "fn-guardrail-needs-content-support"
        if snapshot.get("strong_positive_support", 0) < 2:
            return current_decision, False, "fn-guardrail-needs-two-independent-signals"
        if proposed == "Spam":
            strong_spam_support = sum(
                1
                for condition in (
                    snapshot.get("campaign_matched"),
                    snapshot.get("has_spam_signal"),
                    snapshot.get("rspamd_score", 0.0) >= 8.0,
                )
                if condition
            )
            if strong_spam_support >= 2:
                return proposed, True, reason or "llm-upgraded-borderline-negative-to-spam"
            return current_decision, False, "fn-guardrail-needs-spam-corroboration"
        if proposed == "Phishing":
            if snapshot.get("account_context") and snapshot.get("phish_corroboration", 0) >= 3 and snapshot.get("strong_positive_support", 0) >= 3 and (
                snapshot.get("header_risk") in {"medium", "high"}
                or snapshot.get("url_risk") in {"medium", "high"}
                or snapshot.get("url_suspicious")
                or snapshot.get("scam_matched")
            ):
                return proposed, True, reason or "llm-upgraded-borderline-negative-to-phishing"
            return current_decision, False, "fn-guardrail-needs-phishing-corroboration"
        return current_decision, False, "fn-guardrail-no-applicable-change"

    return current_decision, False, "no-review-mode"

def _developer_predict_row(
    row: dict[str, str],
    *,
    rspamd_base_url: str,
    provider: str = "",
    model: str = "",
    ollama_base_url: str = "",
    llm_review_enabled: bool = False,
    llm_allow_positive_downgrade: bool = True,
    llm_allow_positive_refine: bool = True,
    llm_allow_normal_upgrade: bool = False,
    puter_review_func: Callable[[str, str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    raw_email = _developer_build_raw_email(row)
    subject = row.get("subject", "")
    from_address = row.get("sender", "")
    email_text = row.get("email_text", "")
    rspamd_result = RspamdScanEmailSkill(base_url=rspamd_base_url).run(
        RspamdScanEmailInput(raw_email=raw_email, include_raw_result=False)
    )
    rspamd_data = rspamd_result.data.model_dump() if rspamd_result.ok and rspamd_result.data else {}
    rspamd_score = float(rspamd_data.get("score") or 0.0)
    tools_called = ["rspamd_scan_email"]
    content_data: dict[str, Any] = {}
    header_data: dict[str, Any] = {}
    url_data: dict[str, Any] = {}
    urgency_data: dict[str, Any] = {}
    scam_data: dict[str, Any] = {}
    campaign_data: dict[str, Any] = {}
    memory_data: dict[str, Any] = {}
    patterns_count = None
    routed_skills = _developer_routed_skills(
        rspamd_data=rspamd_data,
        subject=subject,
        from_address=from_address,
        email_text=email_text,
    )

    if "content_model_check" in routed_skills:
        content_result = ContentModelCheckSkill().run(
            ContentModelCheckInput(
                email_text=email_text,
                subject=subject,
                from_address=from_address,
                sender_domain=row.get("sender_domain", ""),
                content_types=row.get("content_types", ""),
            )
        )
        tools_called.append("content_model_check")
        content_data = content_result.data.model_dump() if content_result.ok and content_result.data else {}

    if "email_header_auth_check" in routed_skills:
        header_result = EmailHeaderAuthCheckSkill().run(
            EmailHeaderAuthCheckInput(raw_email=raw_email, include_raw_headers=False)
        )
        tools_called.append("email_header_auth_check")
        header_data = header_result.data.model_dump() if header_result.ok and header_result.data else {}

    if "scam_indicator_check" in routed_skills:
        scam_result = ScamIndicatorCheckSkill().run(
            ScamIndicatorCheckInput(raw_email=raw_email, subject=subject, from_address=from_address)
        )
        tools_called.append("scam_indicator_check")
        scam_data = scam_result.data.model_dump() if scam_result.ok and scam_result.data else {}

    if "spam_campaign_check" in routed_skills:
        campaign_result = SpamCampaignCheckSkill().run(
            SpamCampaignCheckInput(
                raw_email=raw_email,
                email_text=email_text,
                subject=subject,
                from_address=from_address,
            )
        )
        tools_called.append("spam_campaign_check")
        campaign_data = campaign_result.data.model_dump() if campaign_result.ok and campaign_result.data else {}

    if "url_reputation_check" in routed_skills:
        url_result = UrlReputationSkill().run(UrlReputationInput(email_text=email_text, subject=subject))
        tools_called.append("url_reputation_check")
        url_data = url_result.data.model_dump() if url_result.ok and url_result.data else {}

    if "urgency_check" in routed_skills:
        urgency_result = UrgencyCheckSkill().run(UrgencyCheckInput(email_text=email_text, subject=subject))
        tools_called.append("urgency_check")
        urgency_data = urgency_result.data.model_dump() if urgency_result.ok and urgency_result.data else {}

    if "list_error_patterns" in routed_skills:
        patterns_result = ListErrorPatternsSkill().run(ListErrorPatternsInput(limit=20))
        tools_called.append("list_error_patterns")
        if patterns_result.ok and patterns_result.data:
            patterns_count = len(patterns_result.data.entries)

    obvious_reasons = list(scam_data.get("reasons") or [])
    campaign_reasons = list(campaign_data.get("reasons") or [])
    decision = _required_decision_label(
        rspamd_data,
        content_data or None,
        header_data or None,
        url_data or None,
        urgency_data or None,
        scam_data or None,
        campaign_data or None,
        subject,
        from_address,
    )
    if campaign_reasons and decision == "Normal":
        decision = "Spam"
    if "error_pattern_memory_check" in routed_skills:
        current_verdict = "benign" if decision == "Normal" else "suspicious"
        memory_result = ErrorPatternMemoryCheckSkill().run(
            ErrorPatternMemoryCheckInput(
                subject=subject,
                from_address=from_address,
                current_verdict=current_verdict,
                rspamd_risk_level=str(rspamd_data.get("risk_level") or "") or None,
                header_risk_level=str(header_data.get("risk_level") or "") or None,
                urgency_label=str(urgency_data.get("urgency_label") or "") or None,
                url_risk_level=str(url_data.get("risk_level") or "") or None,
            )
        )
        tools_called.append("error_pattern_memory_check")
        memory_data = memory_result.data.model_dump() if memory_result.ok and memory_result.data else {}
        if not obvious_reasons and not campaign_reasons and memory_data.get("matched") and memory_data.get("suggested_verdict") == "benign":
            decision = "Normal"
        if (
            not obvious_reasons
            and not campaign_reasons
            and rspamd_score > 10
            and decision == "Normal"
            and not _extra_checks_strongly_benign(header_data, url_data, urgency_data, memory_data)
        ):
            decision = "Spam"
    if content_data:
        if not bool(content_data.get("is_malicious")) and decision != "Phishing":
            decision = "Normal"
        elif (
            bool(content_data.get("is_malicious"))
                and decision != "Phishing"
                and _content_supports_spam_override(
                    content_data,
                    rspamd_data=rspamd_data,
                    campaign_data=campaign_data,
                    subject=subject,
                    from_address=from_address,
                    email_text=email_text,
                )
        ):
            decision = "Spam"
    if (
        decision == "Spam"
        and _looks_like_legit_marketing_email(
            rspamd_data=rspamd_data,
            content_data=content_data,
            header_data=header_data,
            url_data=url_data,
            urgency_data=urgency_data,
            scam_data=scam_data,
            campaign_data=campaign_data,
            subject=subject,
            from_address=from_address,
            email_text=email_text,
        )
    ):
        decision = "Normal"

    baseline_decision = decision
    baseline_predicted_binary = 0 if baseline_decision == "Normal" else 1
    llm_review_used = False
    llm_review_applied = False
    llm_review_decision = ""
    llm_review_reason = ""
    llm_review_error = ""
    llm_review_confidence = ""
    llm_review_mode = ""
    llm_review_guardrail = ""
    gray_reasons = _developer_gray_zone_reasons(
        decision=decision,
        rspamd_data=rspamd_data,
        content_data=content_data,
        header_data=header_data,
        url_data=url_data,
        urgency_data=urgency_data,
        scam_data=scam_data,
        campaign_data=campaign_data,
    )
    body_text = _mail_body_text(raw_email.encode("utf-8", errors="replace")) or email_text or raw_email
    review_plan = _developer_llm_review_plan(
        decision=decision,
        rspamd_data=rspamd_data,
        content_data=content_data,
        header_data=header_data,
        url_data=url_data,
        urgency_data=urgency_data,
        scam_data=scam_data,
        campaign_data=campaign_data,
        subject=subject,
        from_address=from_address,
        email_text=body_text,
        gray_reasons=gray_reasons,
        allow_positive_downgrade=llm_allow_positive_downgrade,
        allow_positive_refine=llm_allow_positive_refine,
        allow_normal_upgrade=llm_allow_normal_upgrade,
    )
    llm_review_mode = str(review_plan.get("mode") or "")
    if llm_review_enabled and provider and model and bool(review_plan.get("enabled")):
        signal_summary = {
            "rspamd_score": rspamd_score,
            "rspamd_action": rspamd_data.get("action"),
            "rspamd_risk": rspamd_data.get("risk_level"),
            "content_score": content_data.get("malicious_score"),
            "content_threshold": content_data.get("threshold"),
            "content_risk": content_data.get("risk_level"),
            "header_risk": header_data.get("risk_level"),
            "url_risk": url_data.get("risk_level"),
            "url_suspicious": url_data.get("is_suspicious"),
            "urgency_label": urgency_data.get("urgency_label"),
            "scam_matched": scam_data.get("matched"),
            "spam_campaign_matched": campaign_data.get("matched"),
            "scam_reasons": obvious_reasons,
            "campaign_reasons": campaign_reasons,
            "review_snapshot": review_plan.get("snapshot") or {},
        }
        try:
            if provider == PUTER_PROVIDER and puter_review_func is not None:
                prompt = _developer_build_llm_review_prompt(
                    subject=subject,
                    from_address=from_address,
                    body_text=body_text,
                    current_decision=decision,
                    gray_reasons=gray_reasons,
                    signal_summary=signal_summary,
                    review_mode=llm_review_mode,
                )
                llm_review = puter_review_func(prompt, model)
                llm_review = _developer_parse_llm_review(str(llm_review.get("raw_text") or json.dumps(llm_review, ensure_ascii=False))) if isinstance(llm_review, dict) and not llm_review.get("ok") else llm_review
            else:
                llm_review = asyncio.run(
                    _developer_llm_review_async(
                        provider=provider,
                        model=model,
                        rspamd_base_url=rspamd_base_url,
                        ollama_base_url=ollama_base_url,
                        subject=subject,
                        from_address=from_address,
                        body_text=body_text,
                        current_decision=decision,
                        gray_reasons=gray_reasons,
                        signal_summary=signal_summary,
                        review_mode=llm_review_mode,
                    )
                )
        except Exception as exc:
            llm_review = {"ok": False, "verdict": None, "confidence": "", "reason": str(exc), "raw_text": ""}
        if not llm_review.get("ok"):
            llm_review_error = str(llm_review.get("reason") or "LLM final review did not return a valid verdict.")
        else:
            llm_review_used = True
            llm_review_decision = str(llm_review.get("verdict") or "")
            llm_review_reason = str(llm_review.get("reason") or "")
            llm_review_confidence = str(llm_review.get("confidence") or "")
            decision, llm_review_applied, llm_review_guardrail = _developer_apply_llm_review(
                current_decision=decision,
                llm_review=llm_review,
                review_mode=llm_review_mode,
                snapshot=review_plan.get("snapshot") or {},
            )
            tools_called.append("llm_final_review")

    predicted_binary = 0 if decision == "Normal" else 1
    actual_binary = _developer_actual_binary(row)
    return {
        "source": row.get("source", ""),
        "source_record_id": row.get("source_record_id", ""),
        "baseline_verdict": baseline_decision,
        "baseline_predicted_binary": baseline_predicted_binary,
        "subject": subject,
        "sender": from_address,
        "actual_binary": actual_binary,
        "actual_label": row.get("normalized_label", ""),
        "predicted_verdict": decision,
        "predicted_binary": predicted_binary,
        "rspamd_score": rspamd_score,
        "rspamd_risk_level": rspamd_data.get("risk_level"),
        "content_score": content_data.get("malicious_score"),
        "content_risk_level": content_data.get("risk_level"),
        "content_threshold": content_data.get("threshold"),
        "header_risk_level": header_data.get("risk_level"),
        "url_risk_level": url_data.get("risk_level"),
        "url_score": url_data.get("phishing_score"),
        "urgency_label": urgency_data.get("urgency_label"),
        "urgency_score": urgency_data.get("urgency_score"),
        "scam_indicators": scam_data.get("indicators") or [],
        "scam_reasons": obvious_reasons,
        "spam_campaign_indicators": campaign_data.get("indicators") or [],
        "spam_campaign_reasons": campaign_reasons,
        "gray_zone_reasons": gray_reasons,
        "llm_review_used": llm_review_used,
        "llm_review_applied": llm_review_applied,
        "llm_review_mode": llm_review_mode,
        "llm_review_decision": llm_review_decision,
        "llm_review_confidence": llm_review_confidence,
        "llm_review_reason": llm_review_reason,
        "llm_review_guardrail": llm_review_guardrail,
        "llm_review_error": llm_review_error,
        "patterns_checked": patterns_count,
        "tools_called": tools_called,
        "flow": "content_model_ifelse_llm_guardrail_v2" if llm_review_enabled else "content_model_ifelse_no_llm_v1",
    }


class DeveloperExperimentWorker(QObject):
    progress = Signal(int, int)
    log = Signal(str)
    puter_review_requested = Signal(object)
    metrics_ready = Signal(object)
    finished = Signal(str)
    failed = Signal(str)

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__()
        self.config = config
        self._stop_requested = False

    def request_stop(self) -> None:
        self._stop_requested = True

    def _request_puter_review(self, prompt: str, model: str) -> dict[str, Any]:
        event = threading.Event()
        payload: dict[str, Any] = {
            "prompt": prompt,
            "model": model,
            "event": event,
            "result": None,
            "attempt": 1,
            "max_attempts": 3,
        }
        self.puter_review_requested.emit(payload)
        if not event.wait(timeout=180):
            return {
                "ok": False,
                "verdict": None,
                "reason": "Timed out waiting for ChatGPT final review.",
                "raw_text": "",
            }
        result = payload.get("result")
        if isinstance(result, dict):
            return result
        return {
            "ok": False,
            "verdict": None,
            "reason": "ChatGPT final review returned no result.",
            "raw_text": "",
        }

    def run(self) -> None:
        try:
            path = Path(self.config["dataset_path"])
            limit = int(self.config.get("limit") or 0)
            offset = int(self.config.get("offset") or 0)
            sources = set(self.config.get("sources") or [])
            sample_mode = str(self.config.get("sample_mode") or "Sequential")
            seed = int(self.config.get("seed") or 42)
            run_dir = Path(self.config["run_dir"])
            _developer_prepare_run_dir(run_dir, overwrite=bool(self.config.get("overwrite_run_dir")))
            results_path = run_dir / "results.jsonl"
            metrics_path = run_dir / "metrics.json"
            log_path = run_dir / "log.txt"
            config_path = run_dir / "config.json"
            config_path.write_text(json.dumps(self.config, indent=2, ensure_ascii=False), encoding="utf-8")

            rows = _developer_load_rows(
                path,
                sources=sources,
                limit=limit,
                offset=offset,
                sample_mode=sample_mode,
                seed=seed,
            )
            total = len(rows)
            llm_success_count = 0
            llm_error_count = 0
            self.log.emit(
                f"Loaded {total} row(s) from {path.name}; mode={sample_mode}; "
                f"offset={offset}; sources={sorted(sources) or 'all'}"
            )
            records: list[dict[str, Any]] = []
            with results_path.open("a", encoding="utf-8") as out, log_path.open("a", encoding="utf-8") as log_handle:
                for idx, row in enumerate(rows, 1):
                    if self._stop_requested:
                        self.log.emit(f"Stop requested at row {idx - 1}/{total}. Resume will start from index {offset + idx - 1}.")
                        break
                    record = _developer_predict_row(
                        row,
                        rspamd_base_url=str(self.config.get("rspamd_base_url") or DEFAULT_BASE_URL),
                        provider=str(self.config.get("provider") or ""),
                        model=str(self.config.get("model") or ""),
                        ollama_base_url=str(self.config.get("ollama_base_url") or ""),
                        llm_review_enabled=bool(self.config.get("llm_final_review")),
                        llm_allow_positive_downgrade=bool(
                            self.config.get("llm_allow_positive_downgrade", True)
                        ),
                        llm_allow_positive_refine=bool(
                            self.config.get("llm_allow_positive_refine", True)
                        ),
                        llm_allow_normal_upgrade=bool(
                            self.config.get("llm_allow_normal_upgrade", False)
                        ),
                        puter_review_func=self._request_puter_review,
                    )
                    record["run_index"] = offset + idx
                    record["model_provider"] = self.config.get("provider")
                    record["model_name"] = self.config.get("model")
                    records.append(record)
                    if bool(record.get("llm_review_used")):
                        llm_success_count += 1
                    if str(record.get("llm_review_error") or "").strip():
                        llm_error_count += 1
                    line = json.dumps(record, ensure_ascii=False)
                    out.write(line + "\n")
                    out.flush()
                    log_handle.write(
                        f"[{idx}/{total}] actual={record['actual_binary']} pred={record['predicted_binary']} "
                        f"baseline={record.get('baseline_predicted_binary')} score={record['rspamd_score']} "
                        f"llm_review={record.get('llm_review_used')} llm_applied={record.get('llm_review_applied')} "
                        f"llm_success={llm_success_count} llm_errors={llm_error_count} "
                        f"llm_guardrail={record.get('llm_review_guardrail') or ''} "
                        f"llm_error={record.get('llm_review_error') or ''} "
                        f"subject={record['subject'][:80]}\n"
                    )
                    log_handle.flush()
                    if idx == 1 or idx % 5 == 0 or idx == total:
                        metrics = _developer_metric_summary(records)
                        metrics_path.write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
                        self.metrics_ready.emit(metrics)
                    self.progress.emit(idx, total)
            metrics = _developer_metric_summary(records)
            metrics_path.write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
            self.metrics_ready.emit(metrics)
            self.finished.emit(str(run_dir))
        except Exception as exc:
            self.failed.emit(str(exc))


class DeveloperMetricCard(QWidget):
    def __init__(self, slot_idx: int, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.slot_idx = slot_idx
        self._metrics: dict[str, Any] = {}
        self.setMinimumHeight(170)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set_metrics(self, metrics: dict[str, Any]) -> None:
        self._metrics = dict(metrics)
        self.update()

    def paintEvent(self, event: Any) -> None:
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        rect = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        painter.setPen(QPen(QColor("#cbd5e1"), 1))
        painter.setBrush(QColor("#ffffff"))
        painter.drawRoundedRect(rect, 12, 12)

        accent_colors = ["#16697a", "#f59e0b", "#2563eb", "#dc2626"]
        accent = QColor(accent_colors[self.slot_idx % len(accent_colors)])
        painter.setPen(Qt.NoPen)
        painter.setBrush(accent)
        painter.drawRoundedRect(QRectF(rect.left(), rect.top(), 7, rect.height()), 3, 3)

        title_font = QFont(painter.font())
        title_font.setPointSize(11)
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.setPen(QColor("#0f172a"))
        painter.drawText(QRectF(rect.left() + 18, rect.top() + 10, 120, 22), Qt.AlignLeft | Qt.AlignVCenter, f"Test {self.slot_idx + 1}")

        total = self._metrics.get("total")
        total_text = f"Total {int(total)}" if isinstance(total, (int, float)) else "Waiting"
        pill_rect = QRectF(rect.right() - 96, rect.top() + 10, 78, 24)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor("#eef3f7"))
        painter.drawRoundedRect(pill_rect, 12, 12)
        label_font = QFont(painter.font())
        label_font.setPointSize(8)
        label_font.setBold(True)
        painter.setFont(label_font)
        painter.setPen(QColor("#475569"))
        painter.drawText(pill_rect, Qt.AlignCenter, total_text)

        rows = [
            ("accuracy", "Accuracy", QColor("#16697a"), False, 1.0),
            ("fpr", "FPR", QColor("#dc2626"), True, 0.2),
            ("recall", "Recall", QColor("#2563eb"), False, 1.0),
            ("precision", "Precision", QColor("#0f766e"), False, 1.0),
            ("f1", "F1", QColor("#7c3aed"), False, 1.0),
        ]
        y = rect.top() + 46
        bar_left = rect.left() + 88
        bar_right = rect.right() - 18
        bar_width = max(20.0, bar_right - bar_left)
        painter.setFont(label_font)
        for key, label, color, lower_is_better, scale_max in rows:
            raw = self._metrics.get(key)
            value = float(raw) if isinstance(raw, (int, float)) else None
            display = _developer_format_metric(value)
            fill_ratio = 0.0
            if value is not None:
                normalized = max(0.0, min(1.0, value / scale_max))
                fill_ratio = 1.0 - normalized if lower_is_better else normalized

            painter.setPen(QColor("#334155"))
            painter.drawText(QRectF(rect.left() + 18, y - 1, 64, 18), Qt.AlignLeft | Qt.AlignVCenter, label)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor("#e2e8f0"))
            track = QRectF(bar_left, y + 2, bar_width, 11)
            painter.drawRoundedRect(track, 5, 5)
            if fill_ratio > 0:
                painter.setBrush(color)
                painter.drawRoundedRect(QRectF(track.left(), track.top(), track.width() * fill_ratio, track.height()), 5, 5)
            painter.setPen(QColor("#0f172a"))
            painter.drawText(QRectF(bar_right - 45, y - 1, 45, 18), Qt.AlignRight | Qt.AlignVCenter, display)
            y += 22


class DeveloperMetricsChart(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._slot_metrics: dict[int, dict[str, Any]] = {}
        self.setMinimumHeight(260)

    def set_slot_metrics(self, slot_metrics: dict[int, dict[str, Any]]) -> None:
        self._slot_metrics = {idx: dict(metrics) for idx, metrics in slot_metrics.items() if isinstance(metrics, dict)}
        self.update()

    def paintEvent(self, event: Any) -> None:
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), QColor("#ffffff"))

        outer = self.rect().adjusted(12, 12, -12, -12)
        painter.setPen(QPen(QColor("#cbd5e1"), 1))
        painter.setBrush(QColor("#ffffff"))
        painter.drawRoundedRect(outer, 12, 12)

        title_rect = QRectF(outer.left() + 12, outer.top() + 8, outer.width() - 24, 28)
        painter.setPen(QColor("#0f172a"))
        title_font = QFont(painter.font())
        title_font.setPointSize(12)
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.drawText(title_rect, Qt.AlignLeft | Qt.AlignVCenter, "Test Comparison Matrix")

        hint_font = QFont(painter.font())
        hint_font.setPointSize(9)
        hint_font.setBold(False)
        painter.setFont(hint_font)
        painter.setPen(QColor("#64748b"))
        painter.drawText(
            QRectF(outer.left() + 12, outer.top() + 34, outer.width() - 24, 20),
            Qt.AlignLeft | Qt.AlignVCenter,
            "Green means closer to the target: FPR <= 1%, Recall >= 90%.",
        )

        columns = [
            ("total", "Total", "count"),
            ("fpr", "FPR", "fpr"),
            ("recall", "Recall", "recall"),
            ("precision", "Precision", "precision"),
            ("llm_used", "LLM Review", "count_neutral"),
            ("llm_applied", "Accepted", "count_neutral"),
            ("fp", "FP", "count_bad"),
            ("fn", "FN", "count_bad"),
        ]
        colors = ["#16697a", "#f59e0b", "#2563eb", "#dc2626"]
        label_font = QFont(painter.font())
        label_font.setPointSize(9)
        painter.setFont(label_font)

        table_left = outer.left() + 14
        table_top = outer.top() + 68
        table_right = outer.right() - 14
        row_label_width = 72.0
        row_height = 36.0
        header_height = 28.0
        column_width = (table_right - table_left - row_label_width) / len(columns)

        painter.setPen(QColor("#64748b"))
        for col_idx, (_key, label, _kind) in enumerate(columns):
            x = table_left + row_label_width + col_idx * column_width
            painter.drawText(
                QRectF(x + 4, table_top, column_width - 8, header_height),
                Qt.AlignCenter,
                label,
            )

        for slot_idx in range(DEVELOPER_SLOT_COUNT):
            metrics_for_slot = self._slot_metrics.get(slot_idx, {})
            y = table_top + header_height + slot_idx * row_height
            row_rect = QRectF(table_left, y, table_right - table_left, row_height - 4)
            painter.setPen(QPen(QColor("#e2e8f0"), 1))
            painter.setBrush(QColor("#f8fafc") if slot_idx % 2 == 0 else QColor("#ffffff"))
            painter.drawRoundedRect(row_rect, 7, 7)

            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(colors[slot_idx % len(colors)]))
            painter.drawRoundedRect(QRectF(table_left + 8, y + 10, 12, 12), 3, 3)
            painter.setPen(QColor("#0f172a"))
            painter.drawText(QRectF(table_left + 26, y + 3, row_label_width - 30, row_height - 8), Qt.AlignLeft | Qt.AlignVCenter, f"Test {slot_idx + 1}")

            for col_idx, (metric_key, _label, kind) in enumerate(columns):
                raw_value = metrics_for_slot.get(metric_key)
                x = table_left + row_label_width + col_idx * column_width + 4
                cell_rect = QRectF(x, y + 5, column_width - 8, row_height - 12)
                value: float | None = float(raw_value) if isinstance(raw_value, (int, float)) else None

                if value is None:
                    fill = QColor("#f1f5f9")
                    text = "Waiting"
                elif kind == "fpr":
                    fill = QColor("#dcfce7") if value <= 0.01 else QColor("#fef3c7") if value <= 0.02 else QColor("#fee2e2")
                    text = _developer_format_metric(value)
                elif kind == "recall":
                    fill = QColor("#dcfce7") if value >= 0.9 else QColor("#fef3c7") if value >= 0.8 else QColor("#fee2e2")
                    text = _developer_format_metric(value)
                elif kind == "precision":
                    fill = QColor("#dcfce7") if value >= 0.95 else QColor("#fef3c7") if value >= 0.9 else QColor("#fee2e2")
                    text = _developer_format_metric(value)
                elif kind == "count_bad":
                    fill = QColor("#f8fafc") if value == 0 else QColor("#fef3c7") if value <= 5 else QColor("#fee2e2")
                    text = str(int(value))
                elif kind == "count_neutral":
                    fill = QColor("#dbeafe") if value > 0 else QColor("#f1f5f9")
                    text = str(int(value))
                else:
                    fill = QColor("#f1f5f9")
                    text = str(int(value))

                painter.setPen(Qt.NoPen)
                painter.setBrush(fill)
                painter.drawRoundedRect(cell_rect, 6, 6)
                painter.setPen(QColor("#334155"))
                painter.drawText(
                    cell_rect,
                    Qt.AlignCenter,
                    text,
                )

        legend_y = outer.bottom() - 28
        painter.setFont(label_font)
        legend_items = [
            (QColor("#dcfce7"), "Target"),
            (QColor("#fef3c7"), "Watch"),
            (QColor("#fee2e2"), "Risk"),
        ]
        legend_x = outer.left() + 16
        for color, label in legend_items:
            painter.setPen(Qt.NoPen)
            painter.setBrush(color)
            painter.drawRoundedRect(QRectF(legend_x, legend_y, 16, 16), 4, 4)
            painter.setPen(QColor("#334155"))
            painter.drawText(QRectF(legend_x + 22, legend_y - 1, 92, 18), Qt.AlignLeft | Qt.AlignVCenter, label)
            legend_x += 118


async def _direct_email_analysis(
    email_items: list[dict[str, str]],
    *,
    rspamd_base_url: str,
    provider: str,
    model: str,
    ollama_base_url: str,
    progress: Any,
) -> str:
    rspamd_spam_threshold = 7.0
    sections: list[str] = []
    for index, item in enumerate(email_items, 1):
        raw_email = str(item.get("raw_email") or "").strip()
        subject = str(item.get("subject") or "(no subject)")
        from_address = str(item.get("from") or "unknown")

        if len(email_items) > 1:
            progress.emit(f"Analyzing email {index}")

        lines: list[str] = []
        if len(email_items) > 1:
            lines.append(f"Email {index}")
        lines.extend(
            [
                f"Email: {subject}",
                f"Type: {_friendly_email_type(subject, from_address)}",
            ]
        )

        if not raw_email:
            lines.extend(
                [
                    "Verdict: Normal",
                    "Why this conclusion:",
                    "- The original raw email content was not available, so there were no scanner-backed signs of spam or phishing to report.",
                ]
            )
            sections.append("\n".join(lines))
            continue

        progress.emit("Running email security scan")
        rspamd_result = RspamdScanEmailSkill(base_url=rspamd_base_url).run(
            RspamdScanEmailInput(raw_email=raw_email, include_raw_result=True)
        )
        rspamd_data = rspamd_result.data.model_dump() if rspamd_result.ok and rspamd_result.data else {}
        rspamd_score = float(rspamd_data.get("score") or 0.0)
        routed_skills = _developer_routed_skills(
            rspamd_data=rspamd_data,
            subject=subject,
            from_address=from_address,
            email_text=_mail_body_text(raw_email.encode("utf-8", errors="replace")) or raw_email,
        )
        run_extra_tools = bool(routed_skills)
        header_result = None
        url_result = None
        urgency_result = None
        patterns_result = None
        memory_result = None
        scam_result = None
        campaign_result = None
        content_result = None
        content_data: dict[str, Any] = {}
        header_data: dict[str, Any] = {}
        scam_data: dict[str, Any] = {}
        campaign_data: dict[str, Any] = {}
        obvious_phishing_reasons: list[str] = []
        campaign_reasons: list[str] = []
        url_data: dict[str, Any] = {}
        urgency_data: dict[str, Any] = {}

        if run_extra_tools:
            body_text = _mail_body_text(raw_email.encode("utf-8", errors="replace")) or raw_email
            progress.emit("Routing follow-up checks from the Rspamd result")
            if "content_model_check" in routed_skills:
                progress.emit("Running calibrated content classifier")
                content_result = ContentModelCheckSkill().run(
                    ContentModelCheckInput(
                        email_text=body_text,
                        subject=subject,
                        from_address=from_address,
                    )
                )
                content_data = content_result.data.model_dump() if content_result.ok and content_result.data else {}
            if "email_header_auth_check" in routed_skills:
                progress.emit("Checking sender and authentication headers")
                header_result = EmailHeaderAuthCheckSkill().run(
                    EmailHeaderAuthCheckInput(raw_email=raw_email, include_raw_headers=False)
                )
                header_data = header_result.data.model_dump() if header_result.ok and header_result.data else {}
            if "scam_indicator_check" in routed_skills:
                progress.emit("Checking obvious scam indicators")
                scam_result = ScamIndicatorCheckSkill().run(
                    ScamIndicatorCheckInput(
                        raw_email=raw_email,
                        subject=subject,
                        from_address=from_address,
                    )
                )
                scam_data = scam_result.data.model_dump() if scam_result.ok and scam_result.data else {}
                obvious_phishing_reasons = list(scam_data.get("reasons") or [])
            if "spam_campaign_check" in routed_skills:
                progress.emit("Checking high-precision spam campaign patterns")
                campaign_result = SpamCampaignCheckSkill().run(
                    SpamCampaignCheckInput(
                        raw_email=raw_email,
                        email_text=body_text,
                        subject=subject,
                        from_address=from_address,
                    )
                )
                campaign_data = campaign_result.data.model_dump() if campaign_result.ok and campaign_result.data else {}
                campaign_reasons = list(campaign_data.get("reasons") or [])
            if "url_reputation_check" in routed_skills:
                progress.emit("Checking links and URL reputation")
                url_result = UrlReputationSkill().run(UrlReputationInput(email_text=body_text, subject=subject))
                url_data = url_result.data.model_dump() if url_result.ok and url_result.data else {}
            if "urgency_check" in routed_skills:
                progress.emit("Scoring urgency and pressure signals")
                urgency_result = UrgencyCheckSkill().run(UrgencyCheckInput(email_text=body_text, subject=subject))
                urgency_data = urgency_result.data.model_dump() if urgency_result.ok and urgency_result.data else {}
            if "list_error_patterns" in routed_skills:
                progress.emit("Loading stored error patterns")
                patterns_result = ListErrorPatternsSkill().run(ListErrorPatternsInput(limit=20))

        decision = _required_decision_label(
            rspamd_data,
            content_data if run_extra_tools else None,
            header_data if run_extra_tools else None,
            url_data if run_extra_tools else None,
            urgency_data if run_extra_tools else None,
            scam_data if run_extra_tools else None,
            campaign_data if run_extra_tools else None,
            subject,
            from_address,
        )
        if campaign_reasons and decision == "Normal":
            decision = "Spam"

        memory_data: dict[str, Any] = {}
        if run_extra_tools:
            current_verdict = "benign" if decision == "Normal" else "suspicious"
            progress.emit("Checking known error patterns")
            memory_result = ErrorPatternMemoryCheckSkill().run(
                ErrorPatternMemoryCheckInput(
                    subject=subject,
                    from_address=from_address,
                    current_verdict=current_verdict,
                    rspamd_risk_level=str(rspamd_data.get("risk_level") or "") or None,
                    header_risk_level=str(header_data.get("risk_level") or "") or None,
                    urgency_label=str(urgency_data.get("urgency_label") or "") or None,
                    url_risk_level=str(url_data.get("risk_level") or "") or None,
                )
            )
            memory_data = memory_result.data.model_dump() if memory_result.ok and memory_result.data else {}
            if (
                not obvious_phishing_reasons
                and not campaign_reasons
                and memory_data.get("matched")
                and memory_data.get("suggested_verdict") == "benign"
            ):
                decision = "Normal"

        if (
            not obvious_phishing_reasons
            and not campaign_reasons
            and rspamd_score > 10
            and decision == "Normal"
            and not _extra_checks_strongly_benign(header_data, url_data, urgency_data, memory_data)
        ):
            decision = "Spam"
        if content_data:
            if not bool(content_data.get("is_malicious")) and decision != "Phishing":
                decision = "Normal"
            elif (
                bool(content_data.get("is_malicious"))
                and decision != "Phishing"
                and _content_supports_spam_override(
                    content_data,
                    rspamd_data=rspamd_data,
                    campaign_data=campaign_data,
                    subject=subject,
                    from_address=from_address,
                    email_text=body_text,
                )
            ):
                decision = "Spam"
        if (
            decision == "Spam"
            and _looks_like_legit_marketing_email(
                rspamd_data=rspamd_data,
                content_data=content_data,
                header_data=header_data,
                url_data=url_data,
                urgency_data=urgency_data,
                scam_data=scam_data,
                campaign_data=campaign_data,
                subject=subject,
                from_address=from_address,
                email_text=body_text,
            )
        ):
            decision = "Normal"

        gray_reasons = _developer_gray_zone_reasons(
            decision=decision,
            rspamd_data=rspamd_data,
            content_data=content_data,
            header_data=header_data,
            url_data=url_data,
            urgency_data=urgency_data,
            scam_data=scam_data,
            campaign_data=campaign_data,
        )
        body_text = _mail_body_text(raw_email.encode("utf-8", errors="replace")) or raw_email
        review_plan = _developer_llm_review_plan(
            decision=decision,
            rspamd_data=rspamd_data,
            content_data=content_data,
            header_data=header_data,
            url_data=url_data,
            urgency_data=urgency_data,
            scam_data=scam_data,
            campaign_data=campaign_data,
            subject=subject,
            from_address=from_address,
            email_text=body_text,
            gray_reasons=gray_reasons,
        )
        llm_review_used = False
        llm_review_applied = False
        llm_review_reason = ""
        llm_review_guardrail = ""
        llm_review_mode = str(review_plan.get("mode") or "")
        if provider and model and bool(review_plan.get("enabled")):
            progress.emit("Gray-zone email; asking the LLM for constrained final review")
            signal_summary = {
                "rspamd_score": rspamd_score,
                "rspamd_action": rspamd_data.get("action"),
                "rspamd_risk": rspamd_data.get("risk_level"),
                "content_score": content_data.get("malicious_score"),
                "content_threshold": content_data.get("threshold"),
                "content_risk": content_data.get("risk_level"),
                "header_risk": header_data.get("risk_level"),
                "url_risk": url_data.get("risk_level"),
                "url_suspicious": url_data.get("is_suspicious"),
                "urgency_label": urgency_data.get("urgency_label"),
                "scam_matched": scam_data.get("matched"),
                "spam_campaign_matched": campaign_data.get("matched"),
                "scam_reasons": obvious_phishing_reasons,
                "campaign_reasons": campaign_reasons,
                "review_snapshot": review_plan.get("snapshot") or {},
            }
            try:
                llm_review = await _developer_llm_review_async(
                    provider=provider,
                    model=model,
                    rspamd_base_url=rspamd_base_url,
                    ollama_base_url=ollama_base_url,
                    subject=subject,
                    from_address=from_address,
                    body_text=body_text,
                    current_decision=decision,
                    gray_reasons=gray_reasons,
                    signal_summary=signal_summary,
                    review_mode=llm_review_mode,
                )
            except Exception as exc:
                llm_review = {"ok": False, "reason": str(exc)}
            if llm_review.get("ok"):
                llm_review_used = True
                decision, llm_review_applied, llm_review_guardrail = _developer_apply_llm_review(
                    current_decision=decision,
                    llm_review=llm_review,
                    review_mode=llm_review_mode,
                    snapshot=review_plan.get("snapshot") or {},
                )
                llm_review_reason = str(llm_review.get("reason") or "")
            else:
                llm_review_guardrail = str(llm_review.get("reason") or "LLM review did not return a valid verdict.")

        lines.extend([f"Verdict: {decision}", "Why this conclusion:"])
        if rspamd_result.ok:
            lines.append(
                "- The message content and structure were rated "
                + f"{rspamd_data.get('risk_level', 'unknown')} risk "
                + f"(score {rspamd_data.get('score', 'unknown')})."
            )
        else:
            lines.append("- The main content scan could not be completed, so the verdict is based on the remaining available context.")

        if header_result is not None:
            if header_result.ok:
                lines.append(
                    "- The sender and authentication headers looked "
                    + f"{header_data.get('risk_level', 'unknown')} risk."
                )
            else:
                lines.append("- The sender and header-authentication check could not be completed.")

        if url_result is not None:
            if url_result.ok:
                lines.append(
                    "- The links and URL patterns looked "
                    + f"{url_data.get('risk_level', 'unknown')} risk "
                    + f"(phishing score {url_data.get('phishing_score', 'unknown')})."
                )
            else:
                lines.append("- The link-safety check could not be completed.")

        if urgency_result is not None:
            if urgency_result.ok:
                lines.append(
                    "- The wording was "
                    + f"{urgency_data.get('urgency_label', 'unknown')} "
                    + f"(pressure score {urgency_data.get('urgency_score', 'unknown')})."
                )
            else:
                lines.append("- The urgency/pressure check could not be completed.")

        if memory_result is not None:
            if memory_result.ok:
                if memory_data.get("matched"):
                    lines.append("- Similar past analysis patterns were found and considered before choosing the verdict.")
                else:
                    lines.append("- No similar past mistake pattern changed the verdict.")
            else:
                lines.append("- The past-pattern comparison could not be completed.")

        if patterns_result is not None:
            if patterns_result.ok and patterns_result.data:
                lines.append(f"- I compared the result against {len(patterns_result.data.entries)} stored past-error patterns.")
            elif not patterns_result.ok:
                lines.append("- Stored past-error patterns could not be loaded.")

        for reason in obvious_phishing_reasons:
            lines.append(f"- {reason}")
        for reason in campaign_reasons:
            lines.append(f"- {reason}")

        if decision == "Normal" and float(rspamd_data.get("score") or 0.0) >= 6:
            if rspamd_score > 10:
                lines.append("- Even though the scanner score was high, the extra checks gave a clear benign explanation, so it was not called spam or phishing.")
            else:
                lines.append("- Even though the scanner score was somewhat elevated, the extra checks did not support calling it spam or phishing.")
        if gray_reasons:
            lines.append(f"- Gray-zone review reasons: {', '.join(gray_reasons)}.")
            if llm_review_used:
                if llm_review_applied:
                    lines.append(f"- The constrained LLM review changed the decision: {llm_review_reason or llm_review_guardrail}.")
                else:
                    lines.append(f"- The constrained LLM review kept the rule-based decision: {llm_review_guardrail or llm_review_reason or 'no guarded change was allowed'}.")
            elif llm_review_guardrail:
                lines.append(f"- LLM gray-zone review was skipped or unavailable: {llm_review_guardrail}.")
        tools = ["rspamd_scan_email"]
        if content_result is not None:
            tools.append("content_model_check")
        if scam_result is not None:
            tools.append("scam_indicator_check")
        if campaign_result is not None:
            tools.append("spam_campaign_check")
        if url_result is not None:
            tools.append("url_reputation_check")
        if urgency_result is not None:
            tools.append("urgency_check")
        if patterns_result is not None:
            tools.append("list_error_patterns")
        if memory_result is not None:
            tools.append("error_pattern_memory_check")
        if llm_review_used:
            tools.append("llm_final_review")
        lines.extend(["", "Tools called: " + ", ".join(f"`{name}`" for name in tools)])
        sections.append("\n".join(lines))

    progress.emit("Preparing the final answer")
    return "\n\n".join(sections)


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
        direct_referenced_emails: list[dict[str, str]] | None = None,
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
        self.direct_referenced_emails = direct_referenced_emails

    def run(self) -> None:
        try:
            asyncio.run(self._run())
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.finished.emit()

    async def _build_runtime_for_current_thread(self) -> EmailAgentRuntime:
        previous_history: list[BaseMessage] | None = None
        if self.runtime is not None:
            previous_history = list(self.runtime.history)
            self.progress.emit("Refreshing chat runtime for this request")
        else:
            self.progress.emit("Initializing Email Guardian runtime")

        runtime = EmailAgentRuntime(
            provider=self.provider,
            model_name=self.model,
            rspamd_base_url=self.rspamd_base_url,
            ollama_base_url=self.ollama_base_url,
            show_messages=self.trace,
        )
        await runtime.setup()
        if previous_history:
            runtime.history = previous_history
        self.runtime = runtime
        self.updated_runtime = runtime
        self.ready.emit(f"{self.provider} / {self.model}")
        return runtime

    async def _run(self) -> None:
        if self.direct_referenced_emails is not None:
            self.result.emit(
                await _direct_email_analysis(
                    self.direct_referenced_emails,
                    rspamd_base_url=self.rspamd_base_url,
                    provider=self.provider,
                    model=self.model,
                    ollama_base_url=self.ollama_base_url,
                    progress=self.progress,
                )
            )
            return

        runtime = await self._build_runtime_for_current_thread()

        if self.setup_only:
            return

        runtime.show_messages = self.trace
        if self.reset:
            runtime.reset()
            self.progress.emit("Conversation history cleared")

        start_idx = len(runtime.history)
        try:
            messages, start_idx = await runtime.ask(
                self.prompt,
                progress_callback=self.progress.emit,
            )
        except Exception as exc:
            tool_summary = summarize_tool_messages(runtime.history, start_idx)
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
            if body:
                self.result.emit(body)
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
                item["email_address"] = self.email_address
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
    puter_auth_window_ready = Signal()
    puter_auth_success_signal = Signal()
    puter_auth_failure_signal = Signal(str)

    def __init__(self, args: argparse.Namespace) -> None:
        super().__init__()
        self.args = args
        self._shutting_down = False
        self.runtime: EmailAgentRuntime | None = None
        self.thread: QThread | None = None
        self.worker: AgentWorker | None = None
        self.mail_thread: QThread | None = None
        self.mail_worker: MailboxWorker | None = None
        self.dev_threads: dict[int, QThread] = {}
        self.dev_workers: dict[int, DeveloperExperimentWorker] = {}
        self.dev_datasets: list[dict[str, Any]] = []
        self.dev_last_configs: dict[int, dict[str, Any]] = {}
        self.dev_last_completed: dict[int, int] = {idx: 0 for idx in range(DEVELOPER_SLOT_COUNT)}
        self.dev_stop_requested_slots: set[int] = set()
        self.dev_pending_restarts: dict[int, dict[str, Any]] = {}
        self.dev_slot_widgets: list[dict[str, Any]] = []
        self.dev_slot_metric_views: dict[int, QWidget] = {}
        self.dev_slot_progress_views: dict[int, dict[str, Any]] = {}
        self.dev_slot_metrics: dict[int, dict[str, Any]] = {}
        self.dev_slot_timing: dict[int, dict[str, Any]] = {
            idx: {"started_at": None, "finished_at": None, "state": "idle"}
            for idx in range(DEVELOPER_SLOT_COUNT)
        }
        self.dev_export_dashboard_button: QPushButton | None = None
        self.dev_elapsed_timer = QTimer(self)
        self.dev_elapsed_timer.setInterval(1000)
        self.dev_elapsed_timer.timeout.connect(self._developer_refresh_timing_labels)
        self.dev_elapsed_timer.start()
        self._pre_dev_geometry: QRect | None = None
        self._pre_dev_flags = None
        self.puter_bridge: PuterBridgeController | None = None
        self.puter_history: list[dict[str, str]] = []
        self.puter_pending_messages: list[dict[str, str]] | None = None
        self.puter_active_request_id: int | None = None
        self.puter_next_request_id = 1
        self.puter_profile = None
        self.puter_server_process: subprocess.Popen[str] | None = None
        self.puter_auth_window = None
        self.puter_auth_view = None
        self.puter_auth_in_progress = False
        self.puter_retry_after_auth = False
        self.developer_puter_requests: dict[int, dict[str, Any]] = {}
        self.developer_puter_auth_retry_ids: set[int] = set()
        self.developer_puter_retry_after_auth = False
        self.loaded_email_count = 0
        self.referenced_emails: list[dict[str, str]] = []
        self.expanded = False
        self.puter_auth_window_ready.connect(self._on_puter_auth_window_ready, Qt.QueuedConnection)
        self.puter_auth_success_signal.connect(self._puter_auth_succeeded, Qt.QueuedConnection)
        self.puter_auth_failure_signal.connect(self._puter_auth_failed, Qt.QueuedConnection)

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
        self.dev_panel = self._build_developer_panel()
        self.stack.addWidget(self.dev_panel)
        self.stack.setCurrentWidget(self.ball_page)

        self._apply_styles()
        self.resize(BALL_SIZE, BALL_SIZE)
        self._place_bottom_right()
        self.refresh_mailboxes()
        self._sync_provider_ui(self.args.provider)
        QTimer.singleShot(250, self.initialize_runtime)

    def _build_window_controls(self) -> QWidget:
        controls = QWidget()
        controls.setObjectName("windowControls")
        layout = QHBoxLayout(controls)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        minimize_button = QPushButton("Min")
        maximize_button = QPushButton("Max")
        close_button = QPushButton("Close")
        for button in (minimize_button, maximize_button, close_button):
            button.setObjectName("windowControlButton")
            button.setCursor(QCursor(Qt.PointingHandCursor))
            button.setFixedHeight(28)
            button.setMinimumWidth(58)
            button.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            layout.addWidget(button)

        close_button.setObjectName("windowCloseButton")
        minimize_button.setToolTip("Minimize")
        maximize_button.setToolTip("Maximize or restore")
        close_button.setToolTip("Close Email Guardian and shut down launched services")
        minimize_button.clicked.connect(self.minimize_window)
        maximize_button.clicked.connect(self.toggle_window_maximized)
        close_button.clicked.connect(self.close_all_now)
        return controls

    def _use_chat_panel_window_flags(self) -> None:
        if not (self.windowFlags() & Qt.Tool):
            return
        geometry = self.geometry()
        self.hide()
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Window)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setGeometry(geometry)
        self.show()

    def _use_ball_window_flags(self) -> None:
        geometry = self.geometry()
        self.hide()
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setGeometry(geometry)
        self.show()

    def minimize_window(self) -> None:
        if self.stack.currentWidget() is self.panel:
            self._use_chat_panel_window_flags()
        self.showMinimized()

    def toggle_window_maximized(self) -> None:
        if self.isFullScreen() or self.isMaximized():
            self.showNormal()
            return
        if self.stack.currentWidget() is self.panel:
            self._use_chat_panel_window_flags()
        self.showMaximized()

    def close_all_now(self) -> None:
        self._shutting_down = True
        self._full_shutdown_cleanup()
        app = QApplication.instance()
        if app is not None:
            app.quit()

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
        self.provider_combo.addItems(["gemini", "ollama", TOKENROUTER_PROVIDER, PUTER_PROVIDER])
        self.model_input = QComboBox()
        self.model_input.setObjectName("modelInput")
        self.switch_model_button = QPushButton("Switch Model")
        self.switch_model_button.clicked.connect(self.switch_model)
        self.chatgpt_login_button = QPushButton("登录 ChatGPT")
        self.chatgpt_login_button.setObjectName("secondaryButton")
        self.chatgpt_login_button.clicked.connect(self.login_chatgpt)
        self.chatgpt_logout_button = QPushButton("退出登录 ChatGPT")
        self.chatgpt_logout_button.setObjectName("secondaryButton")
        self.chatgpt_logout_button.clicked.connect(self.logout_chatgpt)
        self.provider_combo.setCurrentText(self.args.provider)
        self.provider_combo.currentTextChanged.connect(self.update_model_default)
        _configure_model_selector(self.model_input, self.args.provider, self.args.model)
        side_layout.addWidget(model_label)
        side_layout.addWidget(self.provider_combo)
        side_layout.addWidget(self.model_input)
        side_layout.addWidget(self.switch_model_button)
        side_layout.addWidget(self.chatgpt_login_button)
        side_layout.addWidget(self.chatgpt_logout_button)

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
        developer_button = QPushButton("Developer Mode")
        developer_button.setObjectName("secondaryButton")
        developer_button.clicked.connect(self.show_developer_mode)
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
            developer_button,
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
        chat_header = QHBoxLayout()
        chat_header.addWidget(chat_title)
        chat_header.addStretch()
        chat_header.addWidget(self._build_window_controls())
        main_layout.addLayout(chat_header)

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
            if button.objectName() not in {"windowControlButton", "windowCloseButton"}:
                button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        return panel

    def _build_developer_panel(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("developerPanel")
        layout = QHBoxLayout(panel)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        left = QFrame()
        left.setObjectName("developerColumn")
        left.setFixedWidth(470)
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(12, 12, 12, 12)
        left_layout.setSpacing(10)
        title = QLabel("Developer Mode")
        title.setObjectName("developerTitle")
        subtitle = QLabel("Dataset experiment configuration")
        subtitle.setObjectName("status")
        left_layout.addWidget(title)
        left_layout.addWidget(subtitle)
        refresh_dataset_button = QPushButton("Refresh Databases")
        refresh_dataset_button.clicked.connect(self.refresh_developer_datasets)
        left_layout.addWidget(refresh_dataset_button)
        config_scroll = QScrollArea()
        config_scroll.setWidgetResizable(True)
        config_scroll.setObjectName("sideScroll")
        config_host = QWidget()
        config_layout = QVBoxLayout(config_host)
        config_layout.setContentsMargins(0, 0, 0, 0)
        config_layout.setSpacing(10)
        self.dev_slot_widgets = []
        for slot_idx in range(DEVELOPER_SLOT_COUNT):
            slot_card = QFrame()
            slot_card.setObjectName("developerSlotCard")
            slot_layout = QVBoxLayout(slot_card)
            slot_layout.setContentsMargins(10, 10, 10, 10)
            slot_layout.setSpacing(8)
            slot_title = QLabel(f"Test {slot_idx + 1}")
            slot_title.setObjectName("sectionLabel")
            dataset_combo = QComboBox()
            dataset_combo.currentIndexChanged.connect(lambda index, s=slot_idx: self._developer_dataset_changed(s, index))
            dataset_info = QLabel("No dataset loaded")
            dataset_info.setObjectName("status")
            dataset_info.setWordWrap(True)
            source_list = QListWidget()
            source_list.setObjectName("developerSourceList")
            source_list.setFixedHeight(188)
            limit_spin = QSpinBox()
            limit_spin.setRange(1, 100000)
            limit_spin.setValue(100)
            limit_spin.setSingleStep(50)
            sample_mode_combo = QComboBox()
            sample_mode_combo.addItems([
                "Sequential",
                "Random",
                "Balanced 50/50 ham/spam",
                "Spam only",
                "Ham only",
            ])
            sample_mode_combo.setCurrentText("Balanced 50/50 ham/spam")
            llm_review_check = QCheckBox("Use LLM final review")
            llm_review_check.setObjectName("developerLlmCheck")
            llm_review_check.setChecked(True)
            model_combo = QComboBox()
            model_combo.addItems(["gemini", "ollama", TOKENROUTER_PROVIDER, PUTER_PROVIDER])
            model_combo.setCurrentText(self.args.provider)
            model_input = QComboBox()
            model_input.setObjectName("modelInput")
            _configure_model_selector(model_input, self.args.provider, self.args.model)
            model_combo.currentTextChanged.connect(
                lambda provider, field=model_input: _configure_model_selector(field, provider, _desktop_model_default(provider))
            )
            slot_actions = QHBoxLayout()
            start_button = QPushButton("Start")
            start_button.clicked.connect(lambda _checked=False, s=slot_idx: self.start_developer_experiment(s))
            new_experiment_button = QPushButton("New Experiment")
            new_experiment_button.setObjectName("secondaryButton")
            new_experiment_button.clicked.connect(lambda _checked=False, s=slot_idx: self.reset_developer_experiment_slot(s))
            restart_button = QPushButton("Restart")
            restart_button.setObjectName("secondaryButton")
            restart_button.clicked.connect(lambda _checked=False, s=slot_idx: self.restart_developer_experiment(s))
            stop_button = QPushButton("Stop")
            stop_button.setObjectName("dangerQuitButton")
            stop_button.clicked.connect(lambda _checked=False, s=slot_idx: self.stop_developer_experiment(s))
            slot_actions.addWidget(start_button)
            slot_actions.addWidget(new_experiment_button)
            slot_actions.addWidget(restart_button)
            slot_actions.addWidget(stop_button)

            slot_layout.addWidget(slot_title)
            slot_layout.addWidget(QLabel("Database"))
            slot_layout.addWidget(dataset_combo)
            slot_layout.addWidget(dataset_info)
            slot_layout.addWidget(QLabel("Source filters"))
            slot_layout.addWidget(source_list)
            slot_layout.addWidget(QLabel("Emails to run"))
            slot_layout.addWidget(limit_spin)
            slot_layout.addWidget(QLabel("Sampling mode"))
            slot_layout.addWidget(sample_mode_combo)
            slot_layout.addWidget(llm_review_check)
            slot_layout.addWidget(QLabel("LLM provider and model"))
            slot_layout.addWidget(model_combo)
            slot_layout.addWidget(model_input)
            slot_layout.addLayout(slot_actions)
            config_layout.addWidget(slot_card)
            self.dev_slot_widgets.append(
                {
                    "dataset_combo": dataset_combo,
                    "dataset_info": dataset_info,
                    "source_list": source_list,
                    "limit_spin": limit_spin,
                    "sample_mode_combo": sample_mode_combo,
                    "llm_review_check": llm_review_check,
                    "model_combo": model_combo,
                    "model_input": model_input,
                    "start_button": start_button,
                    "new_experiment_button": new_experiment_button,
                    "restart_button": restart_button,
                    "stop_button": stop_button,
                }
            )
        config_layout.addStretch()
        config_scroll.setWidget(config_host)
        left_layout.addWidget(config_scroll, stretch=1)

        self.dev_back_button = QPushButton("Back To User Mode")
        self.dev_back_button.setObjectName("secondaryButton")
        self.dev_back_button.clicked.connect(self.leave_developer_mode)
        left_layout.addStretch()
        left_layout.addWidget(self.dev_back_button)
        layout.addWidget(left)

        center = QFrame()
        center.setObjectName("developerColumn")
        center_layout = QVBoxLayout(center)
        center_layout.setContentsMargins(12, 12, 12, 12)
        center_layout.setSpacing(10)
        result_title = QLabel("Experiment Comparison")
        result_title.setObjectName("developerTitle")
        result_header = QHBoxLayout()
        result_header.addWidget(result_title)
        result_header.addStretch()
        self.dev_export_dashboard_button = QPushButton("Export Dashboard")
        self.dev_export_dashboard_button.setObjectName("secondaryButton")
        self.dev_export_dashboard_button.setEnabled(False)
        self.dev_export_dashboard_button.clicked.connect(self.export_developer_dashboard)
        result_header.addWidget(self.dev_export_dashboard_button)
        center_layout.addLayout(result_header)
        summaries_grid = QGridLayout()
        summaries_grid.setSpacing(10)
        self.dev_slot_metric_views = {}
        for slot_idx in range(DEVELOPER_SLOT_COUNT):
            summary = DeveloperMetricCard(slot_idx)
            summary.setObjectName("developerMetricCard")
            self.dev_slot_metric_views[slot_idx] = summary
            summaries_grid.addWidget(summary, slot_idx // 2, slot_idx % 2)
        center_layout.addLayout(summaries_grid)
        center_layout.addSpacing(18)
        self.dev_chart = DeveloperMetricsChart()
        self.dev_chart.setObjectName("developerChart")
        center_layout.addWidget(self.dev_chart, stretch=1)
        layout.addWidget(center, stretch=1)

        right = QFrame()
        right.setObjectName("developerColumn")
        right.setFixedWidth(430)
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(12, 12, 12, 12)
        right_layout.setSpacing(10)
        run_title = QLabel("Run Progress")
        run_title.setObjectName("developerTitle")
        run_header = QHBoxLayout()
        run_header.addWidget(run_title)
        run_header.addStretch()
        run_header.addWidget(self._build_window_controls())
        right_layout.addLayout(run_header)
        self.dev_slot_progress_views = {}
        for slot_idx in range(DEVELOPER_SLOT_COUNT):
            box = QFrame()
            box.setObjectName("developerProgressCard")
            box_layout = QVBoxLayout(box)
            box_layout.setContentsMargins(8, 8, 8, 8)
            box_layout.setSpacing(6)
            label = QLabel(f"Test {slot_idx + 1}: Idle")
            label.setObjectName("sectionLabel")
            timing_label = QLabel("Started: n/a\nFinished: n/a\nElapsed: 00:00")
            timing_label.setObjectName("status")
            timing_label.setWordWrap(True)
            progress_bar = QProgressBar()
            progress_bar.setRange(0, 100)
            progress_bar.setValue(0)
            log_view = QTextEdit()
            log_view.setObjectName("progress")
            log_view.setReadOnly(True)
            log_view.setPlaceholderText(f"Test {slot_idx + 1} logs")
            log_view.setMinimumHeight(120)
            box_layout.addWidget(label)
            box_layout.addWidget(timing_label)
            box_layout.addWidget(progress_bar)
            box_layout.addWidget(log_view)
            right_layout.addWidget(box)
            self.dev_slot_progress_views[slot_idx] = {
                "status_label": label,
                "timing_label": timing_label,
                "progress_bar": progress_bar,
                "log_view": log_view,
            }
        right_layout.addStretch()
        layout.addWidget(right)

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
            #developerPanel {
                background: #0f172a;
                border: 0;
            }
            #developerColumn {
                background: #f8fafc;
                border: 1px solid #334155;
                border-radius: 12px;
                padding: 8px;
            }
            #developerSlotCard, #developerProgressCard {
                background: #ffffff;
                border: 1px solid #cbd5e1;
                border-radius: 10px;
            }
            #developerChart {
                background: #ffffff;
                border: 1px solid #cbd5e1;
                border-radius: 12px;
            }
            #developerTitle {
                font-size: 20px;
                font-weight: 800;
                color: #0f172a;
            }
            #metricCard {
                background: #ffffff;
                border: 1px solid #cbd5e1;
                border-left: 8px solid #16697a;
                border-radius: 10px;
                padding: 10px;
                font-size: 18px;
                font-weight: 800;
                color: #0f172a;
            }
            #developerSourceList {
                background: #ffffff;
                border: 1px solid #ccd4dd;
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
            QLineEdit,
            QSpinBox {
                background: #ffffff;
                border: 1px solid #ccd4dd;
                border-radius: 8px;
                padding: 7px 8px;
                selection-background-color: #bfdbfe;
                selection-color: #111827;
            }
            QSpinBox::up-button,
            QSpinBox::down-button {
                width: 20px;
                border: 0;
                background: #e2e8f0;
            }
            QSpinBox::up-button:hover,
            QSpinBox::down-button:hover {
                background: #cbd5e1;
            }
            #sampleSizeInput {
                font-size: 16px;
                font-weight: 800;
                color: #0f172a;
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
            QMessageBox {
                background: #f8fafc;
                color: #17202a;
            }
            QMessageBox QLabel {
                background: transparent;
                color: #17202a;
                font-size: 13px;
            }
            QMessageBox QPushButton {
                min-width: 92px;
                background: #e9eef3;
                color: #17202a;
                border: 1px solid #cbd5e1;
                border-radius: 8px;
                padding: 8px 12px;
                font-weight: 700;
            }
            QMessageBox QPushButton:hover {
                background: #dbe3ea;
            }
            QMessageBox QLineEdit,
            QMessageBox QTextEdit,
            QMessageBox QPlainTextEdit {
                background: #ffffff;
                color: #17202a;
                border: 1px solid #ccd4dd;
                border-radius: 8px;
                padding: 6px 8px;
            }
            #windowControls {
                background: transparent;
            }
            #windowControlButton {
                background: #e9eef3;
                color: #17202a;
                border: 1px solid #cbd5e1;
                border-radius: 7px;
                padding: 4px 8px;
                font-weight: 700;
            }
            #windowControlButton:hover {
                background: #dbe3ea;
            }
            #windowCloseButton {
                background: #b91c1c;
                color: #ffffff;
                border: 0;
                border-radius: 7px;
                padding: 4px 8px;
                font-weight: 700;
            }
            #windowCloseButton:hover {
                background: #991b1b;
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
                color: #0f172a;
                spacing: 8px;
                padding: 4px 6px;
                font-weight: 700;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border: 2px solid #64748b;
                border-radius: 5px;
                background: #ffffff;
            }
            QCheckBox::indicator:hover {
                border: 2px solid #2563eb;
            }
            QCheckBox::indicator:checked {
                background: #16697a;
                border: 2px solid #16697a;
            }
            QCheckBox::indicator:checked:hover {
                background: #0f5260;
                border: 2px solid #0f5260;
            }
            #developerLlmCheck {
                background: #eef6ff;
                border: 1px solid #93c5fd;
                border-radius: 8px;
                padding: 8px;
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

    def show_developer_mode(self) -> None:
        self._pre_dev_geometry = self.geometry()
        self._pre_dev_flags = self.windowFlags()
        self.hide()
        self.setWindowFlags(Qt.Window)
        self.stack.setCurrentWidget(self.dev_panel)
        self.setAttribute(Qt.WA_TranslucentBackground, False)
        self.showFullScreen()
        for slot_idx in range(DEVELOPER_SLOT_COUNT):
            if slot_idx in self.dev_slot_progress_views:
                self.dev_slot_progress_views[slot_idx]["status_label"].setText(f"Test {slot_idx + 1}: Loading datasets")
        QTimer.singleShot(120, self.refresh_developer_datasets)

    def leave_developer_mode(self) -> None:
        if self.dev_threads:
            QMessageBox.information(self, "Experiment running", "Stop the running experiment before leaving developer mode.")
            return
        self.hide()
        if self._pre_dev_flags is not None:
            self.setWindowFlags(self._pre_dev_flags)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.showNormal()
        self.stack.setCurrentWidget(self.panel)
        if self._pre_dev_geometry is not None:
            self.setGeometry(self._pre_dev_geometry)
        else:
            self.resize(PANEL_SIZE)
        self.show()

    def refresh_developer_datasets(self) -> None:
        if not self.dev_slot_widgets:
            return
        current_names = {
            slot_idx: widgets["dataset_combo"].currentText()
            for slot_idx, widgets in enumerate(self.dev_slot_widgets)
        }
        current_paths = {
            slot_idx: self._developer_selected_dataset_path(slot_idx)
            for slot_idx in range(len(self.dev_slot_widgets))
        }
        self.dev_datasets = []
        display_names = {
            "spam_binary_test_4source_all.csv": "Clean test · original 4 sources",
            "spam_binary_test_modern_sources.csv": "Clean test · modern sources",
            "spam_binary_test_all_sources_latest.csv": "Clean test · ALL sources",
        }
        for path in _developer_dataset_paths():
            try:
                summary = _developer_dataset_summary(path)
            except Exception as exc:
                for slot_idx in range(DEVELOPER_SLOT_COUNT):
                    self._developer_append_log(slot_idx, f"Could not read {path}: {exc}")
                continue
            if "binary_label" not in summary.get("fields", []):
                continue
            summary["name"] = display_names.get(path.name, path.name)
            self.dev_datasets.append(summary)
        for slot_idx, widgets in enumerate(self.dev_slot_widgets):
            combo = widgets["dataset_combo"]
            combo.blockSignals(True)
            combo.clear()
            combo.addItem("-- Select dataset --", None)
            for item in self.dev_datasets:
                combo.addItem(item["name"], item)
            combo.blockSignals(False)
            restored = False
            current_name = current_names.get(slot_idx) or ""
            if current_name:
                idx = combo.findText(current_name)
                if idx >= 0:
                    combo.setCurrentIndex(idx)
                    restored = True
            current_path = current_paths.get(slot_idx) or ""
            if not restored and current_path:
                for idx in range(combo.count()):
                    item = combo.itemData(idx)
                    if isinstance(item, dict) and item.get("path") == current_path:
                        combo.setCurrentIndex(idx)
                        restored = True
                        break
            if not restored:
                combo.setCurrentIndex(0)
            self._developer_dataset_changed(slot_idx, combo.currentIndex())
        for slot_idx in range(DEVELOPER_SLOT_COUNT):
            if slot_idx in self.dev_slot_progress_views:
                self.dev_slot_progress_views[slot_idx]["status_label"].setText(f"Test {slot_idx + 1}: Ready")
        self._developer_refresh_timing_labels()

    def _developer_selected_dataset_path(self, slot_idx: int) -> str:
        if not self.dev_slot_widgets:
            return ""
        data = self.dev_slot_widgets[slot_idx]["dataset_combo"].currentData()
        if isinstance(data, dict):
            return str(data.get("path") or "")
        return str(data or "")

    def _developer_finished_dashboard_slots(self) -> list[int]:
        finished_slots: list[int] = []
        for slot_idx in range(DEVELOPER_SLOT_COUNT):
            if slot_idx in self.dev_threads:
                continue
            timing = self.dev_slot_timing.get(slot_idx) or {}
            if str(timing.get("state") or "") != "finished":
                continue
            metrics = self.dev_slot_metrics.get(slot_idx) or {}
            if not isinstance(metrics, dict) or int(metrics.get("total") or 0) <= 0:
                continue
            finished_slots.append(slot_idx)
        return finished_slots

    def _update_developer_dashboard_button(self) -> None:
        button = self.dev_export_dashboard_button
        if button is None:
            return
        finished_count = len(self._developer_finished_dashboard_slots())
        enabled = 2 <= finished_count <= DEVELOPER_SLOT_COUNT
        button.setEnabled(enabled)
        if enabled:
            button.setText(f"Export Dashboard ({finished_count})")
            button.setToolTip("Generate a one-page benchmark dashboard image from the finished tests.")
        else:
            button.setText("Export Dashboard")
            button.setToolTip("Finish at least 2 tests before exporting a comparison dashboard.")

    def _developer_dashboard_runs(self) -> list[dict[str, Any]]:
        runs: list[dict[str, Any]] = []
        palette = ["#2E86AB", "#F18F01", "#C73E1D", "#6A994E"]
        for slot_idx in self._developer_finished_dashboard_slots():
            metrics = dict(self.dev_slot_metrics.get(slot_idx) or {})
            config = dict(self.dev_last_configs.get(slot_idx) or {})
            timing = dict(self.dev_slot_timing.get(slot_idx) or {})
            started_at = timing.get("started_at")
            finished_at = timing.get("finished_at")
            if not isinstance(started_at, (int, float)):
                started_at = None
            if not isinstance(finished_at, (int, float)):
                finished_at = None
            runtime_seconds = 0.0
            if started_at is not None and finished_at is not None:
                runtime_seconds = max(0.0, float(finished_at) - float(started_at))
            elif started_at is not None:
                runtime_seconds = max(0.0, time.time() - float(started_at))
            provider = str(config.get("provider") or "")
            model = str(config.get("model") or "")
            runs.append(
                {
                    "slot_idx": slot_idx,
                    "name": f"Test{slot_idx + 1}",
                    "model_label": _developer_dashboard_model_label(provider, model),
                    "provider": provider,
                    "model": model,
                    "color": palette[slot_idx % len(palette)],
                    "runtime_min": runtime_seconds / 60.0,
                    "accuracy": float(metrics.get("accuracy") or 0.0),
                    "fpr": float(metrics.get("fpr") or 0.0),
                    "recall": float(metrics.get("recall") or 0.0),
                    "precision": float(metrics.get("precision") or 0.0),
                    "f1": float(metrics.get("f1") or 0.0),
                    "llm_used": int(metrics.get("llm_used") or 0),
                    "llm_applied": int(metrics.get("llm_applied") or 0),
                    "llm_errors": int(metrics.get("llm_errors") or 0),
                    "delta_fpr": float(metrics.get("delta_fpr") or 0.0),
                    "delta_recall": float(metrics.get("delta_recall") or 0.0),
                    "fp": int(metrics.get("fp") or 0),
                    "fn": int(metrics.get("fn") or 0),
                }
            )
        return runs

    def export_developer_dashboard(self) -> None:
        runs = self._developer_dashboard_runs()
        if len(runs) < 2:
            QMessageBox.information(
                self,
                "Not enough finished tests",
                "Finish at least 2 tests before exporting a comparison dashboard.",
            )
            return
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        out_path = DEVELOPER_RUNS_DIR / f"developer_run_comparison_dashboard_{timestamp}.png"
        try:
            saved_path = _developer_export_dashboard_image(runs, out_path)
        except Exception as exc:
            QMessageBox.critical(self, "Export failed", f"Could not generate the dashboard image.\n\n{exc}")
            return
        QMessageBox.information(
            self,
            "Dashboard exported",
            f"Saved comparison dashboard for {len(runs)} finished test(s):\n{saved_path}",
        )

    def _developer_refresh_timing_labels(self) -> None:
        now = time.time()
        for slot_idx in range(DEVELOPER_SLOT_COUNT):
            progress_widgets = self.dev_slot_progress_views.get(slot_idx)
            timing = self.dev_slot_timing.get(slot_idx) or {}
            if not progress_widgets:
                continue
            started_at = timing.get("started_at")
            finished_at = timing.get("finished_at")
            state = str(timing.get("state") or "idle")
            if started_at is None:
                elapsed = 0.0
            elif finished_at is not None:
                elapsed = max(0.0, finished_at - started_at)
            elif state in {"running", "stopping"}:
                elapsed = max(0.0, now - started_at)
            else:
                elapsed = max(0.0, now - started_at)
            progress_widgets["timing_label"].setText(
                "Started: "
                + _format_dev_timestamp(started_at)
                + "\nFinished: "
                + _format_dev_timestamp(finished_at)
                + "\nElapsed: "
                + _format_dev_duration(elapsed)
            )
        self._update_developer_dashboard_button()

    def _developer_dataset_changed(self, slot_idx: int, index: int) -> None:
        if index < 0:
            return
        widgets = self.dev_slot_widgets[slot_idx]
        combo_item = widgets["dataset_combo"].itemData(index)
        if not isinstance(combo_item, dict):
            widgets["dataset_info"].setText("No dataset selected")
            widgets["source_list"].clear()
            return
        item = combo_item
        sources = item.get("sources") or []
        labels = item.get("labels") or []
        preset_sources = item.get("preset_sources") or []
        visible_sources = preset_sources or sources
        row_text = f"{item.get('row_count', 0)}+" if item.get("row_count_is_sampled") else str(item.get("row_count", 0))
        widgets["dataset_info"].setText(
            f"Rows: {row_text}\nSources: {', '.join(visible_sources) or 'n/a'}\nLabels: {', '.join(labels) or 'n/a'}"
        )
        widgets["source_list"].clear()
        if not visible_sources:
            list_item = QListWidgetItem("all")
            list_item.setFlags(list_item.flags() | Qt.ItemIsUserCheckable)
            list_item.setCheckState(Qt.Checked)
            widgets["source_list"].addItem(list_item)
            return
        for source in visible_sources:
            list_item = QListWidgetItem(source)
            list_item.setFlags(list_item.flags() | Qt.ItemIsUserCheckable)
            list_item.setCheckState(Qt.Checked)
            widgets["source_list"].addItem(list_item)

    def _developer_selected_sources(self, slot_idx: int) -> list[str]:
        data = self.dev_slot_widgets[slot_idx]["dataset_combo"].currentData() if self.dev_slot_widgets else None
        if isinstance(data, dict):
            preset_sources = data.get("preset_sources") or []
            if preset_sources:
                return list(preset_sources)
        sources: list[str] = []
        source_list = self.dev_slot_widgets[slot_idx]["source_list"]
        for idx in range(source_list.count()):
            item = source_list.item(idx)
            if item.checkState() == Qt.Checked and item.text() != "all":
                sources.append(item.text())
        return sources

    def _developer_build_config(self, slot_idx: int, *, resume: bool = False) -> dict[str, Any]:
        dataset_path = self._developer_selected_dataset_path(slot_idx)
        if not dataset_path:
            return {}
        widgets = self.dev_slot_widgets[slot_idx]
        provider = widgets["model_combo"].currentText().strip()
        model = _model_selector_text(widgets["model_input"]) or _desktop_model_default(provider)
        if resume and slot_idx in self.dev_last_configs:
            config = dict(self.dev_last_configs[slot_idx])
            config["offset"] = int(self.dev_last_completed.get(slot_idx, 0))
            config["limit"] = int(widgets["limit_spin"].value())
            config["sample_mode"] = widgets["sample_mode_combo"].currentText()
            config["llm_final_review"] = bool(widgets["llm_review_check"].isChecked())
            config.setdefault("llm_allow_positive_downgrade", True)
            config.setdefault("llm_allow_positive_refine", True)
            config.setdefault("llm_allow_normal_upgrade", False)
            config["run_dir"] = str(_developer_slot_run_dir(slot_idx))
            config["overwrite_run_dir"] = False
            return config
        return {
            "dataset_path": dataset_path,
            "sources": self._developer_selected_sources(slot_idx),
            "limit": int(widgets["limit_spin"].value()),
            "offset": 0,
            "sample_mode": widgets["sample_mode_combo"].currentText(),
            "seed": 42,
            "provider": provider,
            "model": model,
            "engine": "content_model_ifelse_llm_guardrail_v2",
            "rspamd_base_url": self.args.base_url,
            "ollama_base_url": self.args.ollama_base_url,
            "llm_final_review": bool(widgets["llm_review_check"].isChecked()),
            "llm_allow_positive_downgrade": True,
            "llm_allow_positive_refine": True,
            "llm_allow_normal_upgrade": False,
            "run_dir": str(_developer_slot_run_dir(slot_idx)),
            "overwrite_run_dir": True,
            "runner": "content_model_ifelse_llm_guardrail_v2",
        }

    def start_developer_experiments(self) -> None:
        started = False
        for slot_idx in range(DEVELOPER_SLOT_COUNT):
            if slot_idx in self.dev_threads:
                continue
            if self._start_developer_experiment(slot_idx, resume=False, show_errors=False):
                started = True
        if not started:
            QMessageBox.information(self, "No tests selected", "Choose a dataset in at least one test slot.")

    def resume_developer_experiments(self) -> None:
        started = False
        for slot_idx in range(DEVELOPER_SLOT_COUNT):
            if slot_idx in self.dev_threads:
                continue
            if self._start_developer_experiment(slot_idx, resume=True, show_errors=False):
                started = True
        if not started:
            QMessageBox.information(self, "No previous run", "There is no selected test slot with resumable history yet.")

    def start_developer_experiment(self, slot_idx: int) -> None:
        self._start_developer_experiment(slot_idx, resume=False, show_errors=True)

    def reset_developer_experiment_slot(self, slot_idx: int) -> None:
        if slot_idx in self.dev_threads:
            QMessageBox.information(self, "Experiment running", f"Stop Test {slot_idx + 1} before starting a new experiment.")
            return
        if slot_idx not in self.dev_slot_progress_views or slot_idx >= len(self.dev_slot_widgets):
            return

        self.dev_last_configs.pop(slot_idx, None)
        self.dev_last_completed[slot_idx] = 0
        self.dev_stop_requested_slots.discard(slot_idx)
        self.dev_pending_restarts.pop(slot_idx, None)
        self.dev_slot_metrics.pop(slot_idx, None)
        self.dev_slot_timing[slot_idx] = {"started_at": None, "finished_at": None, "state": "idle"}

        widgets = self.dev_slot_widgets[slot_idx]
        dataset_combo = widgets["dataset_combo"]
        dataset_combo.setCurrentIndex(0 if dataset_combo.count() else -1)
        widgets["source_list"].clear()
        widgets["dataset_info"].setText("No dataset selected")
        widgets["limit_spin"].setValue(100)
        widgets["sample_mode_combo"].setCurrentText("Balanced 50/50 ham/spam")
        widgets["llm_review_check"].setChecked(True)
        widgets["model_combo"].setCurrentText(self.args.provider)
        _configure_model_selector(widgets["model_input"], self.args.provider, _desktop_model_default(self.args.provider))

        progress_widgets = self.dev_slot_progress_views[slot_idx]
        progress_widgets["progress_bar"].setValue(0)
        progress_widgets["status_label"].setText(f"Test {slot_idx + 1}: New experiment")
        progress_widgets["log_view"].clear()
        self.dev_slot_metric_views[slot_idx].clear()
        self.dev_chart.set_slot_metrics(self.dev_slot_metrics)
        self._developer_refresh_timing_labels()

    def restart_developer_experiment(self, slot_idx: int) -> None:
        config = self._developer_build_config(slot_idx, resume=False)
        if not config:
            QMessageBox.information(self, "No dataset selected", f"Choose a dataset for Test {slot_idx + 1} first.")
            return
        self.dev_last_completed[slot_idx] = 0
        self.dev_last_configs[slot_idx] = dict(config)
        self.dev_pending_restarts.pop(slot_idx, None)
        if slot_idx in self.dev_threads:
            self.dev_pending_restarts[slot_idx] = dict(config)
            self.stop_developer_experiment(slot_idx, restart=True)
            return
        self._start_developer_worker(slot_idx, config)

    def _start_developer_experiment(self, slot_idx: int, *, resume: bool, show_errors: bool) -> bool:
        if slot_idx in self.dev_threads:
            if show_errors:
                QMessageBox.information(self, "Busy", f"Test {slot_idx + 1} is already running.")
            return False
        if resume and slot_idx not in self.dev_last_configs:
            if show_errors:
                QMessageBox.information(self, "No previous run", f"Test {slot_idx + 1} has no resumable history yet.")
            return False
        config = self._developer_build_config(slot_idx, resume=resume)
        if not config:
            if show_errors:
                QMessageBox.information(self, "No dataset selected", f"Choose a dataset for Test {slot_idx + 1} first.")
            progress_widgets = self.dev_slot_progress_views[slot_idx]
            progress_widgets["progress_bar"].setValue(0)
            progress_widgets["status_label"].setText(f"Test {slot_idx + 1}: Idle")
            return False
        if not resume:
            self.dev_last_completed[slot_idx] = 0
        self.dev_last_configs[slot_idx] = dict(config)
        self._start_developer_worker(slot_idx, config)
        return True

    def _start_developer_worker(self, slot_idx: int, config: dict[str, Any]) -> None:
        if slot_idx in self.dev_threads:
            return
        self.dev_stop_requested_slots.discard(slot_idx)
        self.dev_pending_restarts.pop(slot_idx, None)
        self.dev_last_configs[slot_idx] = dict(config)
        self.dev_slot_timing[slot_idx] = {
            "started_at": time.time(),
            "finished_at": None,
            "state": "running",
        }
        progress_widgets = self.dev_slot_progress_views[slot_idx]
        progress_widgets["log_view"].clear()
        progress_widgets["progress_bar"].setValue(0)
        progress_widgets["status_label"].setText(f"Test {slot_idx + 1}: Running")
        self._developer_refresh_timing_labels()
        self._developer_append_log(slot_idx, f"Starting run: {config['run_dir']}")
        self._developer_append_log(
            slot_idx,
            f"Engine: {config['runner']} (configured model: {config['provider']} / {config['model']}; LLM final review={bool(config.get('llm_final_review'))}; normal-upgrade={bool(config.get('llm_allow_normal_upgrade', False))})",
        )
        thread = QThread()
        worker = DeveloperExperimentWorker(config)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(self._developer_progress_from_sender, Qt.QueuedConnection)
        worker.log.connect(self._developer_log_from_sender, Qt.QueuedConnection)
        worker.puter_review_requested.connect(self._handle_developer_puter_review, Qt.QueuedConnection)
        worker.metrics_ready.connect(self._developer_metrics_from_sender, Qt.QueuedConnection)
        worker.finished.connect(self._developer_finished_from_sender, Qt.QueuedConnection)
        worker.failed.connect(self._developer_failed_from_sender, Qt.QueuedConnection)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(self._developer_thread_finished_from_sender, Qt.QueuedConnection)
        self.dev_threads[slot_idx] = thread
        self.dev_workers[slot_idx] = worker
        thread.start()

    def stop_developer_experiments(self) -> None:
        if not self.dev_workers:
            return
        for slot_idx, worker in list(self.dev_workers.items()):
            self.stop_developer_experiment(slot_idx)

    def stop_developer_experiment(self, slot_idx: int, *, restart: bool = False) -> None:
        worker = self.dev_workers.get(slot_idx)
        if worker is None:
            if not restart and slot_idx in self.dev_slot_progress_views:
                self.dev_slot_progress_views[slot_idx]["status_label"].setText(f"Test {slot_idx + 1}: Idle")
            return
        self.dev_stop_requested_slots.add(slot_idx)
        worker.request_stop()
        action = "Restarting" if restart else "Stopping"
        self.dev_slot_progress_views[slot_idx]["status_label"].setText(f"Test {slot_idx + 1}: {action}")
        if slot_idx in self.dev_slot_timing:
            self.dev_slot_timing[slot_idx]["state"] = "stopping"
        self._developer_refresh_timing_labels()
        if restart:
            self._developer_append_log(slot_idx, "Restart requested. This test will restart after the current email.")
        else:
            self._developer_append_log(slot_idx, "Stop requested. This test will stop after the current email.")

    def _developer_progress(self, slot_idx: int, current: int, total: int) -> None:
        last_config = self.dev_last_configs.get(slot_idx, {})
        self.dev_last_completed[slot_idx] = int(last_config.get("offset", 0)) + current
        value = int((current / total) * 100) if total else 0
        self.dev_slot_progress_views[slot_idx]["progress_bar"].setValue(value)
        self.dev_slot_progress_views[slot_idx]["status_label"].setText(f"Test {slot_idx + 1}: Running {current}/{total}")
        self._developer_refresh_timing_labels()

    def _developer_update_metrics(self, slot_idx: int, metrics: object) -> None:
        if not isinstance(metrics, dict):
            return
        self.dev_slot_metrics[slot_idx] = dict(metrics)
        metric_view = self.dev_slot_metric_views.get(slot_idx)
        if isinstance(metric_view, DeveloperMetricCard):
            metric_view.set_metrics(metrics)
        self.dev_chart.set_slot_metrics(self.dev_slot_metrics)

    def _developer_finished(self, slot_idx: int, run_dir: str) -> None:
        if slot_idx in self.dev_slot_timing:
            self.dev_slot_timing[slot_idx]["finished_at"] = time.time()
        if slot_idx in self.dev_stop_requested_slots:
            self.dev_slot_timing[slot_idx]["state"] = "stopped"
            self.dev_slot_progress_views[slot_idx]["status_label"].setText(f"Test {slot_idx + 1}: Stopped")
            self._developer_append_log(slot_idx, f"Stopped. Partial results saved in {run_dir}")
            self._developer_refresh_timing_labels()
            return
        self.dev_slot_timing[slot_idx]["state"] = "finished"
        self.dev_slot_progress_views[slot_idx]["status_label"].setText(f"Test {slot_idx + 1}: Finished")
        self._developer_append_log(slot_idx, f"Finished. Saved results in {run_dir}")
        self._developer_refresh_timing_labels()

    def _developer_failed(self, slot_idx: int, message: str) -> None:
        if slot_idx in self.dev_slot_timing:
            self.dev_slot_timing[slot_idx]["finished_at"] = time.time()
            self.dev_slot_timing[slot_idx]["state"] = "failed"
        self.dev_slot_progress_views[slot_idx]["status_label"].setText(f"Test {slot_idx + 1}: Failed")
        self._developer_append_log(slot_idx, f"ERROR: {message}")
        self._developer_refresh_timing_labels()

    def _developer_thread_finished(self, slot_idx: int) -> None:
        thread = self.dev_threads.pop(slot_idx, None)
        if thread is not None:
            thread.deleteLater()
        self.dev_workers.pop(slot_idx, None)
        self.dev_stop_requested_slots.discard(slot_idx)
        restart_config = self.dev_pending_restarts.pop(slot_idx, None)
        if restart_config is not None:
            self._start_developer_worker(slot_idx, restart_config)

    def _developer_append_log(self, slot_idx: int, text: str) -> None:
        if slot_idx not in self.dev_slot_progress_views:
            return
        log_view = self.dev_slot_progress_views[slot_idx]["log_view"]
        log_view.append(text)
        log_view.verticalScrollBar().setValue(log_view.verticalScrollBar().maximum())

    def _developer_slot_for_worker(self, worker: QObject | None) -> int | None:
        if worker is None:
            return None
        for slot_idx, known_worker in self.dev_workers.items():
            if known_worker is worker:
                return slot_idx
        return None

    def _developer_slot_for_thread(self, thread: QObject | None) -> int | None:
        if thread is None:
            return None
        for slot_idx, known_thread in self.dev_threads.items():
            if known_thread is thread:
                return slot_idx
        return None

    def _developer_progress_from_sender(self, current: int, total: int) -> None:
        slot_idx = self._developer_slot_for_worker(self.sender())
        if slot_idx is None:
            return
        self._developer_progress(slot_idx, current, total)

    def _developer_log_from_sender(self, text: str) -> None:
        slot_idx = self._developer_slot_for_worker(self.sender())
        if slot_idx is None:
            return
        self._developer_append_log(slot_idx, text)

    def _developer_metrics_from_sender(self, metrics: object) -> None:
        slot_idx = self._developer_slot_for_worker(self.sender())
        if slot_idx is None:
            return
        self._developer_update_metrics(slot_idx, metrics)

    def _developer_finished_from_sender(self, run_dir: str) -> None:
        slot_idx = self._developer_slot_for_worker(self.sender())
        if slot_idx is None:
            return
        self._developer_finished(slot_idx, run_dir)

    def _developer_failed_from_sender(self, message: str) -> None:
        slot_idx = self._developer_slot_for_worker(self.sender())
        if slot_idx is None:
            return
        self._developer_failed(slot_idx, message)

    def _developer_thread_finished_from_sender(self) -> None:
        slot_idx = self._developer_slot_for_thread(self.sender())
        if slot_idx is None:
            return
        self._developer_thread_finished(slot_idx)

    def initialize_runtime(self) -> None:
        if self.args.provider == PUTER_PROVIDER:
            self.progress.clear()
            self.set_progress_state("success")
            self.append_progress(f"ChatGPT will initialize on the first request for {self.args.model}")
            self.set_status("ready", f"Ready: {self.args.provider} / {self.args.model}")
            return
        self._run_agent("", hidden=True, setup_only=True)

    def _sync_provider_ui(self, provider: str) -> None:
        is_puter = provider == PUTER_PROVIDER
        if hasattr(self, "send_button"):
            self.send_button.setEnabled(True)
            self.send_button.setText("Send")
        if hasattr(self, "chatgpt_login_button"):
            self.chatgpt_login_button.setVisible(is_puter)
        if hasattr(self, "chatgpt_logout_button"):
            self.chatgpt_logout_button.setVisible(is_puter)
        if not hasattr(self, "input"):
            return
        self.input.setReadOnly(False)
        if is_puter:
            self.input.setPlaceholderText(
                "Ask anything. ChatGPT runs in the same chat UI as the other providers."
            )
        else:
            self.input.setPlaceholderText("Ask anything, or paste a raw email/header here.")

    def _puter_bridge_url(self) -> str:
        return f"http://127.0.0.1:{PUTER_WEB_PORT}/static/puter_bridge.html?v=developer-retry-v2"

    def _puter_auth_url(self) -> str:
        return f"http://127.0.0.1:{PUTER_WEB_PORT}/static/puter_auth.html"

    def _ensure_puter_local_server(self) -> None:
        if _port_open("127.0.0.1", PUTER_WEB_PORT):
            return
        if self.puter_server_process is not None and self.puter_server_process.poll() is None:
            if _wait_for_port("127.0.0.1", PUTER_WEB_PORT, timeout_s=2.0):
                return

        self.puter_server_process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "web.server:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(PUTER_WEB_PORT),
            ],
            cwd=str(PROJECT_ROOT),
            stdout=open(PUTER_BRIDGE_LOG, "a", encoding="utf-8"),
            stderr=subprocess.STDOUT,
            text=True,
        )
        if not _wait_for_port("127.0.0.1", PUTER_WEB_PORT, timeout_s=10.0):
            raise RuntimeError(
                f"Timed out starting the local ChatGPT bridge server on port {PUTER_WEB_PORT}. "
                f"See {PUTER_BRIDGE_LOG} for details."
            )

    def _ensure_puter_bridge(self) -> PuterBridgeController:
        self._ensure_puter_local_server()
        if self.puter_profile is None:
            from PySide6.QtWebEngineCore import QWebEngineProfile

            self.puter_profile = QWebEngineProfile("puter_shared_profile", self)
        if self.puter_bridge is None:
            bridge = PuterBridgeController(self._puter_bridge_url(), self.puter_profile, self)
            bridge.ready.connect(self._puter_bridge_ready)
            bridge.chunk.connect(self._puter_bridge_chunk)
            bridge.completed.connect(self._puter_bridge_completed)
            bridge.completed.connect(self._developer_puter_bridge_completed)
            bridge.auth_required.connect(self._puter_bridge_auth_required)
            bridge.auth_required.connect(self._developer_puter_bridge_auth_required)
            bridge.failed.connect(self._puter_bridge_failed)
            bridge.failed.connect(self._developer_puter_bridge_failed)
            bridge.ensure_loaded()
            self.puter_bridge = bridge
        return self.puter_bridge

    def _puter_bridge_ready(self) -> None:
        if self.args.provider != PUTER_PROVIDER:
            return
        if self.puter_retry_after_auth and self.puter_bridge is not None and self.puter_pending_messages is not None and self.puter_active_request_id is not None:
            self.puter_retry_after_auth = False
            self.append_progress("ChatGPT session refreshed. Retrying request.")
            self.puter_bridge.submit(self.puter_pending_messages, self.args.model, self.puter_active_request_id)
            return
        if self.developer_puter_retry_after_auth and self.puter_bridge is not None:
            self.developer_puter_retry_after_auth = False
            retry_ids = list(self.developer_puter_auth_retry_ids)
            self.developer_puter_auth_retry_ids.clear()
            for request_id in retry_ids:
                payload = self.developer_puter_requests.get(request_id)
                if payload is None:
                    continue
                model = str(payload.get("model") or _desktop_model_default(PUTER_PROVIDER))
                prompt = str(payload.get("prompt") or "")
                self.puter_bridge.submit([{"role": "user", "content": prompt}], model, request_id)
            return
        if self.puter_active_request_id is None:
            self.set_progress_state("success")
            self.set_status("ready", f"Ready: {self.args.provider} / {self.args.model}")

    def _puter_bridge_chunk(self, request_id: int, _text: str, full_text: str) -> None:
        if request_id != self.puter_active_request_id:
            return
        self.progress.setPlainText(full_text)
        self.progress.verticalScrollBar().setValue(self.progress.verticalScrollBar().maximum())

    def _finish_puter_request(self) -> None:
        self.puter_active_request_id = None
        self.puter_pending_messages = None
        self.send_button.setEnabled(True)
        self.set_status("ready", f"Ready: {self.args.provider} / {self.args.model}")

    def _ensure_puter_auth_window(self) -> None:
        if self.puter_auth_window is not None:
            return

        from PySide6.QtCore import QUrl
        from PySide6.QtWebEngineWidgets import QWebEngineView
        from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineSettings

        self._ensure_puter_bridge()

        window = QMainWindow(self)
        window.setWindowTitle("Email Guardian · 登录 ChatGPT")
        view = QWebEngineView(window)

        controller = self
        popup_windows: list[QMainWindow] = []

        class _AuthPage(QWebEnginePage):
            def createWindow(self, window_type):  # type: ignore[override]
                del window_type
                popup_window = QMainWindow()
                popup_window.setWindowTitle("登录 ChatGPT")
                popup_view = QWebEngineView(popup_window)
                popup_page = QWebEnginePage(controller.puter_profile, popup_view)
                popup_view.setPage(popup_page)
                popup_window.setCentralWidget(popup_view)
                popup_window.resize(520, 720)
                popup_window.show()
                popup_windows.append(popup_window)

                def _cleanup_popup() -> None:
                    try:
                        popup_windows.remove(popup_window)
                    except ValueError:
                        pass

                popup_window.destroyed.connect(_cleanup_popup)
                return popup_page

            def javaScriptConsoleMessage(self, level, message, line_number, source_id):  # type: ignore[override]
                del level, line_number, source_id
                prefix = "__PUTER_AUTH__"
                if not message.startswith(prefix):
                    return
                try:
                    payload = json.loads(message[len(prefix):])
                except json.JSONDecodeError:
                    return
                auth_type = str(payload.get("type", ""))
                auth_message = str(payload.get("message", ""))
                if auth_type == "ready":
                    controller.puter_auth_window_ready.emit()
                elif auth_type == "success":
                    controller.puter_auth_success_signal.emit()
                elif auth_type == "error":
                    controller.puter_auth_failure_signal.emit(auth_message or "ChatGPT login failed")

        page = _AuthPage(self.puter_profile, view)
        page.settings().setAttribute(
            QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls,
            True,
        )
        view.setPage(page)
        view.load(QUrl(self._puter_auth_url()))
        window.setCentralWidget(view)
        window.resize(520, 720)
        self.puter_auth_window = window
        self.puter_auth_view = view

    def login_chatgpt(self) -> None:
        if self.provider_combo.currentText().strip() != PUTER_PROVIDER:
            return
        self._ensure_puter_auth_window()
        if self.puter_auth_window is not None:
            self.puter_auth_window.show()
            self.puter_auth_window.raise_()
            self.puter_auth_window.activateWindow()
        self.set_progress_state("busy")
        self.append_progress("Opening ChatGPT login window.")

    def logout_chatgpt(self) -> None:
        if self.provider_combo.currentText().strip() != PUTER_PROVIDER:
            return
        self.puter_history = []
        self.puter_pending_messages = None
        self.puter_active_request_id = None
        self.puter_retry_after_auth = False
        self.developer_puter_auth_retry_ids.clear()
        self.developer_puter_retry_after_auth = False
        if self.puter_bridge is not None:
            self.puter_bridge.sign_out()
        if self.puter_profile is not None:
            try:
                self.puter_profile.cookieStore().deleteAllCookies()
                self.puter_profile.clearHttpCache()
                self.puter_profile.clearAllVisitedLinks()
            except Exception:
                pass
        if self.puter_auth_view is not None:
            from PySide6.QtCore import QUrl

            self.puter_auth_view.load(QUrl(self._puter_auth_url()))
        if self.puter_bridge is not None:
            self.puter_bridge.reload()
        self.set_progress_state("success")
        self.append_progress("ChatGPT login has been cleared. Use 登录 ChatGPT to sign in again.")
        self.set_status("ready", f"Ready: {self.args.provider} / {self.args.model}")

    def _puter_bridge_auth_required(self, request_id: int, message: str) -> None:
        if request_id != self.puter_active_request_id:
            return
        self.puter_auth_in_progress = True
        self.set_progress_state("busy")
        self.set_status("starting", "ChatGPT login required")
        self.append_progress(message)
        self.append_progress("A ChatGPT login window is opening. Complete it, then the message will retry automatically.")
        self._ensure_puter_auth_window()
        self.puter_auth_window.show()
        self.puter_auth_window.raise_()
        self.puter_auth_window.activateWindow()

    def _on_puter_auth_window_ready(self) -> None:
        self.append_progress("ChatGPT login window is ready")

    def _puter_auth_succeeded(self) -> None:
        self.puter_auth_in_progress = False
        if self.puter_auth_window is not None:
            self.puter_auth_window.hide()
        self.append_progress("ChatGPT login completed. Refreshing session before retry.")
        if self.developer_puter_auth_retry_ids and self.puter_bridge is not None:
            self.developer_puter_retry_after_auth = True
            self.puter_bridge.reload()
            return
        if self.puter_bridge is None or self.puter_pending_messages is None or self.puter_active_request_id is None:
            self.set_progress_state("success")
            self.set_status("ready", f"Ready: {self.args.provider} / {self.args.model}")
            self.send_button.setEnabled(True)
            return
        self.puter_retry_after_auth = True
        self.puter_bridge.reload()

    def _puter_auth_failed(self, message: str) -> None:
        self.puter_auth_in_progress = False
        self.puter_retry_after_auth = False
        if self.puter_auth_window is not None:
            self.puter_auth_window.hide()
        self._finish_puter_request()
        self._show_failure(message)

    def _puter_bridge_completed(self, request_id: int, text: str) -> None:
        if request_id != self.puter_active_request_id:
            return
        if self.puter_pending_messages is not None:
            self.puter_history = self.puter_pending_messages + [{"role": "assistant", "content": text}]
        self._finish_puter_request()
        self._append_result(text)

    def _puter_bridge_failed(self, request_id: int, message: str) -> None:
        if request_id == 0:
            self.puter_active_request_id = None
            self.puter_pending_messages = None
            self.set_progress_state("error")
            self.set_status("error", "Error")
            self.append_chat_bubble("error", f"Request failed.\nReason: {message}")
            self.send_button.setEnabled(True)
            return
        if request_id != self.puter_active_request_id:
            return
        if self.puter_auth_in_progress:
            return
        self._finish_puter_request()
        self._show_failure(message)

    def _complete_developer_puter_request(self, request_id: int, result: dict[str, Any]) -> None:
        payload = self.developer_puter_requests.pop(request_id, None)
        if payload is None:
            return
        self.developer_puter_auth_retry_ids.discard(request_id)
        payload["result"] = result
        event = payload.get("event")
        if isinstance(event, threading.Event):
            event.set()

    def _submit_developer_puter_payload(self, payload: dict[str, Any]) -> None:
        bridge = self._ensure_puter_bridge()
        request_id = self.puter_next_request_id
        self.puter_next_request_id += 1
        self.developer_puter_requests[request_id] = payload
        payload["request_id"] = request_id
        model = str(payload.get("model") or _desktop_model_default(PUTER_PROVIDER))
        prompt = str(payload.get("prompt") or "")
        bridge.submit([{"role": "user", "content": prompt}], model, request_id)

    def _retry_developer_puter_request(self, payload: dict[str, Any], message: str) -> bool:
        attempt = int(payload.get("attempt") or 1)
        max_attempts = int(payload.get("max_attempts") or 1)
        if attempt >= max_attempts:
            return False
        payload["attempt"] = attempt + 1
        delay_ms = min(15000, 1000 * (2 ** (attempt - 1)))
        payload["last_error"] = message
        QTimer.singleShot(delay_ms, lambda p=payload: self._resubmit_developer_puter_payload(p))
        return True

    def _resubmit_developer_puter_payload(self, payload: dict[str, Any]) -> None:
        if payload.get("result") is not None:
            return
        try:
            self._submit_developer_puter_payload(payload)
        except Exception as exc:
            payload["result"] = {
                "ok": False,
                "verdict": None,
                "reason": str(exc),
                "raw_text": "",
            }
            event = payload.get("event")
            if isinstance(event, threading.Event):
                event.set()

    def _handle_developer_puter_review(self, payload: object) -> None:
        if not isinstance(payload, dict):
            return
        try:
            self._submit_developer_puter_payload(payload)
        except Exception as exc:
            payload["result"] = {
                "ok": False,
                "verdict": None,
                "reason": str(exc),
                "raw_text": "",
            }
            event = payload.get("event")
            if isinstance(event, threading.Event):
                event.set()

    def _developer_puter_bridge_completed(self, request_id: int, text: str) -> None:
        if request_id not in self.developer_puter_requests:
            return
        self._complete_developer_puter_request(request_id, _developer_parse_llm_review(text))

    def _developer_puter_bridge_failed(self, request_id: int, message: str) -> None:
        if request_id == 0:
            for pending_id in list(self.developer_puter_requests):
                self._complete_developer_puter_request(
                    pending_id,
                    {"ok": False, "verdict": None, "reason": message, "raw_text": ""},
            )
            return
        payload = self.developer_puter_requests.pop(request_id, None)
        if payload is None:
            return
        self.developer_puter_auth_retry_ids.discard(request_id)
        if self._retry_developer_puter_request(payload, message):
            return
        attempt = int(payload.get("attempt") or 1)
        max_attempts = int(payload.get("max_attempts") or 1)
        reason = f"{message} (attempt {attempt}/{max_attempts})"
        if payload.get("last_error") and str(payload.get("last_error")) != message:
            reason = f"{reason}; previous error: {payload.get('last_error')}"
        payload["result"] = {
            "ok": False,
            "verdict": None,
            "reason": reason,
            "raw_text": "",
        }
        event = payload.get("event")
        if isinstance(event, threading.Event):
            event.set()

    def _developer_puter_bridge_auth_required(self, request_id: int, message: str) -> None:
        if request_id not in self.developer_puter_requests:
            return
        self.developer_puter_auth_retry_ids.add(request_id)
        try:
            self._ensure_puter_auth_window()
            self.puter_auth_window.show()
            self.puter_auth_window.raise_()
            self.puter_auth_window.activateWindow()
        except Exception:
            self.developer_puter_auth_retry_ids.discard(request_id)
            self._complete_developer_puter_request(
                request_id,
                {
                    "ok": False,
                    "verdict": None,
                    "reason": message or "ChatGPT login required before developer final review can run.",
                    "raw_text": "",
                },
            )

    def _run_puter_agent(
        self,
        prompt: str,
        *,
        hidden: bool = False,
        setup_only: bool = False,
        display_prompt: str | None = None,
        initial_progress: list[str] | None = None,
    ) -> None:
        if self.puter_active_request_id is not None:
            QMessageBox.information(self, "Busy", "ChatGPT is still working on the current request.")
            return

        self.set_status("busy", "Working")
        self.send_button.setEnabled(False)
        if not hidden:
            self.append_chat_bubble("user", display_prompt if display_prompt is not None else prompt)
        self.progress.clear()
        self.set_progress_state("busy")
        for line in initial_progress or []:
            self.append_progress(line)
        self.append_progress(f"Preparing ChatGPT ({self.args.model})")
        QApplication.processEvents()

        try:
            bridge = self._ensure_puter_bridge()
        except Exception as exc:
            self.send_button.setEnabled(True)
            self.set_progress_state("error")
            self.set_status("error", "Error")
            self.append_chat_bubble("error", f"Request failed.\nReason: {exc}")
            return

        if setup_only:
            if bridge.is_ready:
                self._puter_bridge_ready()
            else:
                self.append_progress("Waiting for ChatGPT to finish loading")
            self.send_button.setEnabled(True)
            return

        self.append_progress(f"Calling ChatGPT ({self.args.model})")
        QApplication.processEvents()

        request_id = self.puter_next_request_id
        self.puter_next_request_id += 1
        messages = self.puter_history + [{"role": "user", "content": prompt}]
        self.puter_pending_messages = messages
        self.puter_active_request_id = request_id
        bridge.submit(messages, self.args.model, request_id)

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
        if self.isMaximized():
            self.showNormal()
        old_geo = self.geometry()
        target = QRect(old_geo.x(), old_geo.y(), BALL_SIZE, BALL_SIZE)
        def after_collapse() -> None:
            self.stack.setCurrentWidget(self.ball_page)
            self._use_ball_window_flags()

        self._animate_geometry(target, after=after_collapse)

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
                    "email_address": str(data.get("email_address", "")),
                    "uid": str(data.get("uid", "")),
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
        _configure_model_selector(self.model_input, provider, _desktop_model_default(provider))
        self._sync_provider_ui(provider)

    def switch_model(self) -> None:
        if self.thread is not None:
            QMessageBox.information(self, "Busy", "Wait for the current request to finish before switching models.")
            return

        provider = self.provider_combo.currentText().strip()
        model = _model_selector_text(self.model_input)
        if provider not in {"gemini", "ollama", TOKENROUTER_PROVIDER, PUTER_PROVIDER}:
            QMessageBox.warning(self, "Invalid provider", "Choose gemini, ollama, tokenrouter, or puter-openai.")
            return
        if not model:
            QMessageBox.warning(self, "Missing model", "Enter a model name before switching.")
            return

        self.args.provider = provider
        self.args.model = model
        self.runtime = None
        self.puter_history = []
        self.puter_pending_messages = None
        self.puter_active_request_id = None
        self.progress.clear()
        self.set_progress_state("busy")
        self.append_progress(f"Switching to {provider} / {model}")
        self.set_status("starting", "Starting")
        self._sync_provider_ui(provider)
        self.initialize_runtime()

    def send_chat(self) -> None:
        prompt = self.input.toPlainText().strip()
        if not prompt:
            return
        self.input.clear()
        prompt_to_send = prompt
        prefer_ai_response = False
        initial_progress: list[str] = []
        direct_referenced_emails: list[dict[str, str]] | None = None
        if self.referenced_emails:
            try:
                self.progress.clear()
                self.set_progress_state("busy")
                self.append_progress("Fetching original referenced email from IMAP by UID")
                referenced_emails = resolve_referenced_email_originals(self.referenced_emails)
                self.append_progress(f"Fetched {len(referenced_emails)} original email(s) from IMAP")
                initial_progress = [
                    "Fetching original referenced email from IMAP by UID",
                    f"Fetched {len(referenced_emails)} original email(s) from IMAP",
                ]
            except Exception as exc:
                QMessageBox.warning(self, "Could not fetch original email", str(exc))
                return
            direct_referenced_emails = referenced_emails
            prompt_to_send = build_referenced_email_prompt(prompt, referenced_emails)
            prefer_ai_response = len(self.referenced_emails) > 1
            self.clear_referenced_email()
        elif _looks_like_raw_email_input(prompt):
            pasted_email = [_email_item_from_raw_text(prompt)]
            initial_progress = ["Using pasted email content as raw email input"]
            direct_referenced_emails = pasted_email
            prompt_to_send = build_referenced_email_prompt("Analyze the pasted email", pasted_email)
        self._run_agent(
            prompt_to_send,
            display_prompt=prompt,
            prefer_ai_response=prefer_ai_response,
            initial_progress=initial_progress,
            direct_referenced_emails=direct_referenced_emails,
        )

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
        self.puter_history = []
        self.puter_pending_messages = None
        self.puter_active_request_id = None
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
        initial_progress: list[str] | None = None,
        direct_referenced_emails: list[dict[str, str]] | None = None,
    ) -> None:
        if self.args.provider == PUTER_PROVIDER and direct_referenced_emails is None:
            self._run_puter_agent(
                prompt,
                hidden=hidden,
                setup_only=setup_only,
                display_prompt=display_prompt,
                initial_progress=initial_progress,
            )
            return
        if self.thread is not None:
            QMessageBox.information(self, "Busy", "Email Guardian is still working on the current request.")
            return

        self.set_status("busy", "Working")
        self.send_button.setEnabled(False)
        if not hidden:
            self.append_chat_bubble("user", display_prompt if display_prompt is not None else prompt)
        self.progress.clear()
        self.set_progress_state("busy")
        for line in initial_progress or []:
            self.append_progress(line)

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
            direct_referenced_emails=direct_referenced_emails,
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
        for worker in list(self.dev_workers.values()):
            worker.request_stop()
        for thread in list(self.dev_threads.values()):
            thread.quit()
            thread.wait(timeout_ms)

    def _full_shutdown_cleanup(self) -> None:
        if self.puter_server_process is not None and self.puter_server_process.poll() is None:
            self.puter_server_process.terminate()
            try:
                self.puter_server_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.puter_server_process.kill()
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
    env_provider = (os.getenv("LLM_PROVIDER") or "").strip().lower()
    default_provider = env_provider if env_provider in {PUTER_PROVIDER, TOKENROUTER_PROVIDER} else resolve_provider()
    parser = argparse.ArgumentParser(description="Run Email Guardian as a desktop pet.")
    parser.add_argument("--provider", default=default_provider, choices=["ollama", "gemini", TOKENROUTER_PROVIDER, PUTER_PROVIDER])
    parser.add_argument("--model", default=_desktop_model_default(default_provider))
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

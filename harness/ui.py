from __future__ import annotations

import logging
from typing import Any

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage

from .runtime import latest_ai_message, parse_tool_payload, summarize_invoked_tools


def configure_quiet_logging() -> None:
    for name in (
        "httpx",
        "httpcore",
        "mcp",
        "mcp.server",
        "mcp.server.lowlevel",
        "mcp.server.fastmcp",
    ):
        logging.getLogger(name).setLevel(logging.WARNING)


def _section(title: str) -> str:
    return title


def _kv(label: str, value: object) -> str:
    return f"{label:<10} {value}"


def _compact(text: str, limit: int = 140) -> str:
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _classify_email_type(subject: str, from_address: str) -> str:
    subject_lc = (subject or "").lower()
    from_lc = (from_address or "").lower()
    text = f"{subject_lc} {from_lc}"

    if any(token in text for token in ("columbia", ".edu", "university", "school", "course", "canvas", "professor")):
        return "School email"
    if any(token in text for token in ("invoice", "receipt", "bill", "payment", "statement", "charged", "subscription")):
        return "Billing email"
    if any(token in text for token in ("security alert", "verify", "password", "sign-in", "login", "account alert", "suspended")):
        return "Security / account alert"
    if any(token in text for token in ("sale", "offer", "deal", "save", "coupon", "newsletter", "weekly ad", "promotion", "promo")):
        return "Promotional / advertising email"
    if any(token in text for token in ("order", "shipment", "delivered", "shipping", "package", "tracking", "return")):
        return "Shopping / delivery email"
    if any(token in text for token in ("interview", "recruiting", "job", "career", "application")):
        return "Work / recruiting email"
    if any(token in text for token in ("bank", "credit card", "transaction", "zelle", "paypal", "venmo")):
        return "Financial email"
    if any(token in text for token in ("meeting", "calendar", "zoom", "slack", "workspace")):
        return "Work / collaboration email"
    if any(token in text for token in ("flight", "hotel", "booking", "reservation", "trip")):
        return "Travel email"
    if any(token in text for token in ("google", "microsoft", "apple", "github", "account")):
        return "Account notification"
    return "General notification"


def render_startup_banner(
    *,
    provider: str,
    model: str,
    rspamd_base_url: str,
    ollama_base_url: str | None = None,
) -> str:
    title = "Email Guardian"
    line = "─" * 52
    lines = [
        line,
        title,
        line,
        _kv("Provider", provider),
        _kv("Model", model),
    ]
    if ollama_base_url:
        lines.append(_kv("Ollama", ollama_base_url))
    lines.append(_kv("Rspamd", rspamd_base_url))
    lines.append(line)
    return "\n".join(lines)


def render_ready_message() -> str:
    return "\n".join(
        [
            "Ready",
            "",
            "Examples",
            '  Analyze this email for phishing.',
            '  查看我最近是否有钓鱼邮件',
            '  Bind my Gmail and start monitoring.',
            "",
            "Commands",
            "  /help  /reset  /trace on|off  /quit",
        ]
    )


def render_progress_line(text: str) -> str:
    return f"· {text}"


def render_error(exc: Exception, *, quota: bool = False, tool_summary: str = "") -> str:
    lines = ["Request failed."]
    lines.append("Reason: model quota exhausted" if quota else f"Reason: {exc}")
    if tool_summary:
        lines.extend(["", "Completed tools", tool_summary])
    return "\n".join(lines)


def _last_tool_payload(messages: list[BaseMessage], tool_name: str) -> dict[str, Any] | None:
    for message in reversed(messages):
        if isinstance(message, ToolMessage) and message.name == tool_name:
            payload = parse_tool_payload(message)
            if isinstance(payload, dict):
                return payload
    return None


def _render_recent_scan(messages: list[BaseMessage], start_idx: int) -> str | None:
    payload = _last_tool_payload(messages[start_idx:], "scan_recent_imap_emails")
    if not payload or payload.get("ok") is False:
        return None
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    emails = data.get("emails")
    if not isinstance(emails, list):
        return None

    lines = [
        _section("Recent Mail Scan"),
        f"Mailbox: {data.get('email_address', 'unknown')}",
        f"Scanned: {data.get('scanned_count', len(emails))} emails",
        "",
    ]
    for idx, item in enumerate(emails, 1):
        if not isinstance(item, dict):
            continue
        lines.extend(
            [
                f"{idx}. {item.get('subject') or '(no subject)'}",
                f"From: {item.get('from_address') or 'unknown'}"
                f"  ·  {_classify_email_type(str(item.get('subject') or ''), str(item.get('from_address') or ''))}",
                f"Verdict: {item.get('final_verdict') or 'unknown'}",
                f"Rspamd: {item.get('rspamd_risk_level') or 'unknown'}"
                + (
                    f" ({item.get('rspamd_score')})"
                    if item.get("rspamd_score") is not None
                    else ""
                ),
                f"Header auth: {item.get('header_risk_level') or 'unknown'}",
                f"Why: {item.get('summary') or 'no summary'}",
                "",
            ]
        )
    tool_list = summarize_invoked_tools(messages, start_idx)
    if tool_list:
        lines.extend([f"Tools: {tool_list}"])
    return "\n".join(lines).rstrip()


def _render_single_email_analysis(messages: list[BaseMessage], start_idx: int) -> str | None:
    rspamd_payload = _last_tool_payload(messages[start_idx:], "rspamd_scan_email")
    header_payload = _last_tool_payload(messages[start_idx:], "email_header_auth_check")
    if not rspamd_payload or rspamd_payload.get("ok") is False:
        return None

    rspamd_data = rspamd_payload.get("data")
    if not isinstance(rspamd_data, dict):
        return None

    header_data = header_payload.get("data") if isinstance(header_payload, dict) else None
    categories = rspamd_data.get("categories") or []
    top_symbols = rspamd_data.get("symbols") or []
    symbol_names = []
    for item in top_symbols[:4]:
        if isinstance(item, dict) and item.get("name"):
            symbol_names.append(str(item["name"]))

    lines = [
        _section("Email Analysis"),
        _kv("Verdict", rspamd_data.get("risk_level", "unknown")),
        _kv("Action", rspamd_data.get("action", "unknown")),
        _kv(
            "Score",
            f"{rspamd_data.get('score', 'unknown')}"
            + (
                f" / {rspamd_data.get('required_score')}"
                if rspamd_data.get("required_score") is not None
                else ""
            ),
        ),
        _kv("Headers", header_data.get("risk_level", "n/a") if isinstance(header_data, dict) else "n/a"),
    ]
    if categories:
        lines.append(_kv("Categories", ", ".join(str(item) for item in categories[:5])))
    if symbol_names:
        lines.append(_kv("Signals", ", ".join(symbol_names)))
    summary = rspamd_data.get("summary")
    if isinstance(summary, str) and summary.strip():
        lines.extend(["", "Summary", _compact(summary, limit=220)])

    if isinstance(header_data, dict):
        findings = header_data.get("findings") or []
        finding_types = []
        for item in findings[:4]:
            if isinstance(item, dict) and item.get("type"):
                finding_types.append(str(item["type"]))
        if finding_types:
            lines.extend(["", "Header Findings", ", ".join(finding_types)])

    tool_list = summarize_invoked_tools(messages, start_idx)
    if tool_list:
        lines.extend(["", f"Tools: {tool_list}"])
    return "\n".join(lines)


def _render_monitor_status(messages: list[BaseMessage], start_idx: int) -> str | None:
    payload = _last_tool_payload(messages[start_idx:], "imap_monitor_status")
    if not payload or payload.get("ok") is False:
        return None
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    return "\n".join(
        [
            _section("Monitor Status"),
            f"Running: {data.get('running')}",
            f"Bound mailboxes: {data.get('bound_mailboxes')}",
            f"Enabled mailboxes: {data.get('enabled_mailboxes')}",
            f"Stored results: {data.get('stored_results')}",
        ]
    )


def _render_recent_results(messages: list[BaseMessage], start_idx: int) -> str | None:
    payload = _last_tool_payload(messages[start_idx:], "list_recent_email_results")
    if not payload or payload.get("ok") is False:
        return None
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    results = data.get("results")
    if not isinstance(results, list):
        return None
    lines = [
        _section("Stored Email Results"),
        f"Loaded: {len(results)} results",
        "",
    ]
    for idx, item in enumerate(results, 1):
        if not isinstance(item, dict):
            continue
        lines.extend(
            [
                f"{idx}. {item.get('subject') or '(no subject)'}",
                f"From: {item.get('from_address') or 'unknown'}"
                f"  ·  {_classify_email_type(str(item.get('subject') or ''), str(item.get('from_address') or ''))}",
                f"Verdict: {item.get('final_verdict') or 'unknown'}",
                f"Why: {_compact(str(item.get('summary') or 'no summary'), 180)}",
                "",
            ]
        )
    return "\n".join(lines).rstrip()


def _render_bound_mailboxes(messages: list[BaseMessage], start_idx: int) -> str | None:
    payload = _last_tool_payload(messages[start_idx:], "list_bound_imap_mailboxes")
    if not payload or payload.get("ok") is False:
        return None
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    mailboxes = data.get("mailboxes")
    if not isinstance(mailboxes, list):
        return None
    lines = [
        _section("Bound Mailboxes"),
        f"Count: {len(mailboxes)}",
        "",
    ]
    for idx, item in enumerate(mailboxes, 1):
        if not isinstance(item, dict):
            continue
        lines.extend(
            [
                f"{idx}. {item.get('email_address')}",
                f"Host: {item.get('imap_host')}:{item.get('imap_port')}",
                f"Folder: {item.get('folder')}",
                f"Enabled: {item.get('enabled')}",
                "",
            ]
        )
    return "\n".join(lines).rstrip()


def render_trace(messages: list[BaseMessage], start_idx: int) -> str:
    lines = ["Trace"]
    step = 1
    for message in messages[start_idx:]:
        if isinstance(message, HumanMessage):
            content = str(message.content)
            first_line = content.splitlines()[0].strip() if content else ""
            if first_line.startswith("Routing hints:"):
                lines.append(f"{step}. {first_line}")
                step += 1
            continue
        if isinstance(message, ToolMessage):
            payload = parse_tool_payload(message)
            if isinstance(payload, dict) and payload.get("ok") is False:
                reason = ((payload.get("error") or {}).get("message")) or "tool failed"
                lines.append(f"{step}. {message.name} -> failed: {reason}")
            elif isinstance(payload, dict):
                data = payload.get("data")
                detail = "completed"
                if message.name == "list_bound_imap_mailboxes" and isinstance(data, dict):
                    items = data.get("mailboxes") or []
                    detail = f"found {len(items)} mailbox bindings"
                elif message.name == "scan_recent_imap_emails" and isinstance(data, dict):
                    detail = f"scanned {data.get('scanned_count', 0)} emails"
                elif message.name == "rspamd_scan_email" and isinstance(data, dict):
                    detail = f"risk={data.get('risk_level')} score={data.get('score')}"
                elif message.name == "email_header_auth_check" and isinstance(data, dict):
                    detail = f"risk={data.get('risk_level')}"
                elif message.name == "imap_monitor_status" and isinstance(data, dict):
                    detail = f"running={data.get('running')} bound={data.get('bound_mailboxes')}"
                lines.append(f"{step}. {message.name} -> {detail}")
            else:
                lines.append(f"{step}. {message.name}")
            step += 1
            continue
        if isinstance(message, AIMessage):
            lines.append(f"{step}. model response ready")
            step += 1
    return "\n".join(lines)


def render_chat_response(messages: list[BaseMessage], start_idx: int) -> str:
    for renderer in (
        _render_recent_scan,
        _render_single_email_analysis,
        _render_monitor_status,
        _render_recent_results,
        _render_bound_mailboxes,
    ):
        rendered = renderer(messages, start_idx)
        if rendered:
            return rendered

    tool_list = summarize_invoked_tools(messages, start_idx)
    body = latest_ai_message(messages).strip()
    lines: list[str] = []
    if tool_list:
        lines.extend([_section("Response"), f"Tools: {tool_list}", ""])
    lines.append(body or "No response produced.")
    return "\n".join(lines)

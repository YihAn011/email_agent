from __future__ import annotations

import logging
import re
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


def _friendly_verdict(verdict: str | None) -> str:
    mapping = {
        "benign": "Looks safe",
        "suspicious": "Needs caution",
        "phishing_or_spoofing": "Likely phishing",
        "error": "Could not finish the check",
    }
    return mapping.get((verdict or "").strip().lower(), verdict or "Unknown")


def _friendly_risk(value: str | None) -> str:
    mapping = {
        "low": "low concern",
        "medium": "some concern",
        "high": "high concern",
        "unknown": "unknown",
        "n/a": "not checked",
        "none": "none",
    }
    return mapping.get((value or "").strip().lower(), value or "unknown")


def _friendly_email_type(subject: str, from_address: str) -> str:
    english = _classify_email_type(subject, from_address)
    mapping = {
        "School email": "School",
        "Billing email": "Billing / business",
        "Security / account alert": "Account security",
        "Promotional / advertising email": "Marketing / business",
        "Shopping / delivery email": "Shopping / delivery",
        "Work / recruiting email": "Recruiting / work",
        "Financial email": "Financial",
        "Work / collaboration email": "Work collaboration",
        "Travel email": "Travel",
        "Account notification": "Account notification",
        "General notification": "General notification",
    }
    return mapping.get(english, "General notification")


def _extract_prompt_header(messages: list[BaseMessage], start_idx: int, header: str) -> str:
    pattern = re.compile(rf"^{re.escape(header)}\s*:\s*(.+)$", flags=re.IGNORECASE | re.MULTILINE)
    for message in messages[start_idx:]:
        if not isinstance(message, HumanMessage):
            continue
        match = pattern.search(str(message.content))
        if match:
            return match.group(1).strip()
    return ""


def _email_name_from_prompt(messages: list[BaseMessage], start_idx: int) -> str:
    return _extract_prompt_header(messages, start_idx, "Subject") or "(no subject)"


def _email_from_prompt(messages: list[BaseMessage], start_idx: int) -> str:
    return _extract_prompt_header(messages, start_idx, "From") or "unknown sender"


def _required_decision_label(
    rspamd_data: dict[str, Any],
    header_data: dict[str, Any] | None = None,
    url_data: dict[str, Any] | None = None,
    urgency_data: dict[str, Any] | None = None,
    subject: str = "",
    from_address: str = "",
) -> str:
    categories = {str(item).lower() for item in (rspamd_data.get("categories") or [])}
    symbols = {
        str(item.get("name") or "").lower()
        for item in (rspamd_data.get("symbols") or [])
        if isinstance(item, dict)
    }
    risk = str(rspamd_data.get("risk_level") or "").lower()
    header_risk = str((header_data or {}).get("risk_level") or "").lower()
    action = str(rspamd_data.get("action") or "").lower()
    url_risk = str((url_data or {}).get("risk_level") or "").lower()
    url_suspicious = bool((url_data or {}).get("is_suspicious"))
    urgency_risk = str((urgency_data or {}).get("risk_contribution") or "").lower()
    urgent = bool((urgency_data or {}).get("is_urgent"))
    email_type = _classify_email_type(subject, from_address)
    sender_text = f"{subject} {from_address}".lower()
    branded_marketing = (
        email_type == "Promotional / advertising email"
        and any(token in sender_text for token in ("subway", "subs.subway.com", "news@subs.subway.com"))
    )
    header_format_noise = bool(
        symbols
        and symbols
        <= {
            "short_part_bad_headers",
            "missing_essential_headers",
            "hfilter_hostname_unknown",
            "missing_mid",
            "missing_to",
            "r_bad_cte_7bit",
        }
    )
    corroborating_checks_low = (
        url_risk in {"", "low", "unknown"}
        and not url_suspicious
        and urgency_risk in {"", "low", "unknown"}
        and not urgent
        and header_risk in {"", "low", "unknown", "n/a"}
    )

    if url_risk == "high" or (url_suspicious and urgency_risk in {"medium", "high"}):
        return "Phishing"
    if {"phishing", "spoofing", "suspicious_links"} & categories and url_risk in {"medium", "high"}:
        return "Phishing"
    if header_risk == "high" and url_suspicious:
        return "Phishing"

    if branded_marketing and corroborating_checks_low:
        return "Normal"
    if action == "reject" and header_format_noise and corroborating_checks_low:
        return "Normal"
    if "spam" in categories or any("bayes" in item for item in symbols) or action == "reject":
        return "Spam"
    if risk == "high" and (urgent or url_risk == "medium"):
        return "Spam"
    return "Normal"


def _header_format_noise(symbol_names: list[str]) -> bool:
    symbols = {item.lower() for item in symbol_names}
    return bool(
        symbols
        and symbols
        <= {
            "short_part_bad_headers",
            "missing_essential_headers",
            "hfilter_hostname_unknown",
            "missing_mid",
            "missing_to",
            "r_bad_cte_7bit",
        }
    )


def _parse_summary_flags(summary: str) -> dict[str, str]:
    parts = [part.strip() for part in (summary or "").split("|") if part.strip()]
    flags: dict[str, str] = {}
    for part in parts:
        if "=" in part:
            key, value = part.split("=", 1)
            flags[key.strip()] = value.strip()
    return flags


def _user_reason_lines(
    *,
    final_verdict: str | None,
    rspamd_risk: str | None,
    header_risk: str | None,
    summary: str,
) -> list[str]:
    flags = _parse_summary_flags(summary)
    reasons: list[str] = []

    if final_verdict == "benign":
        reasons.append("The system did not find strong signs of phishing or spam.")
    elif final_verdict == "suspicious":
        reasons.append("There were some warning signs, but not enough to call it phishing with high confidence.")
    elif final_verdict == "phishing_or_spoofing":
        reasons.append("Several signals point to impersonation or phishing behavior.")

    if rspamd_risk == "low":
        reasons.append("The content scanner saw only low-risk signals.")
    elif rspamd_risk == "medium":
        reasons.append("The content scanner found a few warning signs.")
    elif rspamd_risk == "high":
        reasons.append("The content scanner found strong warning signs.")

    if header_risk == "low":
        reasons.append("The sender and authentication details looked mostly normal.")
    elif header_risk == "medium":
        reasons.append("The sender or authentication details were a little unusual.")
    elif header_risk == "high":
        reasons.append("The sender or authentication details looked risky.")

    if "error_pattern_override" in flags:
        reasons.append(f"A remembered past mistake changed the final decision: {flags['error_pattern_override']}.")
    elif "error_pattern_hint" in flags:
        reasons.append("A remembered past mistake looked similar, so the system took an extra caution check.")

    return reasons[:4]


def _pattern_note(summary: str, memory_hint: str | None = None) -> str | None:
    flags = _parse_summary_flags(summary)
    if "error_pattern_override" in flags:
        return f"Used a remembered pattern to change the decision: {flags['error_pattern_override']}."
    if "error_pattern_hint" in flags:
        return "A remembered pattern looked similar, but it did not change the final decision."
    if "error_patterns_loaded" in flags:
        count = flags["error_patterns_loaded"]
        return f"Checked {count} remembered error patterns before deciding."
    if memory_hint:
        return memory_hint
    return None


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
    if any(token in text for token in ("sale", "offer", "deal", "save", "coupon", "newsletter", "weekly ad", "promotion", "promo", "discount", "%", "subway")):
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
            '  Check whether my recent emails contain phishing.',
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
                f"Decision: {_friendly_verdict(str(item.get('final_verdict') or 'unknown'))}",
                f"Scanner result: {_friendly_risk(str(item.get('rspamd_risk_level') or 'unknown'))}"
                + (
                    f" (score {item.get('rspamd_score')})"
                    if item.get("rspamd_score") is not None
                    else ""
                ),
                f"Sender check: {_friendly_risk(str(item.get('header_risk_level') or 'unknown'))}",
                "Why this decision:",
                *(
                    f"- {line}"
                    for line in _user_reason_lines(
                        final_verdict=str(item.get("final_verdict") or ""),
                        rspamd_risk=str(item.get("rspamd_risk_level") or ""),
                        header_risk=str(item.get("header_risk_level") or ""),
                        summary=str(item.get("summary") or ""),
                    )
                ),
                (
                    f"Pattern memory: {_pattern_note(str(item.get('summary') or ''), str(item.get('memory_hint') or ''))}"
                    if _pattern_note(str(item.get("summary") or ""), str(item.get("memory_hint") or ""))
                    else "Pattern memory: no similar past mistake was used."
                ),
                "",
            ]
        )
    return "\n".join(lines).rstrip()


def _render_single_email_analysis(messages: list[BaseMessage], start_idx: int) -> str | None:
    rspamd_payload = _last_tool_payload(messages[start_idx:], "rspamd_scan_email")
    header_payload = _last_tool_payload(messages[start_idx:], "email_header_auth_check")
    url_payload = _last_tool_payload(messages[start_idx:], "url_reputation_check")
    urgency_payload = _last_tool_payload(messages[start_idx:], "urgency_check")
    if not rspamd_payload or rspamd_payload.get("ok") is False:
        return None

    rspamd_data = rspamd_payload.get("data")
    if not isinstance(rspamd_data, dict):
        return None

    header_data = header_payload.get("data") if isinstance(header_payload, dict) else None
    url_data = url_payload.get("data") if isinstance(url_payload, dict) else None
    urgency_data = urgency_payload.get("data") if isinstance(urgency_payload, dict) else None
    categories = rspamd_data.get("categories") or []
    top_symbols = rspamd_data.get("symbols") or []
    symbol_names = []
    for item in top_symbols[:4]:
        if isinstance(item, dict) and item.get("name"):
            symbol_names.append(str(item["name"]))

    header_risk = header_data.get("risk_level", "n/a") if isinstance(header_data, dict) else "n/a"
    summary = str(rspamd_data.get("summary") or "")
    subject = _email_name_from_prompt(messages, start_idx)
    from_address = _email_from_prompt(messages, start_idx)
    decision = _required_decision_label(
        rspamd_data,
        header_data if isinstance(header_data, dict) else None,
        url_data if isinstance(url_data, dict) else None,
        urgency_data if isinstance(urgency_data, dict) else None,
        subject,
        from_address,
    )
    lines = [
        f"Email: {subject}",
        f"Type: {_friendly_email_type(subject, from_address)}",
        f"Verdict: {decision}",
        "Why this conclusion:",
        "- The message content and structure were rated "
        + f"{rspamd_data.get('risk_level', 'unknown')} risk "
        + f"(score {rspamd_data.get('score', 'unknown')}).",
    ]
    if isinstance(header_data, dict):
        lines.append(f"- The sender and authentication headers looked {header_risk} risk.")
    if isinstance(url_data, dict):
        lines.append(
            "- The links and URL patterns looked "
            + f"{url_data.get('risk_level', 'unknown')} risk "
            + f"(phishing score {url_data.get('phishing_score', 'unknown')})."
        )
    if isinstance(urgency_data, dict):
        lines.append(
            "- The wording was "
            + f"{urgency_data.get('urgency_label', 'unknown')} "
            + f"(pressure score {urgency_data.get('urgency_score', 'unknown')})."
        )
    if categories:
        lines.append(f"- The main warning categories were: {', '.join(str(item) for item in categories[:4])}.")
    if symbol_names:
        lines.append(f"- The strongest technical signals were: {', '.join(symbol_names[:4])}.")
    rspamd_score = float(rspamd_data.get("score") or 0.0)
    if decision == "Normal" and rspamd_score >= 6:
        if rspamd_score > 10:
            lines.append("- The scanner score was high, but the additional checks gave a clear benign explanation, so it was not called spam or phishing.")
        else:
            lines.append("- The elevated score looked more like bulk-mail noise because links, urgency, or sender checks did not support spam or phishing.")
    if decision == "Normal" and str(rspamd_data.get("action") or "").lower() == "reject" and _header_format_noise(symbol_names):
        lines.append("- The reject-style signal appeared to come from missing or malformed headers, so it was not used alone as a spam verdict.")

    note = _pattern_note(summary)
    if note:
        lines.append(f"- Past-analysis memory: {note}")
    tool_list = summarize_invoked_tools(messages, start_idx)
    if tool_list:
        lines.extend(["", f"Tools called: {tool_list}"])
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
                f"Decision: {_friendly_verdict(str(item.get('final_verdict') or 'unknown'))}",
                "Why this decision:",
                *(
                    f"- {line}"
                    for line in _user_reason_lines(
                        final_verdict=str(item.get("final_verdict") or ""),
                        rspamd_risk=str(item.get("rspamd_risk_level") or ""),
                        header_risk=str(item.get("header_risk_level") or ""),
                        summary=str(item.get("summary") or ""),
                    )
                ),
                (
                    f"Pattern memory: {_pattern_note(str(item.get('summary') or ''), str(item.get('memory_hint') or ''))}"
                    if _pattern_note(str(item.get("summary") or ""), str(item.get("memory_hint") or ""))
                    else "Pattern memory: no similar past mistake was used."
                ),
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

    body = latest_ai_message(messages).strip()
    lines: list[str] = []
    lines.append(body or "No response produced.")
    return "\n".join(lines)

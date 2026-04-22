from __future__ import annotations

import argparse
import logging
import os
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from skills.header_auth.schemas import EmailHeaderAuthCheckInput
from skills.header_auth.skill import EmailHeaderAuthCheckSkill
from skills.error_patterns.schemas import ErrorPatternMemoryCheckInput, ListErrorPatternsInput
from skills.error_patterns.skill import ErrorPatternMemoryCheckSkill, ListErrorPatternsSkill
from skills.imap_monitor.schemas import (
    BindImapMailboxInput,
    ListDecisionMemoryInput,
    ListRecentEmailResultsInput,
    PollMailboxInput,
    RecordEmailCorrectionInput,
    ScanRecentImapEmailsInput,
)
from skills.imap_monitor.skill import (
    BindImapMailboxSkill,
    ImapMonitorStatusSkill,
    ListDecisionMemorySkill,
    ListBoundImapMailboxesSkill,
    ListRecentEmailResultsSkill,
    PollImapMailboxesOnceSkill,
    RecordEmailCorrectionSkill,
    ScanRecentImapEmailsSkill,
    SetupImapMonitorSkill,
    StartImapMonitorSkill,
    StopImapMonitorSkill,
)
from skills.rspamd.schemas import RspamdScanEmailInput
from skills.rspamd.skill import RspamdScanEmailSkill
from skills.scam_indicators.schemas import ScamIndicatorCheckInput
from skills.scam_indicators.skill import ScamIndicatorCheckSkill
from skills.urgency.schemas import UrgencyCheckInput
from skills.urgency.skill import UrgencyCheckSkill
from skills.url_reputation.schemas import UrlReputationInput
from skills.url_reputation.skill import UrlReputationSkill


for logger_name in (
    "mcp",
    "mcp.server",
    "mcp.server.lowlevel",
    "mcp.server.fastmcp",
    "httpx",
    "httpcore",
):
    logging.getLogger(logger_name).setLevel(logging.WARNING)


DEFAULT_BASE_URL = os.getenv("RSPAMD_BASE_URL", "http://127.0.0.1:11333")


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _env_csv(name: str) -> list[str]:
    return [part.strip() for part in os.getenv(name, "").split(",") if part.strip()]


mcp = FastMCP(
    name="rspamd-email-skill",
    host=os.getenv("MCP_HOST", "127.0.0.1"),
    port=_env_int("MCP_PORT", 8000),
    sse_path=os.getenv("MCP_SSE_PATH", "/sse"),
    message_path=os.getenv("MCP_MESSAGE_PATH", "/messages/"),
    streamable_http_path=os.getenv("MCP_STREAMABLE_HTTP_PATH", "/mcp"),
    stateless_http=_env_bool("MCP_STATELESS_HTTP", False),
    instructions=(
        "Use rspamd_scan_email to scan RFC822 raw emails with rspamd, and "
        "email_header_auth_check to quickly triage header authentication signals. "
        "Use urgency_check to score the urgency/pressure level of an email using a trained classifier. "
        "Use url_reputation_check to score URL/content phishing risk using a trained GradientBoosting model. "
        "Use scam_indicator_check to detect obvious scam indicators like gift-card or crypto payment demands, "
        "extortion threats, lookalike domains, and suspicious reply-to addresses. "
        "Use error_pattern_memory_check to consult known dataset-derived misclassification patterns before finalizing a verdict, "
        "and list_error_patterns to inspect those stored patterns. "
        "Use list_bound_imap_mailboxes to discover already saved mailbox bindings before asking the user "
        "for credentials again. Use setup_imap_monitor or bind_imap_mailbox plus start_imap_monitor, poll_imap_mailboxes_once, "
        "imap_monitor_status, list_recent_email_results, record_email_correction, list_decision_memory, and scan_recent_imap_emails to manage "
        "continuous mailbox monitoring over IMAP and inspect recent emails on demand."
    ),
)


@mcp.tool(
    name="rspamd_scan_email",
    description=(
        "Scan an RFC822 raw email with rspamd /checkv2 and return normalized "
        "security signals. Pass the complete raw email as raw_email. "
        "email_text is accepted only as a compatibility alias."
    ),
)
def rspamd_scan_email(
    raw_email: str | None = None,
    email_text: str | None = None,
    mail_from: str | None = None,
    rcpt_to: list[str] | None = None,
    ip: str | None = None,
    helo: str | None = None,
    hostname: str | None = None,
    log_tag: str | None = None,
    timeout_seconds: float = 15.0,
    include_raw_result: bool = True,
    base_url: str | None = None,
) -> dict[str, Any]:
    """MCP tool wrapper around the existing RspamdScanEmailSkill."""
    resolved_raw_email = raw_email or email_text
    payload = RspamdScanEmailInput(
        raw_email=resolved_raw_email or "",
        mail_from=mail_from,
        rcpt_to=rcpt_to or [],
        ip=ip,
        helo=helo,
        hostname=hostname,
        log_tag=log_tag,
        timeout_seconds=timeout_seconds,
        include_raw_result=include_raw_result,
    )

    skill = RspamdScanEmailSkill(base_url=base_url or DEFAULT_BASE_URL)
    result = skill.run(payload)
    return result.model_dump()


@mcp.tool(
    name="email_header_auth_check",
    description=(
        "Parse email headers only (ignores body) and return lightweight authentication/"
        "routing signals based on common headers like Authentication-Results and DKIM-Signature."
    ),
)
def email_header_auth_check(
    raw_email: str | None = None,
    raw_headers: str | None = None,
    include_raw_headers: bool = False,
) -> dict[str, Any]:
    """MCP tool wrapper around the EmailHeaderAuthCheckSkill."""
    payload = EmailHeaderAuthCheckInput(
        raw_email=raw_email,
        raw_headers=raw_headers,
        include_raw_headers=include_raw_headers,
    )
    skill = EmailHeaderAuthCheckSkill()
    result = skill.run(payload)
    return result.model_dump()


@mcp.tool(
    name="error_pattern_memory_check",
    description=(
        "Check known dataset-derived misclassification patterns before finalizing an email verdict. "
        "Useful when the current signals are ambiguous and you want to reduce repeated false positives or false negatives."
    ),
)
def error_pattern_memory_check(
    subject: str = "",
    from_address: str = "",
    current_verdict: str = "benign",
    rspamd_risk_level: str | None = None,
    header_risk_level: str | None = None,
    urgency_label: str | None = None,
    url_risk_level: str | None = None,
) -> dict[str, Any]:
    payload = ErrorPatternMemoryCheckInput(
        subject=subject,
        from_address=from_address,
        current_verdict=current_verdict,
        rspamd_risk_level=rspamd_risk_level,
        header_risk_level=header_risk_level,
        urgency_label=urgency_label,
        url_risk_level=url_risk_level,
    )
    skill = ErrorPatternMemoryCheckSkill()
    return skill.run(payload).model_dump()


@mcp.tool(
    name="list_error_patterns",
    description="List stored dataset-derived error patterns that the memory layer can use before final email decisions.",
)
def list_error_patterns(limit: int = 20, pattern_type: str | None = None) -> dict[str, Any]:
    payload = ListErrorPatternsInput(limit=limit, pattern_type=pattern_type)
    skill = ListErrorPatternsSkill()
    return skill.run(payload).model_dump()


@mcp.tool(
    name="bind_imap_mailbox",
    description=(
        "Bind an IMAP mailbox for continuous monitoring. For Gmail, pass the Gmail "
        "address and a Gmail app password."
    ),
)
def bind_imap_mailbox(
    email_address: str,
    app_password: str,
    username: str | None = None,
    imap_host: str = "imap.gmail.com",
    imap_port: int = 993,
    folder: str = "INBOX",
    poll_interval_seconds: int = 30,
    use_ssl: bool = True,
    enabled: bool = True,
) -> dict[str, Any]:
    payload = BindImapMailboxInput(
        email_address=email_address,
        app_password=app_password,
        username=username,
        imap_host=imap_host,
        imap_port=imap_port,
        folder=folder,
        poll_interval_seconds=poll_interval_seconds,
        use_ssl=use_ssl,
        enabled=enabled,
    )
    skill = BindImapMailboxSkill()
    return skill.run(payload).model_dump()


@mcp.tool(
    name="setup_imap_monitor",
    description=(
        "One-step IMAP monitor setup: bind the mailbox, poll once immediately, "
        "and start the background monitor daemon."
    ),
)
def setup_imap_monitor(
    email_address: str,
    app_password: str,
    username: str | None = None,
    imap_host: str = "imap.gmail.com",
    imap_port: int = 993,
    folder: str = "INBOX",
    poll_interval_seconds: int = 30,
    use_ssl: bool = True,
    enabled: bool = True,
) -> dict[str, Any]:
    payload = BindImapMailboxInput(
        email_address=email_address,
        app_password=app_password,
        username=username,
        imap_host=imap_host,
        imap_port=imap_port,
        folder=folder,
        poll_interval_seconds=poll_interval_seconds,
        use_ssl=use_ssl,
        enabled=enabled,
    )
    skill = SetupImapMonitorSkill()
    return skill.run(payload).model_dump()


@mcp.tool(
    name="start_imap_monitor",
    description="Start the background IMAP mailbox monitor daemon.",
)
def start_imap_monitor() -> dict[str, Any]:
    skill = StartImapMonitorSkill()
    return skill.run(PollMailboxInput()).model_dump()


@mcp.tool(
    name="stop_imap_monitor",
    description="Stop the background IMAP mailbox monitor daemon.",
)
def stop_imap_monitor() -> dict[str, Any]:
    skill = StopImapMonitorSkill()
    return skill.run(PollMailboxInput()).model_dump()


@mcp.tool(
    name="imap_monitor_status",
    description="Get background IMAP monitor status, bound mailbox count, and recent errors.",
)
def imap_monitor_status() -> dict[str, Any]:
    skill = ImapMonitorStatusSkill()
    return skill.run(PollMailboxInput()).model_dump()


@mcp.tool(
    name="list_bound_imap_mailboxes",
    description=(
        "List IMAP mailboxes that are already stored locally. Use this before asking "
        "the user for credentials again. If exactly one mailbox is bound and the user "
        "asks about recent emails, prefer using it directly."
    ),
)
def list_bound_imap_mailboxes() -> dict[str, Any]:
    skill = ListBoundImapMailboxesSkill()
    return skill.run(PollMailboxInput()).model_dump()


@mcp.tool(
    name="poll_imap_mailboxes_once",
    description=(
        "Poll bound IMAP mailboxes once immediately. Useful for testing Gmail "
        "credentials and fetching new emails without waiting for the daemon."
    ),
)
def poll_imap_mailboxes_once(email_address: str | None = None) -> dict[str, Any]:
    skill = PollImapMailboxesOnceSkill()
    return skill.run(PollMailboxInput(email_address=email_address)).model_dump()


@mcp.tool(
    name="list_recent_email_results",
    description="List recent analyzed email results from the IMAP monitor database.",
)
def list_recent_email_results(
    email_address: str | None = None,
    limit: int = 10,
) -> dict[str, Any]:
    skill = ListRecentEmailResultsSkill()
    payload = ListRecentEmailResultsInput(email_address=email_address, limit=limit)
    return skill.run(payload).model_dump()


@mcp.tool(
    name="record_email_correction",
    description=(
        "Store a correction pattern for a previously analyzed email. Use this when the user says the earlier verdict was wrong "
        "and wants future similar emails handled better."
    ),
)
def record_email_correction(
    email_address: str,
    uid: int,
    corrected_verdict: str,
    notes: str = "",
) -> dict[str, Any]:
    skill = RecordEmailCorrectionSkill()
    payload = RecordEmailCorrectionInput(
        email_address=email_address,
        uid=uid,
        corrected_verdict=corrected_verdict,
        notes=notes,
    )
    return skill.run(payload).model_dump()


@mcp.tool(
    name="list_decision_memory",
    description="List stored correction-memory patterns that can influence future final verdicts.",
)
def list_decision_memory(limit: int = 20) -> dict[str, Any]:
    skill = ListDecisionMemorySkill()
    payload = ListDecisionMemoryInput(limit=limit)
    return skill.run(payload).model_dump()


@mcp.tool(
    name="scan_recent_imap_emails",
    description=(
        "Fetch and analyze the latest N emails from a bound IMAP mailbox on demand. "
        "Useful when the user asks about the newest emails without enabling historical backfill."
    ),
)
def scan_recent_imap_emails(
    email_address: str,
    limit: int = 10,
) -> dict[str, Any]:
    skill = ScanRecentImapEmailsSkill()
    payload = ScanRecentImapEmailsInput(email_address=email_address, limit=limit)
    return skill.run(payload).model_dump()


@mcp.tool(
    name="urgency_check",
    description=(
        "Score the urgency/pressure level of an email using a logistic regression trained on 355k emails. "
        "Returns urgency_label (not urgent / somewhat urgent / very urgent), urgency_score (0-1), "
        "and risk_contribution. Call this when rspamd score is ambiguous or when social engineering "
        "pressure is suspected."
    ),
)
def urgency_check(
    email_text: str,
    subject: str = "",
) -> dict[str, Any]:
    payload = UrgencyCheckInput(email_text=email_text, subject=subject)
    skill = UrgencyCheckSkill()
    return skill.run(payload).model_dump()


@mcp.tool(
    name="scam_indicator_check",
    description=(
        "Detect obvious human-readable scam indicators in an email, including gift-card or crypto payment demands, "
        "extortion threats, lookalike brand domains, suspicious payment/recovery links, and free-mail reply addresses "
        "for messages claiming to be from official organizations."
    ),
)
def scam_indicator_check(
    raw_email: str = "",
    subject: str = "",
    from_address: str = "",
) -> dict[str, Any]:
    payload = ScamIndicatorCheckInput(
        raw_email=raw_email,
        subject=subject,
        from_address=from_address,
    )
    skill = ScamIndicatorCheckSkill()
    return skill.run(payload).model_dump()


@mcp.tool(
    name="url_reputation_check",
    description=(
        "Score URL/content phishing risk using a GradientBoosting classifier trained on 355k emails. "
        "Extracts URL features (count, length, subdomain depth, IP URLs) from email_text automatically. "
        "Returns phishing_score (0-1), is_suspicious flag, and risk_level. "
        "Optimised for recall — low threshold means fewer missed phishing emails."
    ),
)
def url_reputation_check(
    email_text: str,
    subject: str = "",
) -> dict[str, Any]:
    payload = UrlReputationInput(email_text=email_text, subject=subject)
    skill = UrlReputationSkill()
    return skill.run(payload).model_dump()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Email Guardian MCP server.")
    parser.add_argument(
        "--transport",
        choices=("stdio", "sse", "streamable-http"),
        default=os.getenv("MCP_TRANSPORT", "stdio"),
        help=(
            "MCP transport to serve. Use stdio for local agent adapters, "
            "or streamable-http/sse for MCP clients that connect by URL."
        ),
    )
    parser.add_argument(
        "--host",
        default=os.getenv("MCP_HOST", "127.0.0.1"),
        help="HTTP host for sse/streamable-http transports.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=_env_int("MCP_PORT", 8000),
        help="HTTP port for sse/streamable-http transports.",
    )
    parser.add_argument(
        "--path",
        default=os.getenv("MCP_STREAMABLE_HTTP_PATH", "/mcp"),
        help="Streamable HTTP endpoint path.",
    )
    parser.add_argument(
        "--sse-path",
        default=os.getenv("MCP_SSE_PATH", "/sse"),
        help="SSE endpoint path.",
    )
    parser.add_argument(
        "--message-path",
        default=os.getenv("MCP_MESSAGE_PATH", "/messages/"),
        help="SSE message endpoint path.",
    )
    parser.add_argument(
        "--stateless-http",
        action="store_true",
        default=_env_bool("MCP_STATELESS_HTTP", False),
        help="Run streamable HTTP without server-side session state.",
    )
    parser.add_argument(
        "--allowed-host",
        action="append",
        default=_env_csv("MCP_ALLOWED_HOSTS"),
        help=(
            "Allowed HTTP Host value for DNS rebinding protection. Repeat for "
            "multiple public tunnel hostnames."
        ),
    )
    parser.add_argument(
        "--allowed-origin",
        action="append",
        default=_env_csv("MCP_ALLOWED_ORIGINS"),
        help="Allowed Origin value for DNS rebinding protection. Repeat for multiple origins.",
    )
    parser.add_argument(
        "--disable-dns-rebinding-protection",
        action="store_true",
        default=_env_bool("MCP_DISABLE_DNS_REBINDING_PROTECTION", False),
        help="Disable FastMCP HTTP DNS rebinding checks. Only use on trusted networks.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    mcp.settings.host = args.host
    mcp.settings.port = args.port
    mcp.settings.streamable_http_path = args.path
    mcp.settings.sse_path = args.sse_path
    mcp.settings.message_path = args.message_path
    mcp.settings.stateless_http = args.stateless_http
    if args.disable_dns_rebinding_protection:
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=False,
        )
    elif args.allowed_host or args.allowed_origin:
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=args.allowed_host,
            allowed_origins=args.allowed_origin,
        )
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()

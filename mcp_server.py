from __future__ import annotations

import os
from typing import Any

from mcp.server.fastmcp import FastMCP

from skills.header_auth.schemas import EmailHeaderAuthCheckInput
from skills.header_auth.skill import EmailHeaderAuthCheckSkill
from skills.imap_monitor.schemas import (
    BindImapMailboxInput,
    ListRecentEmailResultsInput,
    PollMailboxInput,
    ScanRecentImapEmailsInput,
)
from skills.imap_monitor.skill import (
    BindImapMailboxSkill,
    ImapMonitorStatusSkill,
    ListRecentEmailResultsSkill,
    PollImapMailboxesOnceSkill,
    ScanRecentImapEmailsSkill,
    SetupImapMonitorSkill,
    StartImapMonitorSkill,
    StopImapMonitorSkill,
)
from skills.rspamd.schemas import RspamdScanEmailInput
from skills.rspamd.skill import RspamdScanEmailSkill
from skills.urgency.schemas import UrgencyCheckInput
from skills.urgency.skill import UrgencyCheckSkill
from skills.url_reputation.schemas import UrlReputationInput
from skills.url_reputation.skill import UrlReputationSkill


DEFAULT_BASE_URL = os.getenv("RSPAMD_BASE_URL", "http://127.0.0.1:11333")

mcp = FastMCP(
    name="rspamd-email-skill",
    instructions=(
        "Use rspamd_scan_email to scan RFC822 raw emails with rspamd, and "
        "email_header_auth_check to quickly triage header authentication signals. "
        "Use urgency_check to score the urgency/pressure level of an email using a trained classifier. "
        "Use url_reputation_check to score URL/content phishing risk using a trained GradientBoosting model. "
        "Use setup_imap_monitor or bind_imap_mailbox plus start_imap_monitor, poll_imap_mailboxes_once, "
        "imap_monitor_status, list_recent_email_results, and scan_recent_imap_emails to manage "
        "continuous mailbox monitoring over IMAP and inspect recent emails on demand."
    ),
)


@mcp.tool(
    name="rspamd_scan_email",
    description=(
        "Scan an RFC822 raw email with rspamd /checkv2 and return normalized "
        "security signals."
    ),
)
def rspamd_scan_email(
    raw_email: str,
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
    payload = RspamdScanEmailInput(
        raw_email=raw_email,
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


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

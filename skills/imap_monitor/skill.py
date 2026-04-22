from __future__ import annotations

import imaplib
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
from time import perf_counter
from typing import Any

from skills.base_skill import BaseSkill, SkillError, SkillMeta, SkillResult
from skills.error_patterns.schemas import ErrorPatternMemoryCheckInput, ListErrorPatternsInput
from skills.error_patterns.skill import ErrorPatternMemoryCheckSkill, ListErrorPatternsSkill
from skills.header_auth.schemas import EmailHeaderAuthCheckInput
from skills.header_auth.skill import EmailHeaderAuthCheckSkill
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

from .schemas import (
    BindImapMailboxInput,
    BindImapMailboxResult,
    BoundMailbox,
    DecisionMemoryEntry,
    ListRecentEmailResultsInput,
    ListRecentEmailResultsResult,
    ListBoundImapMailboxesResult,
    ListDecisionMemoryInput,
    ListDecisionMemoryResult,
    MonitorActionResult,
    MonitorStatusResult,
    PollMailboxInput,
    PollMailboxResult,
    PollMailboxSummary,
    RecentEmailResult,
    RecordEmailCorrectionInput,
    RecordEmailCorrectionResult,
    ScanRecentImapEmailsInput,
    ScanRecentImapEmailsResult,
    SetupImapMonitorResult,
)
from .memory import extract_domain, extract_keywords, find_memory_match, normalize_subject
from .storage import (
    DB_PATH,
    LOG_PATH,
    PROJECT_ROOT,
    clear_pid,
    count_results,
    get_email_result,
    get_mailbox,
    insert_decision_memory,
    is_pid_running,
    list_decision_memory,
    list_mailboxes,
    list_recent_results,
    recent_errors,
    read_pid,
    upsert_mailbox,
    update_mailbox_state,
    utc_now_iso,
    write_pid,
    write_raw_email,
    insert_email_result,
)

DEFAULT_RSPAMD_BASE_URL = os.getenv("RSPAMD_BASE_URL", "http://127.0.0.1:11333")
DAEMON_PATH = PROJECT_ROOT / "imap_monitor_daemon.py"


def _masked_mailbox(record: dict[str, Any]) -> BoundMailbox:
    return BoundMailbox(
        email_address=str(record["email_address"]),
        username=str(record["username"]),
        imap_host=str(record["imap_host"]),
        imap_port=int(record["imap_port"]),
        folder=str(record["folder"]),
        poll_interval_seconds=int(record["poll_interval_seconds"]),
        use_ssl=bool(record["use_ssl"]),
        enabled=bool(record["enabled"]),
        has_app_password=bool(record.get("app_password")),
        created_at=str(record["created_at"]),
        updated_at=str(record["updated_at"]),
        last_uid=int(record["last_uid"]) if record.get("last_uid") is not None else None,
        last_poll_utc=str(record["last_poll_utc"]) if record.get("last_poll_utc") else None,
        last_error=str(record["last_error"]) if record.get("last_error") else None,
    )


def _connect_imap(mailbox: dict[str, Any]) -> imaplib.IMAP4:
    host = str(mailbox["imap_host"])
    port = int(mailbox["imap_port"])
    if bool(mailbox["use_ssl"]):
        client: imaplib.IMAP4 = imaplib.IMAP4_SSL(host=host, port=port)
    else:
        client = imaplib.IMAP4(host=host, port=port)
    client.login(str(mailbox["username"]), str(mailbox["app_password"]))
    status, _ = client.select(str(mailbox["folder"]), readonly=True)
    if status != "OK":
        raise RuntimeError(f"Failed to select mailbox folder {mailbox['folder']}")
    return client


def _parse_uids(search_data: list[bytes]) -> list[int]:
    if not search_data:
        return []
    raw = search_data[0].decode("utf-8", errors="ignore").strip()
    if not raw:
        return []
    return [int(item) for item in raw.split() if item.isdigit()]


def _fetch_message_bytes(client: imaplib.IMAP4, uid: int) -> bytes:
    status, msg_data = client.uid("fetch", str(uid), "(RFC822)")
    if status != "OK":
        raise RuntimeError(f"Failed to fetch message UID {uid}")
    for item in msg_data:
        if isinstance(item, tuple) and isinstance(item[1], (bytes, bytearray)):
            return bytes(item[1])
    raise RuntimeError(f"IMAP fetch for UID {uid} returned no message body")


def _get_highest_uid(client: imaplib.IMAP4) -> int | None:
    status, search_data = client.uid("search", None, "ALL")
    if status != "OK":
        raise RuntimeError("Failed to enumerate mailbox UIDs")
    uids = _parse_uids(search_data)
    return max(uids) if uids else None


def _get_all_uids(client: imaplib.IMAP4) -> list[int]:
    status, search_data = client.uid("search", None, "ALL")
    if status != "OK":
        raise RuntimeError("Failed to enumerate mailbox UIDs")
    return _parse_uids(search_data)


def _compose_final_verdict(
    rspamd_result: SkillResult[Any],
    header_result: SkillResult[Any],
    urgency_result: SkillResult[Any] | None = None,
    url_result: SkillResult[Any] | None = None,
    scam_result: SkillResult[Any] | None = None,
    spam_result: SkillResult[Any] | None = None,
    *,
    subject: str = "",
    from_address: str = "",
) -> tuple[str, str]:
    if not rspamd_result.ok and not header_result.ok:
        return "error", "Both rspamd_scan_email and email_header_auth_check failed."

    verdict = "benign"
    reasons: list[str] = []

    rspamd_data = rspamd_result.data
    header_data = header_result.data
    urgency_data = urgency_result.data if urgency_result and urgency_result.ok else None
    url_data = url_result.data if url_result and url_result.ok else None
    scam_data = scam_result.data if scam_result and scam_result.ok else None
    spam_data = spam_result.data if spam_result and spam_result.ok else None

    categories: set[str] = set()
    symbol_names: set[str] = set()
    rspamd_action = ""
    rspamd_score = 0.0
    header_findings: set[str] = set()
    explicit_auth_failure = False
    has_high_header_finding = False
    has_medium_header_finding = False

    sender_text = f"{subject} {from_address}".lower()
    branded_marketing = any(
        token in sender_text
        for token in (
            "subway",
            "subs.subway.com",
            "news@subs.subway.com",
        )
    )

    if rspamd_result.ok and rspamd_data is not None:
        categories = {item.lower() for item in rspamd_data.categories}
        symbol_names = {symbol.name.upper() for symbol in rspamd_data.symbols}
        rspamd_action = str(rspamd_data.action or "").lower()
        rspamd_score = float(rspamd_data.score or 0.0)
        header_noise_only = bool(
            symbol_names
            and symbol_names
            <= {
                "SHORT_PART_BAD_HEADERS",
                "MISSING_ESSENTIAL_HEADERS",
                "HFILTER_HOSTNAME_UNKNOWN",
                "MISSING_MID",
                "MISSING_TO",
                "R_BAD_CTE_7BIT",
            }
        )
        security_categories = {"spam", "phishing", "spoofing", "suspicious_links", "reputation_issue", "attachment_risk"}
        if "phishing" in categories or "BLACKLIST_DMARC" in symbol_names or "PHISHING" in symbol_names:
            verdict = "phishing_or_spoofing"
        elif "spam" in categories or any("BAYES" in name for name in symbol_names):
            verdict = "suspicious"
        elif (
            rspamd_data.risk_level in {"medium", "high"}
            and categories & security_categories
        ) or rspamd_action in {"soft reject", "reject"}:
            verdict = "suspicious"
        elif rspamd_action == "reject" and not header_noise_only:
            verdict = "suspicious"
        reasons.append(
            f"rspamd={rspamd_data.risk_level} score={rspamd_data.score:.2f} categories={','.join(sorted(categories)) or 'none'}"
        )

    if header_result.ok and header_data is not None:
        header_findings = {finding.type for finding in header_data.findings}
        has_high_header_finding = any(finding.severity == "high" for finding in header_data.findings)
        has_medium_header_finding = any(finding.severity == "medium" for finding in header_data.findings)
        explicit_auth_failure = bool({"dmarc_fail", "spf_not_pass", "dkim_not_pass"} & header_findings)

        # Treat header analysis as corroborating evidence rather than a primary detector.
        if has_high_header_finding and explicit_auth_failure:
            if verdict == "suspicious":
                verdict = "phishing_or_spoofing"
            elif verdict == "benign":
                verdict = "suspicious"
        elif has_medium_header_finding and explicit_auth_failure and verdict != "benign":
            verdict = _max_verdict(verdict, "suspicious")
        reasons.append(
            "header_auth="
            f"{header_data.risk_level} findings={len(header_data.findings)} "
            f"received={header_data.received_count} dkim={header_data.dkim_signature_count}"
        )

    if urgency_data is not None:
        reasons.append(
            f"urgency={urgency_data.risk_contribution} score={urgency_data.urgency_score:.2f} label={urgency_data.urgency_label}"
        )

    if url_data is not None:
        reasons.append(
            f"url={url_data.risk_level} score={url_data.phishing_score:.2f} urls={len(url_data.extracted_urls)}"
        )

    if scam_data is not None:
        reasons.append(
            f"scam_indicators={scam_data.risk_level} matched={str(bool(scam_data.matched)).lower()} indicators={','.join(scam_data.indicators[:4]) or 'none'}"
        )

    if spam_data is not None:
        reasons.append(
            f"spam_campaign={spam_data.risk_level} matched={str(bool(spam_data.matched)).lower()} indicators={','.join(spam_data.indicators[:4]) or 'none'}"
        )

    corroborating_checks_low = (
        (url_data is None or (url_data.risk_level in {"low", "unknown"} and not url_data.is_suspicious))
        and (urgency_data is None or urgency_data.risk_contribution in {"low", "unknown"})
        and (header_data is None or header_data.risk_level in {"low", "unknown"})
    )

    if verdict != "phishing_or_spoofing":
        if scam_data is not None and scam_data.matched:
            if explicit_auth_failure or (url_data is not None and url_data.risk_level in {"medium", "high"}):
                verdict = "phishing_or_spoofing"
            else:
                verdict = _max_verdict(verdict, "suspicious")

        if (
            url_data is not None
            and url_data.risk_level == "high"
            and (
                explicit_auth_failure
                or (scam_data is not None and scam_data.matched)
                or "suspicious_links" in categories
            )
        ):
            verdict = "phishing_or_spoofing"

        if (
            url_data is not None
            and url_data.is_suspicious
            and urgency_data is not None
            and urgency_data.risk_contribution in {"medium", "high"}
        ):
            verdict = _max_verdict(verdict, "suspicious")

        if (
            spam_data is not None
            and spam_data.matched
            and not explicit_auth_failure
            and not (scam_data is not None and scam_data.matched)
            and (
                spam_data.risk_level == "high"
                or (url_data is not None and url_data.risk_level in {"medium", "high"})
                or bool(categories & {"spam", "reputation_issue"})
                or rspamd_action in {"soft reject", "reject"}
            )
        ):
            verdict = _max_verdict(verdict, "suspicious")

        if (
            verdict == "benign"
            and explicit_auth_failure
            and (
                (url_data is not None and url_data.risk_level in {"medium", "high"})
                or (urgency_data is not None and urgency_data.risk_contribution in {"medium", "high"})
                or (scam_data is not None and scam_data.matched)
            )
        ):
            verdict = "suspicious"

    if branded_marketing and corroborating_checks_low:
        verdict = "benign"

    summary = " | ".join(reasons) if reasons else "No analysis details available."
    return verdict, summary


def _severity_rank(value: str) -> int:
    return {
        "error": 4,
        "phishing_or_spoofing": 3,
        "suspicious": 2,
        "benign": 1,
    }.get(value, 0)


def _max_verdict(current: str, candidate: str) -> str:
    return candidate if _severity_rank(candidate) > _severity_rank(current) else current


def _apply_memory_guidance(
    *,
    subject: str,
    from_address: str,
    current_verdict: str,
    summary: str,
) -> tuple[str, str | None, bool, str]:
    match = find_memory_match(
        subject=subject,
        from_address=from_address,
        current_verdict=current_verdict,
    )
    if match is None:
        return current_verdict, None, False, summary

    memory_hint = (
        f"Matched a stored correction pattern ({match.reason}). "
        f"A similar email was previously corrected from `{match.prior_verdict}` "
        f"to `{match.corrected_verdict}`."
    )
    if match.notes:
        memory_hint += f" Note: {match.notes}"

    should_apply = current_verdict in {"benign", "suspicious"} and match.score >= 6
    if should_apply and match.corrected_verdict != current_verdict:
        return (
            match.corrected_verdict,
            memory_hint,
            True,
            f"{summary} | memory_override={current_verdict}->{match.corrected_verdict}",
        )
    return current_verdict, memory_hint, False, f"{summary} | memory_hint=matched"


def _apply_error_pattern_guidance(
    *,
    subject: str,
    from_address: str,
    current_verdict: str,
    rspamd_risk_level: str | None,
    header_risk_level: str | None,
    urgency_label: str | None,
    url_risk_level: str | None,
    summary: str,
) -> tuple[str, str | None, bool, str]:
    skill = ErrorPatternMemoryCheckSkill()
    result = skill.run(
        ErrorPatternMemoryCheckInput(
            subject=subject,
            from_address=from_address,
            current_verdict=current_verdict,
            rspamd_risk_level=rspamd_risk_level,
            header_risk_level=header_risk_level,
            urgency_label=urgency_label,
            url_risk_level=url_risk_level,
        )
    )
    if not result.ok or result.data is None or not result.data.matched:
        return current_verdict, None, False, summary

    suggested = result.data.suggested_verdict or current_verdict
    hint = result.data.summary
    top_match = result.data.matches[0] if result.data.matches else None
    corroborating_signal = any(
        value in {"medium", "high", "somewhat urgent", "very urgent"}
        for value in (
            rspamd_risk_level,
            header_risk_level,
            urgency_label,
            url_risk_level,
        )
        if value
    )
    exact_pattern = bool(
        top_match
        and (
            top_match.pattern.sender_domain
            or top_match.pattern.subject_normalized
            or top_match.pattern.required_keywords
        )
    )

    should_apply = False
    if current_verdict == "suspicious" and suggested == "benign":
        should_apply = True
    elif current_verdict == "benign" and suggested in {"suspicious", "phishing_or_spoofing"}:
        should_apply = exact_pattern and corroborating_signal

    if should_apply and suggested != current_verdict:
        return suggested, hint, True, f"{summary} | error_pattern_override={current_verdict}->{suggested}"
    return current_verdict, hint, False, f"{summary} | error_pattern_hint=matched"


def _load_error_pattern_context(summary: str) -> tuple[str | None, str]:
    skill = ListErrorPatternsSkill()
    result = skill.run(ListErrorPatternsInput(limit=20))
    if not result.ok or result.data is None:
        return None, summary

    count = len(result.data.entries)
    hint = f"Loaded {count} stored error patterns before finalizing the verdict."
    return hint, f"{summary} | error_patterns_loaded={count}"


def _build_memory_entry(record: dict[str, Any]) -> DecisionMemoryEntry:
    return DecisionMemoryEntry(
        id=int(record["id"]),
        source_email_address=str(record["source_email_address"]),
        source_uid=int(record["source_uid"]),
        sender_domain=str(record["sender_domain"]),
        subject_normalized=str(record["subject_normalized"]),
        subject_keywords=[token for token in str(record["subject_keywords"]).split("|") if token],
        prior_verdict=str(record["prior_verdict"]),
        corrected_verdict=str(record["corrected_verdict"]),
        notes=str(record.get("notes") or ""),
        times_referenced=int(record.get("times_referenced") or 0),
        last_referenced_utc=str(record["last_referenced_utc"]) if record.get("last_referenced_utc") else None,
        created_at=str(record["created_at"]),
        updated_at=str(record["updated_at"]),
    )


def _build_recent_result(record: dict[str, Any]) -> RecentEmailResult:
    return RecentEmailResult(
        email_address=str(record["email_address"]),
        uid=int(record["uid"]),
        message_id=str(record["message_id"]) if record.get("message_id") else None,
        subject=str(record.get("subject") or ""),
        from_address=str(record.get("from_address") or ""),
        analyzed_at_utc=str(record["analyzed_at_utc"]),
        rspamd_risk_level=str(record["rspamd_risk_level"]) if record.get("rspamd_risk_level") else None,
        rspamd_score=float(record["rspamd_score"]) if record.get("rspamd_score") is not None else None,
        header_risk_level=str(record["header_risk_level"]) if record.get("header_risk_level") else None,
        final_verdict=str(record["final_verdict"]),
        summary=str(record["summary"]),
        raw_email_path=str(record["raw_email_path"]) if record.get("raw_email_path") else None,
        memory_hint=str(record["memory_hint"]) if record.get("memory_hint") else None,
        memory_applied=bool(record.get("memory_applied", False)),
    )


def _analyze_email_message(
    *,
    email_address: str,
    uid: int,
    raw_bytes: bytes,
    rspamd_base_url: str | None = None,
) -> RecentEmailResult:
    parsed = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    raw_email = raw_bytes.decode("utf-8", errors="replace")
    raw_email_path = write_raw_email(email_address, uid, raw_email)

    rspamd_skill = RspamdScanEmailSkill(base_url=rspamd_base_url or DEFAULT_RSPAMD_BASE_URL)
    header_skill = EmailHeaderAuthCheckSkill()
    urgency_skill = UrgencyCheckSkill()
    url_reputation_skill = UrlReputationSkill()
    scam_indicator_skill = ScamIndicatorCheckSkill()
    spam_campaign_skill = SpamCampaignCheckSkill()

    rspamd_result = rspamd_skill.run(
        RspamdScanEmailInput(
            raw_email=raw_email,
            include_raw_result=False,
        )
    )
    header_result = header_skill.run(
        EmailHeaderAuthCheckInput(
            raw_email=raw_email,
            include_raw_headers=False,
        )
    )
    urgency_result = urgency_skill.run(
        UrgencyCheckInput(
            subject=str(parsed.get("Subject") or ""),
            email_text=raw_email,
        )
    )
    url_reputation_result = url_reputation_skill.run(
        UrlReputationInput(
            email_text=raw_email,
        )
    )
    scam_indicator_result = scam_indicator_skill.run(
        ScamIndicatorCheckInput(
            raw_email=raw_email,
            subject=str(parsed.get("Subject") or ""),
            from_address=str(parsed.get("From") or ""),
        )
    )
    spam_campaign_result = spam_campaign_skill.run(
        SpamCampaignCheckInput(
            raw_email=raw_email,
            email_text=raw_email,
            subject=str(parsed.get("Subject") or ""),
            from_address=str(parsed.get("From") or ""),
        )
    )
    final_verdict, summary = _compose_final_verdict(
        rspamd_result,
        header_result,
        urgency_result,
        url_reputation_result,
        scam_indicator_result,
        spam_campaign_result,
        subject=str(parsed.get("Subject") or ""),
        from_address=str(parsed.get("From") or ""),
    )
    error_pattern_context_hint, summary = _load_error_pattern_context(summary)
    final_verdict, error_pattern_hint, error_pattern_applied, summary = _apply_error_pattern_guidance(
        subject=str(parsed.get("Subject") or ""),
        from_address=str(parsed.get("From") or ""),
        current_verdict=final_verdict,
        rspamd_risk_level=rspamd_result.data.risk_level if rspamd_result.ok and rspamd_result.data else None,
        header_risk_level=header_result.data.risk_level if header_result.ok and header_result.data else None,
        urgency_label=urgency_result.data.urgency_label if urgency_result.ok and urgency_result.data else None,
        url_risk_level=url_reputation_result.data.risk_level if url_reputation_result.ok and url_reputation_result.data else None,
        summary=summary,
    )
    final_verdict, memory_hint, memory_applied, summary = _apply_memory_guidance(
        subject=str(parsed.get("Subject") or ""),
        from_address=str(parsed.get("From") or ""),
        current_verdict=final_verdict,
        summary=summary,
    )
    analyzed_at_utc = utc_now_iso()

    record = {
        "email_address": email_address,
        "uid": uid,
        "message_id": parsed.get("Message-ID"),
        "subject": str(parsed.get("Subject") or ""),
        "from_address": str(parsed.get("From") or ""),
        "analyzed_at_utc": analyzed_at_utc,
        "rspamd_risk_level": rspamd_result.data.risk_level if rspamd_result.ok and rspamd_result.data else None,
        "rspamd_score": rspamd_result.data.score if rspamd_result.ok and rspamd_result.data else None,
        "header_risk_level": header_result.data.risk_level if header_result.ok and header_result.data else None,
        "final_verdict": final_verdict,
        "summary": summary,
        "raw_email_path": raw_email_path,
        "memory_hint": " | ".join(
            hint for hint in (error_pattern_context_hint, error_pattern_hint, memory_hint) if hint
        ) or None,
        "memory_applied": error_pattern_applied or memory_applied,
    }
    insert_email_result(record)
    return _build_recent_result(record)


def poll_mailbox_once(mailbox: dict[str, Any], rspamd_base_url: str | None = None) -> PollMailboxSummary:
    email_address = str(mailbox["email_address"])
    processed_uids: list[int] = []
    last_uid = int(mailbox["last_uid"]) if mailbox.get("last_uid") is not None else None
    now = utc_now_iso()

    try:
        client = _connect_imap(mailbox)
        try:
            if last_uid is None:
                status, search_data = client.uid("search", None, "ALL")
            else:
                status, search_data = client.uid("search", None, f"UID {last_uid + 1}:*")
            if status != "OK":
                raise RuntimeError("Failed to search mailbox for new emails")
            uids = _parse_uids(search_data)

            for uid in uids:
                raw_bytes = _fetch_message_bytes(client, uid)
                _analyze_email_message(
                    email_address=email_address,
                    uid=uid,
                    raw_bytes=raw_bytes,
                    rspamd_base_url=rspamd_base_url,
                )
                processed_uids.append(uid)

            if uids:
                last_uid = max(uids)
            update_mailbox_state(
                email_address,
                last_uid=last_uid,
                last_poll_utc=now,
                last_error=None,
            )
        finally:
            try:
                client.logout()
            except Exception:
                pass
        return PollMailboxSummary(
            email_address=email_address,
            processed_uids=processed_uids,
            new_results=len(processed_uids),
            last_uid=last_uid,
            last_error=None,
        )
    except Exception as exc:
        update_mailbox_state(email_address, last_uid=last_uid, last_poll_utc=now, last_error=str(exc))
        return PollMailboxSummary(
            email_address=email_address,
            processed_uids=processed_uids,
            new_results=0,
            last_uid=last_uid,
            last_error=str(exc),
        )


def poll_bound_mailboxes_once(email_address: str | None = None) -> PollMailboxResult:
    mailboxes = [get_mailbox(email_address)] if email_address else list_mailboxes(enabled_only=True)
    mailbox_records = [record for record in mailboxes if record]
    summaries = [poll_mailbox_once(mailbox) for mailbox in mailbox_records]
    return PollMailboxResult(
        polled_mailboxes=len(mailbox_records),
        total_new_results=sum(item.new_results for item in summaries),
        summaries=summaries,
    )


def scan_recent_imap_emails(email_address: str, limit: int) -> ScanRecentImapEmailsResult:
    mailbox = get_mailbox(email_address)
    if mailbox is None:
        raise RuntimeError(f"Mailbox {email_address} is not bound")

    client = _connect_imap(mailbox)
    try:
        all_uids = _get_all_uids(client)
        recent_uids = sorted(all_uids[-limit:], reverse=True)
        emails: list[RecentEmailResult] = []
        for uid in recent_uids:
            raw_bytes = _fetch_message_bytes(client, uid)
            emails.append(
                _analyze_email_message(
                    email_address=email_address,
                    uid=uid,
                    raw_bytes=raw_bytes,
                )
            )
        return ScanRecentImapEmailsResult(
            email_address=email_address,
            scanned_count=len(emails),
            emails=emails,
        )
    finally:
        try:
            client.logout()
        except Exception:
            pass


def start_monitor_process() -> MonitorActionResult:
    pid = read_pid()
    if is_pid_running(pid):
        return MonitorActionResult(
            running=True,
            pid=pid,
            message="IMAP monitor is already running.",
            log_path=str(LOG_PATH),
            db_path=str(DB_PATH),
        )

    if pid is not None:
        clear_pid()

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    log_handle = open(LOG_PATH, "a", encoding="utf-8")
    env = dict(os.environ)
    process = subprocess.Popen(
        [sys.executable, str(DAEMON_PATH)],
        cwd=str(PROJECT_ROOT),
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    write_pid(process.pid)
    return MonitorActionResult(
        running=True,
        pid=process.pid,
        message="IMAP monitor started.",
        log_path=str(LOG_PATH),
        db_path=str(DB_PATH),
    )


def stop_monitor_process() -> MonitorActionResult:
    pid = read_pid()
    if not is_pid_running(pid):
        clear_pid()
        return MonitorActionResult(
            running=False,
            pid=None,
            message="IMAP monitor is not running.",
            log_path=str(LOG_PATH),
            db_path=str(DB_PATH),
        )

    assert pid is not None
    os.kill(pid, signal.SIGTERM)
    deadline = time.time() + 5
    while time.time() < deadline:
        if not is_pid_running(pid):
            break
        time.sleep(0.1)
    if is_pid_running(pid):
        os.kill(pid, signal.SIGKILL)
    clear_pid()
    return MonitorActionResult(
        running=False,
        pid=None,
        message="IMAP monitor stopped.",
        log_path=str(LOG_PATH),
        db_path=str(DB_PATH),
    )


def get_monitor_status() -> MonitorStatusResult:
    pid = read_pid()
    running = is_pid_running(pid)
    if not running and pid is not None:
        clear_pid()
        pid = None

    mailboxes = list_mailboxes(enabled_only=False)
    enabled_mailboxes = sum(1 for item in mailboxes if bool(item["enabled"]))
    return MonitorStatusResult(
        running=running,
        pid=pid,
        bound_mailboxes=len(mailboxes),
        enabled_mailboxes=enabled_mailboxes,
        stored_results=count_results(),
        log_path=str(LOG_PATH),
        db_path=str(DB_PATH),
        recent_errors=recent_errors(),
    )


def daemon_loop() -> None:
    signal.signal(signal.SIGTERM, lambda *_args: sys.exit(0))
    write_pid(os.getpid())
    try:
        while True:
            status = get_monitor_status()
            mailboxes = list_mailboxes(enabled_only=True)
            now = datetime.now(timezone.utc)
            for mailbox in mailboxes:
                last_poll_text = mailbox.get("last_poll_utc")
                if last_poll_text:
                    last_poll = datetime.fromisoformat(str(last_poll_text))
                    elapsed = (now - last_poll).total_seconds()
                    if elapsed < int(mailbox["poll_interval_seconds"]):
                        continue
                poll_mailbox_once(mailbox)

            sleep_for = 5
            if status.enabled_mailboxes:
                sleep_for = min(
                    max(int(item["poll_interval_seconds"]) for item in mailboxes),
                    30,
                )
                sleep_for = max(5, min(sleep_for, 30))
            time.sleep(sleep_for)
    finally:
        clear_pid()


class BindImapMailboxSkill(BaseSkill[BindImapMailboxInput, BindImapMailboxResult]):
    name = "bind_imap_mailbox"
    description = "Bind an IMAP mailbox for continuous monitoring."
    version = "0.1.0"

    def run(self, payload: BindImapMailboxInput) -> SkillResult[BindImapMailboxResult]:
        start = perf_counter()
        timestamp_utc = utc_now_iso()
        try:
            record = upsert_mailbox(
                {
                    "email_address": payload.email_address,
                    "username": payload.username or payload.email_address,
                    "app_password": payload.app_password,
                    "imap_host": payload.imap_host,
                    "imap_port": payload.imap_port,
                    "folder": payload.folder,
                    "poll_interval_seconds": payload.poll_interval_seconds,
                    "use_ssl": payload.use_ssl,
                    "enabled": payload.enabled,
                }
            )
            client = _connect_imap(record)
            try:
                highest_uid = _get_highest_uid(client)
            finally:
                try:
                    client.logout()
                except Exception:
                    pass

            update_mailbox_state(
                payload.email_address,
                last_uid=highest_uid,
                last_poll_utc=timestamp_utc,
                last_error=None,
            )
            refreshed = get_mailbox(payload.email_address)
            if refreshed is None:
                raise RuntimeError("Mailbox was bound but could not be reloaded from storage")
            result = BindImapMailboxResult(
                mailbox=_masked_mailbox(refreshed),
                monitor_hint=(
                    "Mailbox bound. Monitoring cursor was initialized to the current newest "
                    "email, so only future emails will be analyzed. Call start_imap_monitor "
                    "to begin background polling or poll_imap_mailboxes_once to test for mail "
                    "that arrives after this binding step."
                ),
            )
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=True,
                data=result,
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )
        except Exception as exc:
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=False,
                error=SkillError(type="bind_error", message=str(exc), retryable=False),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )


class StartImapMonitorSkill(BaseSkill[PollMailboxInput, MonitorActionResult]):
    name = "start_imap_monitor"
    description = "Start the background IMAP monitor daemon."
    version = "0.1.0"

    def run(self, payload: PollMailboxInput) -> SkillResult[MonitorActionResult]:
        del payload
        start = perf_counter()
        timestamp_utc = utc_now_iso()
        try:
            result = start_monitor_process()
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=True,
                data=result,
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )
        except Exception as exc:
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=False,
                error=SkillError(type="start_error", message=str(exc), retryable=False),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )


class SetupImapMonitorSkill(BaseSkill[BindImapMailboxInput, SetupImapMonitorResult]):
    name = "setup_imap_monitor"
    description = "Bind an IMAP mailbox, poll it once immediately, and start the monitor daemon."
    version = "0.1.0"

    def run(self, payload: BindImapMailboxInput) -> SkillResult[SetupImapMonitorResult]:
        start = perf_counter()
        timestamp_utc = utc_now_iso()
        try:
            bind_result = BindImapMailboxSkill().run(payload)
            if not bind_result.ok or bind_result.data is None:
                raise RuntimeError(bind_result.error.message if bind_result.error else "Mailbox bind failed")

            poll_result = poll_bound_mailboxes_once(payload.email_address)
            daemon_result = start_monitor_process()
            result = SetupImapMonitorResult(
                mailbox=bind_result.data.mailbox,
                initial_poll=poll_result,
                daemon=daemon_result,
            )
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=True,
                data=result,
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )
        except Exception as exc:
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=False,
                error=SkillError(type="setup_error", message=str(exc), retryable=False),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )


class StopImapMonitorSkill(BaseSkill[PollMailboxInput, MonitorActionResult]):
    name = "stop_imap_monitor"
    description = "Stop the background IMAP monitor daemon."
    version = "0.1.0"

    def run(self, payload: PollMailboxInput) -> SkillResult[MonitorActionResult]:
        del payload
        start = perf_counter()
        timestamp_utc = utc_now_iso()
        try:
            result = stop_monitor_process()
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=True,
                data=result,
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )
        except Exception as exc:
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=False,
                error=SkillError(type="stop_error", message=str(exc), retryable=False),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )


class ImapMonitorStatusSkill(BaseSkill[PollMailboxInput, MonitorStatusResult]):
    name = "imap_monitor_status"
    description = "Return IMAP monitor daemon status and recent errors."
    version = "0.1.0"

    def run(self, payload: PollMailboxInput) -> SkillResult[MonitorStatusResult]:
        del payload
        start = perf_counter()
        timestamp_utc = utc_now_iso()
        result = get_monitor_status()
        latency_ms = int((perf_counter() - start) * 1000)
        return SkillResult(
            ok=True,
            data=result,
            meta=SkillMeta(
                skill_name=self.name,
                skill_version=self.version,
                latency_ms=latency_ms,
                timestamp_utc=timestamp_utc,
            ),
        )


class ListBoundImapMailboxesSkill(
    BaseSkill[PollMailboxInput, ListBoundImapMailboxesResult]
):
    name = "list_bound_imap_mailboxes"
    description = "List locally stored IMAP mailbox bindings."
    version = "0.1.0"

    def run(self, payload: PollMailboxInput) -> SkillResult[ListBoundImapMailboxesResult]:
        del payload
        start = perf_counter()
        timestamp_utc = utc_now_iso()
        records = list_mailboxes(enabled_only=False)
        result = ListBoundImapMailboxesResult(
            mailboxes=[_masked_mailbox(record) for record in records]
        )
        latency_ms = int((perf_counter() - start) * 1000)
        return SkillResult(
            ok=True,
            data=result,
            meta=SkillMeta(
                skill_name=self.name,
                skill_version=self.version,
                latency_ms=latency_ms,
                timestamp_utc=timestamp_utc,
            ),
        )


class PollImapMailboxesOnceSkill(BaseSkill[PollMailboxInput, PollMailboxResult]):
    name = "poll_imap_mailboxes_once"
    description = "Poll bound IMAP mailboxes once for immediate testing."
    version = "0.1.0"

    def run(self, payload: PollMailboxInput) -> SkillResult[PollMailboxResult]:
        start = perf_counter()
        timestamp_utc = utc_now_iso()
        try:
            result = poll_bound_mailboxes_once(payload.email_address)
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=True,
                data=result,
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )
        except Exception as exc:
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=False,
                error=SkillError(type="poll_error", message=str(exc), retryable=False),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )


class ScanRecentImapEmailsSkill(
    BaseSkill[ScanRecentImapEmailsInput, ScanRecentImapEmailsResult]
):
    name = "scan_recent_imap_emails"
    description = "Fetch and analyze the latest N emails from a bound IMAP mailbox on demand."
    version = "0.1.0"

    def run(
        self, payload: ScanRecentImapEmailsInput
    ) -> SkillResult[ScanRecentImapEmailsResult]:
        start = perf_counter()
        timestamp_utc = utc_now_iso()
        try:
            result = scan_recent_imap_emails(payload.email_address, payload.limit)
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=True,
                data=result,
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )
        except Exception as exc:
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=False,
                error=SkillError(type="scan_recent_error", message=str(exc), retryable=False),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )


class ListRecentEmailResultsSkill(
    BaseSkill[ListRecentEmailResultsInput, ListRecentEmailResultsResult]
):
    name = "list_recent_email_results"
    description = "List recent IMAP monitor analysis results."
    version = "0.1.0"

    def run(
        self, payload: ListRecentEmailResultsInput
    ) -> SkillResult[ListRecentEmailResultsResult]:
        start = perf_counter()
        timestamp_utc = utc_now_iso()
        try:
            rows = list_recent_results(payload.limit, payload.email_address)
            results = ListRecentEmailResultsResult(
                results=[_build_recent_result(row) for row in rows]
            )
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=True,
                data=results,
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )
        except Exception as exc:
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=False,
                error=SkillError(type="list_results_error", message=str(exc), retryable=False),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )


class RecordEmailCorrectionSkill(
    BaseSkill[RecordEmailCorrectionInput, RecordEmailCorrectionResult]
):
    name = "record_email_correction"
    description = "Store a correction pattern for a previously analyzed email."
    version = "0.1.0"

    def run(
        self, payload: RecordEmailCorrectionInput
    ) -> SkillResult[RecordEmailCorrectionResult]:
        start = perf_counter()
        timestamp_utc = utc_now_iso()
        try:
            row = get_email_result(payload.email_address, payload.uid)
            if row is None:
                raise RuntimeError(
                    f"No analyzed email result found for {payload.email_address} uid={payload.uid}"
                )

            memory_row = insert_decision_memory(
                {
                    "source_email_address": payload.email_address,
                    "source_uid": payload.uid,
                    "sender_domain": extract_domain(str(row.get("from_address") or "")),
                    "subject_normalized": normalize_subject(str(row.get("subject") or "")),
                    "subject_keywords": "|".join(extract_keywords(str(row.get("subject") or ""))),
                    "prior_verdict": str(row.get("final_verdict") or ""),
                    "corrected_verdict": payload.corrected_verdict,
                    "notes": payload.notes,
                }
            )
            result = RecordEmailCorrectionResult(
                memory_entry=_build_memory_entry(memory_row),
                message=(
                    "Stored a correction memory. Future similar emails can consult this "
                    "pattern during the final decision step."
                ),
            )
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=True,
                data=result,
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )
        except Exception as exc:
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=False,
                error=SkillError(type="record_correction_error", message=str(exc), retryable=False),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )


class ListDecisionMemorySkill(BaseSkill[ListDecisionMemoryInput, ListDecisionMemoryResult]):
    name = "list_decision_memory"
    description = "List stored correction-memory patterns."
    version = "0.1.0"

    def run(self, payload: ListDecisionMemoryInput) -> SkillResult[ListDecisionMemoryResult]:
        start = perf_counter()
        timestamp_utc = utc_now_iso()
        try:
            rows = list_decision_memory(payload.limit)
            result = ListDecisionMemoryResult(entries=[_build_memory_entry(row) for row in rows])
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=True,
                data=result,
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )
        except Exception as exc:
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=False,
                error=SkillError(type="list_memory_error", message=str(exc), retryable=False),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )

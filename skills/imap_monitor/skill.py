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
from skills.header_auth.schemas import EmailHeaderAuthCheckInput
from skills.header_auth.skill import EmailHeaderAuthCheckSkill
from skills.rspamd.schemas import RspamdScanEmailInput
from skills.rspamd.skill import RspamdScanEmailSkill

from .schemas import (
    BindImapMailboxInput,
    BindImapMailboxResult,
    BoundMailbox,
    ListRecentEmailResultsInput,
    ListRecentEmailResultsResult,
    ListBoundImapMailboxesResult,
    MonitorActionResult,
    MonitorStatusResult,
    PollMailboxInput,
    PollMailboxResult,
    PollMailboxSummary,
    RecentEmailResult,
    ScanRecentImapEmailsInput,
    ScanRecentImapEmailsResult,
    SetupImapMonitorResult,
)
from .storage import (
    DB_PATH,
    LOG_PATH,
    PROJECT_ROOT,
    clear_pid,
    count_results,
    get_mailbox,
    is_pid_running,
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
) -> tuple[str, str]:
    if not rspamd_result.ok and not header_result.ok:
        return "error", "Both rspamd_scan_email and email_header_auth_check failed."

    verdict = "benign"
    reasons: list[str] = []

    rspamd_data = rspamd_result.data
    header_data = header_result.data

    if rspamd_result.ok and rspamd_data is not None:
        categories = set(rspamd_data.categories)
        symbol_names = {symbol.name for symbol in rspamd_data.symbols}
        if "phishing" in categories or "BLACKLIST_DMARC" in symbol_names or "PHISHING" in symbol_names:
            verdict = "phishing_or_spoofing"
        elif rspamd_data.risk_level in {"medium", "high"}:
            verdict = "suspicious"
        reasons.append(
            f"rspamd={rspamd_data.risk_level} score={rspamd_data.score:.2f} categories={','.join(sorted(categories)) or 'none'}"
        )

    if header_result.ok and header_data is not None:
        finding_types = {finding.type for finding in header_data.findings}
        has_high_header_finding = any(finding.severity == "high" for finding in header_data.findings)
        has_medium_header_finding = any(finding.severity == "medium" for finding in header_data.findings)
        explicit_auth_failure = bool(
            {"dmarc_fail", "spf_not_pass", "dkim_not_pass"} & finding_types
        )

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

    if verdict == "benign":
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
    final_verdict, summary = _compose_final_verdict(rspamd_result, header_result)
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

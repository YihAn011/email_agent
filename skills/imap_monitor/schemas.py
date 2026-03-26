from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field, field_validator


class BindImapMailboxInput(BaseModel):
    email_address: str = Field(..., description="Mailbox email address.")
    app_password: str = Field(
        ...,
        description="IMAP password or Gmail app password. This is stored locally for the monitor daemon.",
    )
    username: Optional[str] = Field(default=None, description="IMAP username. Defaults to email_address.")
    imap_host: str = Field(default="imap.gmail.com", description="IMAP server hostname.")
    imap_port: int = Field(default=993, ge=1, le=65535, description="IMAP server port.")
    folder: str = Field(default="INBOX", description="Mailbox folder to monitor.")
    poll_interval_seconds: int = Field(
        default=30,
        ge=10,
        le=3600,
        description="Polling interval for this mailbox.",
    )
    use_ssl: bool = Field(default=True, description="Use IMAP over SSL.")
    enabled: bool = Field(default=True, description="Whether the mailbox should be monitored.")

    @field_validator("email_address", "app_password", "imap_host", "folder")
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("Field must not be empty")
        return value.strip()

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None


class BoundMailbox(BaseModel):
    email_address: str
    username: str
    imap_host: str
    imap_port: int
    folder: str
    poll_interval_seconds: int
    use_ssl: bool
    enabled: bool
    has_app_password: bool = True
    created_at: str
    updated_at: str
    last_uid: Optional[int] = None
    last_poll_utc: Optional[str] = None
    last_error: Optional[str] = None


class BindImapMailboxResult(BaseModel):
    mailbox: BoundMailbox
    monitor_hint: str


class SetupImapMonitorResult(BaseModel):
    mailbox: BoundMailbox
    initial_poll: "PollMailboxResult"
    daemon: "MonitorActionResult"


class MonitorActionResult(BaseModel):
    running: bool
    pid: Optional[int] = None
    message: str
    log_path: str
    db_path: str


class MonitorStatusResult(BaseModel):
    running: bool
    pid: Optional[int] = None
    bound_mailboxes: int = 0
    enabled_mailboxes: int = 0
    stored_results: int = 0
    log_path: str
    db_path: str
    recent_errors: list[str] = Field(default_factory=list)


class PollMailboxInput(BaseModel):
    email_address: Optional[str] = Field(
        default=None,
        description="Optional single mailbox to poll. If omitted, poll all enabled mailboxes.",
    )


class PollMailboxSummary(BaseModel):
    email_address: str
    processed_uids: list[int] = Field(default_factory=list)
    new_results: int = 0
    last_uid: Optional[int] = None
    last_error: Optional[str] = None


class PollMailboxResult(BaseModel):
    polled_mailboxes: int
    total_new_results: int
    summaries: list[PollMailboxSummary] = Field(default_factory=list)


class ScanRecentImapEmailsInput(BaseModel):
    email_address: str = Field(..., description="Bound mailbox email address to inspect.")
    limit: int = Field(
        default=10,
        ge=1,
        le=200,
        description="How many of the latest emails to fetch and analyze on demand.",
    )


class RecentEmailResult(BaseModel):
    email_address: str
    uid: int
    message_id: Optional[str] = None
    subject: str = ""
    from_address: str = ""
    analyzed_at_utc: str
    rspamd_risk_level: Optional[str] = None
    rspamd_score: Optional[float] = None
    header_risk_level: Optional[str] = None
    final_verdict: str
    summary: str
    raw_email_path: Optional[str] = None


class ListRecentEmailResultsInput(BaseModel):
    email_address: Optional[str] = Field(default=None, description="Optional mailbox filter.")
    limit: int = Field(default=10, ge=1, le=100, description="Maximum number of results to return.")


class ScanRecentImapEmailsResult(BaseModel):
    email_address: str
    scanned_count: int
    emails: list[RecentEmailResult] = Field(default_factory=list)


SetupImapMonitorResult.model_rebuild()


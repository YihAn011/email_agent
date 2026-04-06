from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_DIR = PROJECT_ROOT / "runtime" / "imap_monitor"
MESSAGES_DIR = RUNTIME_DIR / "messages"
DB_PATH = RUNTIME_DIR / "monitor.db"
LOG_PATH = RUNTIME_DIR / "monitor.log"
PID_PATH = RUNTIME_DIR / "monitor.pid"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_storage() -> None:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    MESSAGES_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(RUNTIME_DIR, 0o700)
    os.chmod(MESSAGES_DIR, 0o700)


def get_connection() -> sqlite3.Connection:
    ensure_storage()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    _init_db(conn)
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass
    return conn


def _init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS mailboxes (
            email_address TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            app_password TEXT NOT NULL,
            imap_host TEXT NOT NULL,
            imap_port INTEGER NOT NULL,
            folder TEXT NOT NULL,
            poll_interval_seconds INTEGER NOT NULL,
            use_ssl INTEGER NOT NULL,
            enabled INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_uid INTEGER,
            last_poll_utc TEXT,
            last_error TEXT
        );

        CREATE TABLE IF NOT EXISTS email_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_address TEXT NOT NULL,
            uid INTEGER NOT NULL,
            message_id TEXT,
            subject TEXT NOT NULL,
            from_address TEXT NOT NULL,
            analyzed_at_utc TEXT NOT NULL,
            rspamd_risk_level TEXT,
            rspamd_score REAL,
            header_risk_level TEXT,
            final_verdict TEXT NOT NULL,
            summary TEXT NOT NULL,
            memory_hint TEXT,
            memory_applied INTEGER NOT NULL DEFAULT 0,
            raw_email_path TEXT,
            UNIQUE(email_address, uid)
        );

        CREATE TABLE IF NOT EXISTS decision_memory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_email_address TEXT NOT NULL,
            source_uid INTEGER NOT NULL,
            sender_domain TEXT NOT NULL,
            subject_normalized TEXT NOT NULL,
            subject_keywords TEXT NOT NULL,
            prior_verdict TEXT NOT NULL,
            corrected_verdict TEXT NOT NULL,
            notes TEXT NOT NULL,
            times_referenced INTEGER NOT NULL DEFAULT 0,
            last_referenced_utc TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    existing_email_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(email_results)").fetchall()
    }
    if "memory_hint" not in existing_email_columns:
        conn.execute("ALTER TABLE email_results ADD COLUMN memory_hint TEXT")
    if "memory_applied" not in existing_email_columns:
        conn.execute("ALTER TABLE email_results ADD COLUMN memory_applied INTEGER NOT NULL DEFAULT 0")
    conn.commit()


def upsert_mailbox(mailbox: dict[str, Any]) -> dict[str, Any]:
    now = utc_now_iso()
    with get_connection() as conn:
        existing = conn.execute(
            "SELECT created_at, last_uid, last_poll_utc, last_error FROM mailboxes WHERE email_address = ?",
            (mailbox["email_address"],),
        ).fetchone()
        created_at = existing["created_at"] if existing else now
        last_uid = existing["last_uid"] if existing else None
        last_poll_utc = existing["last_poll_utc"] if existing else None
        last_error = existing["last_error"] if existing else None
        conn.execute(
            """
            INSERT INTO mailboxes (
                email_address, username, app_password, imap_host, imap_port, folder,
                poll_interval_seconds, use_ssl, enabled, created_at, updated_at,
                last_uid, last_poll_utc, last_error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(email_address) DO UPDATE SET
                username=excluded.username,
                app_password=excluded.app_password,
                imap_host=excluded.imap_host,
                imap_port=excluded.imap_port,
                folder=excluded.folder,
                poll_interval_seconds=excluded.poll_interval_seconds,
                use_ssl=excluded.use_ssl,
                enabled=excluded.enabled,
                updated_at=excluded.updated_at
            """,
            (
                mailbox["email_address"],
                mailbox["username"],
                mailbox["app_password"],
                mailbox["imap_host"],
                mailbox["imap_port"],
                mailbox["folder"],
                mailbox["poll_interval_seconds"],
                int(mailbox["use_ssl"]),
                int(mailbox["enabled"]),
                created_at,
                now,
                last_uid,
                last_poll_utc,
                last_error,
            ),
        )
        conn.commit()
    return get_mailbox(mailbox["email_address"]) or {}


def get_mailbox(email_address: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM mailboxes WHERE email_address = ?",
            (email_address,),
        ).fetchone()
    return dict(row) if row else None


def list_mailboxes(enabled_only: bool = False) -> list[dict[str, Any]]:
    query = "SELECT * FROM mailboxes"
    params: tuple[Any, ...] = ()
    if enabled_only:
        query += " WHERE enabled = 1"
    query += " ORDER BY email_address"
    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def update_mailbox_state(
    email_address: str,
    *,
    last_uid: int | None = None,
    last_poll_utc: str | None = None,
    last_error: str | None = None,
) -> None:
    assignments: list[str] = ["updated_at = ?"]
    params: list[Any] = [utc_now_iso()]
    if last_uid is not None:
        assignments.append("last_uid = ?")
        params.append(last_uid)
    if last_poll_utc is not None:
        assignments.append("last_poll_utc = ?")
        params.append(last_poll_utc)
    assignments.append("last_error = ?")
    params.append(last_error)
    params.append(email_address)

    with get_connection() as conn:
        conn.execute(
            f"UPDATE mailboxes SET {', '.join(assignments)} WHERE email_address = ?",
            tuple(params),
        )
        conn.commit()


def insert_email_result(record: dict[str, Any]) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO email_results (
                email_address, uid, message_id, subject, from_address,
                analyzed_at_utc, rspamd_risk_level, rspamd_score, header_risk_level,
                final_verdict, summary, memory_hint, memory_applied, raw_email_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["email_address"],
                record["uid"],
                record.get("message_id"),
                record.get("subject", ""),
                record.get("from_address", ""),
                record["analyzed_at_utc"],
                record.get("rspamd_risk_level"),
                record.get("rspamd_score"),
                record.get("header_risk_level"),
                record["final_verdict"],
                record["summary"],
                record.get("memory_hint"),
                int(bool(record.get("memory_applied", False))),
                record.get("raw_email_path"),
            ),
        )
        conn.commit()


def list_recent_results(limit: int, email_address: str | None = None) -> list[dict[str, Any]]:
    query = "SELECT * FROM email_results"
    params: list[Any] = []
    if email_address:
        query += " WHERE email_address = ?"
        params.append(email_address)
    query += " ORDER BY analyzed_at_utc DESC, id DESC LIMIT ?"
    params.append(limit)
    with get_connection() as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
    return [dict(row) for row in rows]


def get_email_result(email_address: str, uid: int) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT * FROM email_results
            WHERE email_address = ? AND uid = ?
            """,
            (email_address, uid),
        ).fetchone()
    return dict(row) if row else None


def insert_decision_memory(entry: dict[str, Any]) -> dict[str, Any]:
    now = utc_now_iso()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO decision_memory (
                source_email_address, source_uid, sender_domain, subject_normalized,
                subject_keywords, prior_verdict, corrected_verdict, notes,
                times_referenced, last_referenced_utc, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry["source_email_address"],
                entry["source_uid"],
                entry["sender_domain"],
                entry["subject_normalized"],
                entry["subject_keywords"],
                entry["prior_verdict"],
                entry["corrected_verdict"],
                entry.get("notes", ""),
                int(entry.get("times_referenced", 0)),
                entry.get("last_referenced_utc"),
                now,
                now,
            ),
        )
        conn.commit()
        row_id = conn.execute("SELECT last_insert_rowid() AS row_id").fetchone()["row_id"]
        row = conn.execute("SELECT * FROM decision_memory WHERE id = ?", (row_id,)).fetchone()
    return dict(row) if row else {}


def list_decision_memory(limit: int = 20) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT * FROM decision_memory
            ORDER BY updated_at DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def mark_memory_referenced(memory_id: int) -> None:
    now = utc_now_iso()
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE decision_memory
            SET times_referenced = times_referenced + 1,
                last_referenced_utc = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (now, now, memory_id),
        )
        conn.commit()


def count_results() -> int:
    with get_connection() as conn:
        row = conn.execute("SELECT COUNT(*) AS count FROM email_results").fetchone()
    return int(row["count"]) if row else 0


def recent_errors(limit: int = 5) -> list[str]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT last_error FROM mailboxes
            WHERE last_error IS NOT NULL AND last_error != ''
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [str(row["last_error"]) for row in rows]


def sanitize_mailbox_dir(email_address: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in email_address.lower())


def write_raw_email(email_address: str, uid: int, raw_email: str) -> str:
    mailbox_dir = MESSAGES_DIR / sanitize_mailbox_dir(email_address)
    mailbox_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(mailbox_dir, 0o700)
    except OSError:
        pass
    path = mailbox_dir / f"{uid}.eml"
    path.write_text(raw_email, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return str(path)


def read_pid() -> int | None:
    try:
        return int(PID_PATH.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def write_pid(pid: int) -> None:
    ensure_storage()
    PID_PATH.write_text(str(pid), encoding="utf-8")
    try:
        os.chmod(PID_PATH, 0o600)
    except OSError:
        pass


def clear_pid() -> None:
    try:
        PID_PATH.unlink()
    except OSError:
        pass


def is_pid_running(pid: int | None) -> bool:
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

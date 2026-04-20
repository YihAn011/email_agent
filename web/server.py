from __future__ import annotations

import email as stdlib_email
import json
import os
import sys
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = Path(__file__).resolve().parent / "static"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from skills.imap_monitor.storage import (
    MESSAGES_DIR,
    count_results,
    get_email_result,
    is_pid_running,
    list_mailboxes,
    list_recent_results,
    read_pid,
    sanitize_mailbox_dir,
)

app = FastAPI(title="Intelligent Mail")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/api/status")
def api_status() -> dict:
    pid = read_pid()
    mailboxes = list_mailboxes()
    return {
        "monitor_running": is_pid_running(pid),
        "bound_mailboxes": len(mailboxes),
        "mailbox_addresses": [str(m["email_address"]) for m in mailboxes],
        "result_count": count_results(),
    }


def _parse_eml_preview(path: Path) -> dict:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
        msg = stdlib_email.message_from_string(raw)
        return {
            "subject": msg.get("Subject", "(no subject)"),
            "from_address": msg.get("From", ""),
        }
    except Exception:
        return {"subject": "(unreadable)", "from_address": ""}


@app.get("/api/emails")
def api_emails() -> list[dict]:
    analyzed: dict[tuple[str, int], dict] = {}
    for row in list_recent_results(limit=500):
        key = (str(row["email_address"]), int(row["uid"]))
        analyzed[key] = {
            "uid": int(row["uid"]),
            "email_address": str(row["email_address"]),
            "subject": str(row["subject"]),
            "from_address": str(row["from_address"]),
            "analyzed": True,
            "final_verdict": str(row["final_verdict"]),
            "analyzed_at_utc": str(row.get("analyzed_at_utc", "")),
        }

    all_emails = analyzed

    mailboxes = list_mailboxes()
    for mailbox in mailboxes:
        email_address = str(mailbox["email_address"])
        mailbox_dir = MESSAGES_DIR / sanitize_mailbox_dir(email_address)
        if not mailbox_dir.exists():
            continue
        for eml_path in sorted(mailbox_dir.glob("*.eml")):
            try:
                uid = int(eml_path.stem)
            except ValueError:
                continue
            key = (email_address, uid)
            if key in all_emails:
                continue
            preview = _parse_eml_preview(eml_path)
            all_emails[key] = {
                "uid": uid,
                "email_address": email_address,
                "subject": preview["subject"],
                "from_address": preview["from_address"],
                "analyzed": False,
                "final_verdict": None,
                "analyzed_at_utc": None,
            }

    return sorted(all_emails.values(), key=lambda r: r["uid"], reverse=True)


@app.get("/api/email/{uid}/raw")
def api_email_raw(uid: int) -> dict:
    mailboxes = list_mailboxes()
    for mailbox in mailboxes:
        email_address = str(mailbox["email_address"])
        path = MESSAGES_DIR / sanitize_mailbox_dir(email_address) / f"{uid}.eml"
        if path.exists():
            msg = stdlib_email.message_from_string(
                path.read_text(encoding="utf-8", errors="replace")
            )
            body = ""
            if msg.is_multipart():
                plain_body = ""
                html_body = ""
                for part in msg.walk():
                    ct = part.get_content_type()
                    if ct in ("text/plain", "text/html"):
                        try:
                            decoded = part.get_payload(decode=True).decode(
                                part.get_content_charset() or "utf-8", errors="replace"
                            )
                            if ct == "text/plain":
                                plain_body = decoded
                            else:
                                html_body = decoded
                        except Exception:
                            pass
                body = plain_body or html_body
            else:
                try:
                    body = msg.get_payload(decode=True).decode(
                        msg.get_content_charset() or "utf-8", errors="replace"
                    )
                except Exception:
                    body = str(msg.get_payload())
            return {"uid": uid, "body": body}
    raise HTTPException(status_code=404, detail="Email not found")


@app.get("/api/stream/{uid}")
async def api_stream(uid: int) -> StreamingResponse:
    from web.agent_runner import stream_analysis

    mailboxes = list_mailboxes()
    if not mailboxes:
        async def _no_mailbox() -> AsyncGenerator[str, None]:
            yield 'data: {"type":"error","message":"No mailbox bound"}\n\n'
        return StreamingResponse(_no_mailbox(), media_type="text/event-stream")

    email_address = None
    eml_path = None
    for mailbox in mailboxes:
        candidate_addr = str(mailbox["email_address"])
        candidate_path = MESSAGES_DIR / sanitize_mailbox_dir(candidate_addr) / f"{uid}.eml"
        if candidate_path.exists():
            email_address = candidate_addr
            eml_path = candidate_path
            break

    if eml_path is None:
        raise HTTPException(status_code=404, detail="Email file not found")

    raw_email = eml_path.read_text(encoding="utf-8", errors="replace")

    async def _event_stream() -> AsyncGenerator[str, None]:
        async for event in stream_analysis(uid, email_address, raw_email):
            yield f"data: {json.dumps(event)}\n\n"
        yield 'data: {"type":"done"}\n\n'

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/")
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))

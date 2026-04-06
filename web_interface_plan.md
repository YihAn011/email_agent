# Web Interface Implementation Plan - Email Security Agent

## Overview

A real-time web UI for the email security agent. The browser connects to a live IMAP inbox, triggers the agent on selected emails, and visualizes the skill pipeline and results as they happen.

---

## Tech Stack

| Layer | Choice | Reason |
|-------|--------|--------|
| Backend | FastAPI + uvicorn | Async-native and simple |
| Frontend | Vanilla JS + single HTML file | No build step |
| Real-time | Server-Sent Events | Simple one-way event stream |
| DB | Existing SQLite via `storage.py` | Reuse current persistence |

New dependencies proposed by this plan:
- `fastapi`
- `uvicorn[standard]`
- `python-multipart`

---

## Architecture

```text
Browser
  POST /api/link-account
  GET  /api/status
  GET  /api/stream/{uid}

FastAPI server
  reads SQLite via storage.py
  starts existing daemon process
  runs LangGraph agent inline and emits SSE events
    -> MultiServerMCPClient
    -> mcp_server.py
    -> skills/*
```

The daemon can continue handling background polling. The web server only needs to trigger live analysis for the email the operator opens.

---

## New Files

```text
email_agent/
  web/
    __init__.py
    server.py
    agent_runner.py
    auth.py
    static/
      index.html
      app.js
```

Files likely to change:
- `requirements.txt`
- `skills/imap_monitor/storage.py`

---

## UI Layout

Main sections:
- Header with bound mailbox state
- Account linking form
- Recent email list
- Live skill flow column
- Live reasoning column
- Final report panel

The key UX point is to show skill execution and reasoning as a stream, not only the final verdict.

---

## Skill Node Design

Each skill appears as a vertical flow node with three states:
- `pending`
- `active`
- `done`

Suggested colors:
- `rspamd_scan_email`: indigo
- `email_header_auth_check`: emerald
- `urgency_check`: amber
- `url_reputation_check`: red

---

## SSE Event Schema

Suggested events:

`skill_start`
```json
{ "skill": "rspamd_scan_email", "label": "Rspamd Scan" }
```

`skill_complete`
```json
{ "skill": "rspamd_scan_email", "ok": true, "latency_ms": 420, "risk_level": "medium" }
```

`reasoning_token`
```json
{ "token": "Based on the rspamd score..." }
```

`agent_complete`
```json
{
  "final_verdict": "suspicious",
  "rspamd_score": 8.2,
  "header_risk_level": "high",
  "urgency_score": 0.74,
  "url_phishing_score": 0.31,
  "elapsed_ms": 3200
}
```

`error`
```json
{ "message": "rspamd connection refused", "retryable": true }
```

---

## Backend Endpoints

| Method | Path | Action |
|--------|------|--------|
| `POST` | `/api/link-account` | Bind IMAP and return session token |
| `GET` | `/api/status` | Poll monitor state + recent emails |
| `GET` | `/api/stream/{uid}` | SSE stream for a live analysis |
| `GET` | `/api/email/{uid}/report` | Fetch stored result |
| `GET` | `/` | Serve `index.html` |

---

## Session Auth

Simple in-process token map:
- token generated on successful IMAP bind
- token stored in browser session storage
- every request includes the token

---

## Extended DB Table

Suggested new table:

```sql
CREATE TABLE IF NOT EXISTS agent_results (
    uid INTEGER NOT NULL,
    email_address TEXT NOT NULL,
    urgency_score REAL,
    urgency_label TEXT,
    urgency_risk TEXT,
    url_phishing_score REAL,
    url_risk TEXT,
    agent_verdict TEXT,
    agent_reasoning TEXT,
    skills_called TEXT,
    elapsed_ms INTEGER,
    completed_at_utc TEXT,
    PRIMARY KEY (uid, email_address)
);
```

Needed helpers:
- `insert_agent_result(record)`
- `get_agent_result(uid, email_address)`

---

## Email Linking Flow

1. User enters email address, app password, host
2. Backend validates via IMAP bind skill
3. On success, daemon starts and UI switches to mailbox mode
4. Credentials continue to live in the existing SQLite DB

---

## Phased Implementation

### Phase 1 - Backend Skeleton
- Add `web/server.py`
- Implement basic API routes
- Serve a minimal static page

### Phase 2 - Frontend Shell
- Build page layout
- Add account linking
- Add polling for mailbox status

### Phase 3 - SSE Streaming
- Build `agent_runner.py`
- Emit tool and reasoning events
- Update the page live

### Phase 4 - Persist Results
- Add `agent_results`
- Reuse prior results instead of rerunning analysis

### Phase 5 - Polish
- Better error handling
- Disconnect flow
- Startup env checks
- Loading indicators

---

## Existing Files To Reuse

| File | Role |
|------|------|
| `skills/imap_monitor/storage.py` | DB helpers |
| `skills/imap_monitor/skill.py` | monitor lifecycle and mailbox status |
| `examples/run_langgraph_gemini_agent.py` | model for async agent execution |
| `mcp_server.py` | tool surface |

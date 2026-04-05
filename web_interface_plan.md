# Web Interface Implementation Plan — Email Security Agent

## Overview

A real-time web UI for the email security agent. Connects to a live IMAP inbox, runs the LangGraph agent on new emails, and visualizes the skill pipeline and results as they happen.

---

## Tech Stack

| Layer | Choice | Reason |
|-------|--------|--------|
| Backend | FastAPI + uvicorn | Async-native, matches existing codebase |
| Frontend | Vanilla JS + single HTML file | No build step, no npm, finite UI components |
| Real-time | Server-Sent Events (SSE) | Unidirectional server→browser push, simpler than WebSockets |
| DB | Existing SQLite via `storage.py` | No new DB needed, extend with one new table |

New pip dependencies: `fastapi`, `uvicorn[standard]`, `python-multipart`

---

## Architecture

```
Browser
  ├── POST /api/link-account   (IMAP credentials)
  ├── GET  /api/status         (polls every 5s for new emails)
  └── GET  /api/stream/{uid}   (SSE: live agent events per email)

FastAPI server  (web/server.py)
  ├── reads SQLite DB via existing storage.py
  ├── starts existing daemon process
  └── runs LangGraph agent inline → emits SSE events
        └── MultiServerMCPClient → mcp_server.py → skills/*.py
```

The existing daemon continues running as before (rspamd + header sweep). The web server triggers the full 4-skill LangGraph agent on demand when the browser opens an SSE stream for a specific email.

---

## New Files

```
email_agent/
  web/
    __init__.py          # empty package marker
    server.py            # FastAPI app + all routes
    agent_runner.py      # async generator: LangGraph → SSE events
    auth.py              # in-memory session token dict
    static/
      index.html         # full page HTML + CSS
      app.js             # vanilla JS: EventSource, polling, DOM updates
```

**Modified files:**
- `requirements.txt` — add fastapi, uvicorn[standard], python-multipart
- `skills/imap_monitor/storage.py` — add `agent_results` table + 2 new functions

**No changes to:** `mcp_server.py`, any `skills/*.py`, `imap_monitor_daemon.py`

---

## UI Layout

```
┌─────────────────────────────────────────────────────────────┐
│  HEADER: "Email Security Monitor"   [user@gmail.com ✓]      │
├─────────────────────────────────────────────────────────────┤
│  ACCOUNT PANEL (shown when no account linked)               │
│  [Email]  [App Password]  [Host: imap.gmail.com]  [Link →]  │
├─────────────────────────────────────────────────────────────┤
│  EMAIL LIST (scrollable, refreshes every 5s)                │
│  ┌──────────────────────────────┐                           │
│  │ ● Invoice attached  SUSPICIOUS│  ← click to analyze      │
│  │   sender@evil.com   2 min ago │                           │
│  └──────────────────────────────┘                           │
├──────────────────────┬──────────────────────────────────────┤
│  SKILL FLOWCHART     │  LIVE REASONING                      │
│  (left column)       │  (right column)                      │
│                      │                                      │
│  [Rspamd Scan]       │  "Analyzing email headers..."        │
│         ↓            │  "rspamd returned score 8.2..."      │
│  [Header Auth]       │  "Checking urgency signals..."       │
│         ↓            │  "This email uses pressure..."       │
│  [Urgency Check]     │                                      │
│         ↓            │                                      │
│  [URL Reputation]    │                                      │
├──────────────────────┴──────────────────────────────────────┤
│  ANALYSIS REPORT (appears after pipeline completes)         │
│                                                             │
│  Rspamd Score      [████████░░] 0.82   HIGH                 │
│  Header Auth       [██████████] 1.00   HIGH                 │
│  URL Reputation    [███░░░░░░░] 0.31   LOW                  │
│  Urgency           [███████░░░] 0.74   MEDIUM               │
│  TLD Reputation    [ not yet available ]                    │
│                                                             │
│  Final Verdict:  ● SUSPICIOUS                               │
└─────────────────────────────────────────────────────────────┘
```

---

## Skill Node Design

Each skill is a rounded rectangle in a vertical flex column, connected by arrow dividers.

**States:**
- `pending` — grey, dashed border
- `active` — solid color, CSS `@keyframes pulse` animation (0.3s ease-in)
- `done` — solid color, checkmark badge, latency shown

**Colors:**
| Skill | Color | Hex |
|-------|-------|-----|
| rspamd_scan_email | Indigo | `#6366f1` |
| email_header_auth_check | Emerald | `#10b981` |
| urgency_check | Amber | `#f59e0b` |
| url_reputation_check | Red | `#ef4444` |

No JS animation library — CSS transitions only.

---

## SSE Event Schema

All events: `event: <name>` + `data: <json>` format.

**`skill_start`** — emitted when agent calls a tool
```json
{ "skill": "rspamd_scan_email", "label": "Rspamd Scan", "color": "#6366f1" }
```

**`skill_complete`** — emitted when tool returns
```json
{ "skill": "rspamd_scan_email", "ok": true, "latency_ms": 420, "risk_level": "medium", "score": 8.2 }
```

**`reasoning_token`** — one per streamed LLM token
```json
{ "token": "Based on the rspamd score..." }
```

**`agent_complete`** — final event with all scores
```json
{
  "final_verdict": "suspicious",
  "rspamd_score": 8.2,
  "header_risk_level": "high",
  "urgency_score": 0.74,
  "urgency_label": "somewhat urgent",
  "url_phishing_score": 0.31,
  "url_risk": "low",
  "elapsed_ms": 3200
}
```

**`error`**
```json
{ "message": "rspamd connection refused", "retryable": true }
```

Streaming is powered by LangGraph's `.astream_events()` API:
- `on_tool_start` → `skill_start`
- `on_tool_end` → `skill_complete`
- `on_chat_model_stream` → `reasoning_token`

---

## Backend Endpoints

| Method | Path | Action |
|--------|------|--------|
| `POST` | `/api/link-account` | Bind IMAP, start daemon, return session token |
| `GET` | `/api/status` | Poll DB for monitor state + recent emails |
| `GET` | `/api/stream/{uid}` | SSE stream: run LangGraph agent live |
| `GET` | `/api/email/{uid}/report` | Fetch stored agent results after completion |
| `GET` | `/` | Serve `index.html` |

### Session Auth

Simple in-process `dict` mapping `session_token → email_address`. Token generated with `secrets.token_hex(32)` on successful IMAP bind. Stored in `sessionStorage` on the browser (clears on tab close). Every API call passes `?session_token=<token>`.

---

## Extended DB Table

Add to `skills/imap_monitor/storage.py`:

```sql
CREATE TABLE IF NOT EXISTS agent_results (
    uid             INTEGER NOT NULL,
    email_address   TEXT NOT NULL,
    urgency_score   REAL,
    urgency_label   TEXT,
    urgency_risk    TEXT,
    url_phishing_score REAL,
    url_risk        TEXT,
    agent_verdict   TEXT,
    agent_reasoning TEXT,
    skills_called   TEXT,   -- JSON array
    elapsed_ms      INTEGER,
    completed_at_utc TEXT,
    PRIMARY KEY (uid, email_address)
);
```

New functions: `insert_agent_result(record)`, `get_agent_result(uid, email_address)`.

If a result row already exists when `/api/stream/{uid}` is opened, the backend replays a synthetic event sequence immediately instead of re-running the agent.

---

## Email Account Linking Flow

1. User fills form: email address, Gmail app password, IMAP host (default `imap.gmail.com`)
2. `POST /api/link-account` → backend calls `BindImapMailboxSkill` (validates IMAP connection live)
3. On success: daemon starts, session token returned, form hides, email list appears
4. Credentials stored in existing SQLite DB at `runtime/imap_monitor/monitor.db` (already `chmod 600`)

---

## Phased Implementation

### Phase 1 — Backend Skeleton
- Create `web/__init__.py`, `web/server.py`, `web/auth.py`
- Implement `/api/link-account`, `/api/status`, static file serving
- Add fastapi/uvicorn/python-multipart to `requirements.txt`
- Minimal `index.html` to verify endpoints work
- **Run with:** `uvicorn web.server:app --reload --port 8000`

### Phase 2 — Frontend Shell
- Full HTML/CSS two-column layout
- Account linking form wired to backend
- Status polling loop (5s interval)
- Skill node DOM + CSS transitions (pending → active → done)
- Gauge DOM + CSS transitions (mock data first)

### Phase 3 — SSE Streaming
- Create `web/agent_runner.py`: async generator using `.astream_events()`
- Add `GET /api/stream/{uid}` with `StreamingResponse`
- Wire `EventSource` in `app.js` for all 5 event types
- Skill nodes animate live as agent runs

### Phase 4 — Persist Results + Report Section
- Add `agent_results` table to `storage.py`
- Store agent output after `agent_complete`
- Report gauges animate on `agent_complete` event
- Page refresh loads from DB (no re-run)

### Phase 5 — Polish
- IMAP credential validation before storing (fail fast with clear error)
- Rspamd-down graceful error display in UI
- "Disconnect Account" button → `POST /api/stop-monitor`
- Startup check for LLM API key env var
- Loading spinner on account link button

---

## Key Existing Files to Build On

| File | Role in web layer |
|------|------------------|
| `skills/imap_monitor/storage.py` | DB read/write; add `agent_results` table here |
| `skills/imap_monitor/skill.py` | `start_monitor_process()`, `get_monitor_status()`, `list_mailboxes()` — called directly by server |
| `examples/run_langgraph_gemini_agent.py` | Direct template for `web/agent_runner.py`; swap `.ainvoke()` → `.astream_events()` |
| `mcp_server.py` | Launched as subprocess by `MultiServerMCPClient`, unchanged |

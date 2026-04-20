# Intelligent Mail — Web UI Design Spec

**Date:** 2026-04-17  
**Stack:** FastAPI + Server-Sent Events + Vanilla JS  
**Status:** Approved for implementation

---

## Overview

A localhost web interface for the email classification agent. Displays a live IMAP inbox, triggers the agent pipeline on demand, and streams the skill execution and reasoning live as it happens.

---

## Layout

**Split pane — two columns, always visible:**

- **Left (30%):** inbox list. Each row shows subject, sender, timestamp, and a verdict badge. Clicking a row loads its analysis in the right panel without navigating away.
- **Right (70%):** analysis panel for the selected email. Contains: email header bar, live timeline feed, verdict bar, blurred email body.

**Top bar:** app title ("✦ INTELLIGENT MAIL"), connected mailbox address, green status dot, disconnect button.

---

## Inbox List

Each row displays:
- Subject (truncated)
- Sender address
- Timestamp
- Verdict badge: `BENIGN` (green) · `SUSPICIOUS` (amber) · `PHISHING` (red/purple) · `ERROR` (grey) · `—` (not yet analyzed)

Selected row has a left purple border highlight. Clicking an unanalyzed email triggers analysis immediately.

---

## Analysis Panel

### Email Header Bar
Subject, From, To, received timestamp.

### Live Timeline Feed

Skills appear as nodes in a vertical feed as the agent runs. Each node transitions through three states:

- **Pending** — dim circle, grey border, "waiting" label
- **Running** — pulsing blue dot, blue border, "running…" label
- **Done** — filled colored circle (✓), result summary inline

A vertical connector line links nodes top to bottom.

Skill colors:
- `rspamd_scan_email` — purple
- `email_header_auth_check` — green
- `urgency_check` — amber
- `url_reputation_check` — red
- `error_pattern_memory_check` — slate

Each completed node shows the key output field inline:
- rspamd: `score 14.2 · HIGH · reject`
- header_auth: `risk=high · dmarc_fail · spf_not_pass`
- urgency: `score 0.91 · very urgent`
- url_reputation: `phishing_score 0.03 · low`
- error_pattern_memory: `matched=true · suggested=benign`

### Reasoning Text

Below the skill nodes, a left-bordered italic text box streams the agent's reasoning tokens as they arrive. Cursor blink effect at the end while streaming.

### Verdict Bar

Appears after `agent_complete` event. Full-width bar colored by verdict:
- `benign` — green (`#052e16` bg, `#4ade80` text)
- `suspicious` — amber
- `phishing_or_spoofing` — red (`#450a0a` bg, `#fca5a5` text), label "PHISHING"
- `error` — grey

Shows verdict label, elapsed time, skill count.

### Email Body

Below the verdict bar. Behavior by verdict:
- `benign` — rendered directly
- `suspicious` — blurred with semi-transparent overlay and "Click to reveal" button
- `phishing_or_spoofing` — blurred with overlay, label "Blurred — classified as phishing"
- `error` — rendered directly (analysis failed, no basis to hide)

Clicking the overlay removes the blur for that session only.

Previously analyzed emails load verdict + body from SQLite cache — no re-run.

---

## Backend API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Serve `index.html` |
| `GET` | `/api/emails` | List emails: analyzed ones from `email_results`, unanalyzed ones by scanning `.eml` files in `runtime/imap_monitor/messages/`; merged and ordered by uid desc |
| `GET` | `/api/stream/{uid}` | SSE stream — triggers agent and emits events |
| `GET` | `/api/email/{uid}/raw` | Raw email body text for display |
| `GET` | `/api/status` | Monitor status (running, mailbox, result count) |

---

## SSE Event Schema

All events are JSON lines prefixed `data: `.

```
skill_start       { "skill": "rspamd_scan_email", "label": "Running email security scan" }
skill_complete    { "skill": "rspamd_scan_email", "ok": true, "latency_ms": 420, "summary": "score 14.2 · HIGH · reject" }
reasoning_token   { "token": "The rspamd score..." }
agent_complete    { "verdict": "phishing_or_spoofing", "elapsed_ms": 3200, "skills_called": 3 }
error             { "message": "rspamd connection refused", "retryable": true }
```

---

## Verdict Mapping

| Pipeline value | Display label | Badge color | Body |
|---|---|---|---|
| `benign` | BENIGN | green | shown directly |
| `suspicious` | SUSPICIOUS | amber | blurred overlay |
| `phishing_or_spoofing` | PHISHING | red | blurred overlay |
| `error` | ERROR | grey | shown directly |

---

## New Files

```
web/
  __init__.py
  server.py          FastAPI app, all routes
  agent_runner.py    wraps EmailAgentRuntime, emits SSE events
  static/
    index.html       single-page shell
    app.js           DOM logic, SSE client, timeline renderer
```

---

## Existing Files Reused (unchanged)

| File | Role |
|------|------|
| `harness/runtime.py` | `EmailAgentRuntime` — agent + streaming with `progress_callback` |
| `skills/imap_monitor/storage.py` | `list_recent_results`, `get_email_result`, `write_raw_email` |
| `mcp_server.py` | MCP tool surface |
| `imap_monitor_daemon.py` | Background IMAP polling (keeps running) |

---

## New Dependencies

- `fastapi`
- `uvicorn[standard]`

---

## Run Command

```bash
uvicorn web.server:app --reload --port 8000
```

Open `http://localhost:8000`.

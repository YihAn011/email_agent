# Intelligent Mail Web UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a localhost FastAPI + SSE + Vanilla JS web interface that displays the IMAP inbox, triggers the LLM agent on demand, and streams skill execution and reasoning live.

**Architecture:** FastAPI serves a single HTML page and a small JSON/SSE API. Clicking an email opens an SSE stream that drives a LangGraph agent run, emitting structured events as skills start/complete and reasoning tokens arrive. Results are cached in SQLite so re-opening an email loads instantly.

**Tech Stack:** FastAPI, uvicorn, Server-Sent Events, Vanilla JS, LangGraph (existing), SQLite (existing)

---

## File Map

| File | Role |
|------|------|
| `web/__init__.py` | Package marker |
| `web/server.py` | FastAPI app — all routes, static serving, SSE endpoint |
| `web/agent_runner.py` | Async generator that runs the LangGraph agent and yields SSE event dicts |
| `web/static/index.html` | Single-page shell — split pane layout, all HTML structure |
| `web/static/app.js` | Inbox rendering, SSE client, timeline feed, verdict bar, body reveal |
| `requirements.txt` | Add `fastapi`, `uvicorn[standard]` |

**Existing files used as-is (no changes):**
- `harness/runtime.py` — `_BaseRuntime.setup()` pattern, `describe_progress_message()`, `parse_tool_payload()`, `render_content()`, `extract_final_output()`
- `skills/imap_monitor/storage.py` — `list_recent_results()`, `get_email_result()`, `insert_email_result()`, `list_mailboxes()`, `sanitize_mailbox_dir()`, `MESSAGES_DIR`
- `mcp_server.py` — MCP tool surface
- `examples/model_factory.py` — `build_chat_model()`, `resolve_provider()`, `resolve_default_model()`

---

## Task 1: Dependencies and Package Scaffold

**Files:**
- Modify: `requirements.txt`
- Create: `web/__init__.py`
- Create: `web/static/.gitkeep`

- [ ] **Step 1: Add new dependencies to requirements.txt**

Open `requirements.txt` and append:
```
fastapi>=0.111.0
uvicorn[standard]>=0.29.0
```

- [ ] **Step 2: Create the web package**

Create `web/__init__.py` (empty file):
```python
```

Create `web/static/` directory and an empty `web/static/.gitkeep`.

- [ ] **Step 3: Install dependencies**

```bash
pip install fastapi "uvicorn[standard]"
```

Expected: installs without errors.

- [ ] **Step 4: Verify import**

```bash
python -c "import fastapi; import uvicorn; print('ok')"
```

Expected output: `ok`

- [ ] **Step 5: Commit**

```bash
git add requirements.txt web/__init__.py web/static/.gitkeep
git commit -m "feat: add web package scaffold and fastapi/uvicorn deps"
```

---

## Task 2: FastAPI Server — Routes and Static Serving

**Files:**
- Create: `web/server.py`

The server exposes five routes. The SSE route (`/api/stream/{uid}`) is a stub that returns a placeholder event for now — it gets wired to the real agent runner in Task 3.

- [ ] **Step 1: Write a test for /api/status**

Create `tests/web/test_server.py`:

```python
import pytest
from fastapi.testclient import TestClient
from web.server import app

client = TestClient(app)

def test_status_returns_200():
    resp = client.get("/api/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "monitor_running" in data
    assert "result_count" in data

def test_emails_returns_list():
    resp = client.get("/api/emails")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/web/test_server.py -v
```

Expected: `ImportError` or `ModuleNotFoundError` — `web.server` doesn't exist yet.

- [ ] **Step 3: Create web/server.py**

```python
from __future__ import annotations

import email as stdlib_email
import os
import sys
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
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
        "result_count": count_results(),
    }


def _parse_eml_preview(path: Path) -> dict:
    """Return subject and from_address from an .eml file without loading the body."""
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
    """
    Merge analyzed emails (from email_results) with unanalyzed .eml files on disk.
    Returns a list ordered by uid descending.
    """
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

    all_emails: dict[tuple[str, int], dict] = dict(analyzed)

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
    """Return raw text of the .eml file for the given uid."""
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
                for part in msg.walk():
                    ct = part.get_content_type()
                    if ct in ("text/plain", "text/html"):
                        try:
                            body = part.get_payload(decode=True).decode(
                                part.get_content_charset() or "utf-8", errors="replace"
                            )
                            if ct == "text/plain":
                                break
                        except Exception:
                            pass
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
    """SSE stream: run agent analysis for uid and emit events."""
    from web.agent_runner import stream_analysis  # imported here to avoid circular init

    mailboxes = list_mailboxes()
    if not mailboxes:
        async def _no_mailbox() -> AsyncGenerator[str, None]:
            yield 'data: {"type":"error","message":"No mailbox bound"}\n\n'
        return StreamingResponse(_no_mailbox(), media_type="text/event-stream")

    email_address = str(mailboxes[0]["email_address"])
    eml_path = MESSAGES_DIR / sanitize_mailbox_dir(email_address) / f"{uid}.eml"
    if not eml_path.exists():
        raise HTTPException(status_code=404, detail="Email file not found")

    raw_email = eml_path.read_text(encoding="utf-8", errors="replace")

    async def _event_stream() -> AsyncGenerator[str, None]:
        async for event in stream_analysis(uid, email_address, raw_email):
            import json
            yield f"data: {json.dumps(event)}\n\n"
        yield "data: {\"type\":\"done\"}\n\n"

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/")
def index():
    from fastapi.responses import FileResponse
    return FileResponse(str(STATIC_DIR / "index.html"))
```

- [ ] **Step 4: Create tests/ directory if needed**

```bash
mkdir -p tests/web
touch tests/__init__.py tests/web/__init__.py
```

- [ ] **Step 5: Run the tests**

```bash
pytest tests/web/test_server.py -v
```

Expected: both tests pass. (`/api/stream` is not tested here — it requires the agent.)

- [ ] **Step 6: Smoke-test the server manually**

Create a minimal `web/static/index.html` placeholder so the server starts:
```html
<!DOCTYPE html><html><body><h1>Intelligent Mail</h1></body></html>
```

Then run:
```bash
uvicorn web.server:app --reload --port 8000
```

Open `http://localhost:8000/api/status` — should return JSON.
Open `http://localhost:8000/api/emails` — should return a list (possibly empty).

- [ ] **Step 7: Commit**

```bash
git add web/server.py tests/web/test_server.py tests/__init__.py tests/web/__init__.py
git commit -m "feat: add FastAPI server with status, emails, and stream routes"
```

---

## Task 3: Agent Runner — SSE Event Generator

**Files:**
- Create: `web/agent_runner.py`

This module runs a single-turn LangGraph agent analysis and yields structured SSE event dicts. It reuses the MCP client setup from `harness/runtime.py` but is stateless (no chat history).

The agent streams via `astream(stream_mode="values")`. Each state snapshot contains the full message list. We diff against the previous count to find new messages and emit events for each.

- [ ] **Step 1: Write a unit test for _extract_verdict**

Add to `tests/web/test_server.py` (or create `tests/web/test_agent_runner.py`):

```python
# tests/web/test_agent_runner.py
from web.agent_runner import _extract_verdict

def test_phishing_verdict():
    assert _extract_verdict("This email is a phishing attempt.") == "phishing_or_spoofing"

def test_suspicious_verdict():
    assert _extract_verdict("The email looks suspicious due to urgency.") == "suspicious"

def test_benign_verdict():
    assert _extract_verdict("This is a legitimate email from Columbia IT.") == "benign"

def test_spoofing_verdict():
    assert _extract_verdict("Domain spoofing detected.") == "phishing_or_spoofing"

def test_default_conservative():
    assert _extract_verdict("Unable to determine conclusively.") == "suspicious"
```

- [ ] **Step 2: Run test to confirm failure**

```bash
pytest tests/web/test_agent_runner.py -v
```

Expected: `ImportError` — `web.agent_runner` doesn't exist.

- [ ] **Step 3: Create web/agent_runner.py**

```python
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, AsyncGenerator

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MCP_SERVER_PATH = PROJECT_ROOT / "mcp_server.py"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _extract_verdict(text: str) -> str:
    """Heuristic: map agent final message text to a pipeline verdict value."""
    lower = text.lower()
    if any(w in lower for w in ("phishing", "spoofing", "phish")):
        return "phishing_or_spoofing"
    if "suspicious" in lower:
        return "suspicious"
    if any(w in lower for w in ("benign", "legitimate", "safe", "ham", "no threat", "not phishing")):
        return "benign"
    return "suspicious"


def _skill_summary_from_tool_message(message: ToolMessage) -> str:
    """Extract a one-line display summary from a completed skill ToolMessage."""
    try:
        payload = json.loads(message.content) if isinstance(message.content, str) else {}
    except (json.JSONDecodeError, TypeError):
        return ""
    if not isinstance(payload, dict) or not payload.get("ok"):
        err = (payload.get("error") or {}) if isinstance(payload, dict) else {}
        return f"error: {err.get('message', 'failed')}"
    data = payload.get("data") or {}
    name = message.name or ""
    if name == "rspamd_scan_email":
        return f"score {data.get('score', '?')} · {data.get('risk_level', '?')} · {data.get('action', '?')}"
    if name == "email_header_auth_check":
        findings = data.get("findings") or []
        types = ", ".join(f.get("type", "") for f in findings[:3]) if findings else "none"
        return f"risk={data.get('risk_level', '?')} · findings: {types}"
    if name == "urgency_check":
        score = data.get('urgency_score')
        score_str = f"{score:.2f}" if isinstance(score, float) else str(score or '?')
        return f"score {score_str} · {data.get('urgency_label', '?')}"
    if name == "url_reputation_check":
        score = data.get('phishing_score')
        score_str = f"{score:.2f}" if isinstance(score, float) else str(score or '?')
        return f"phishing_score {score_str} · {data.get('risk_level', '?')}"
    if name == "error_pattern_memory_check":
        matched = data.get("matched", False)
        suggested = data.get("suggested_verdict") or "no override"
        return f"matched={matched} · {suggested}"
    return "complete"


def _events_from_new_messages(new_messages: list[BaseMessage]) -> list[dict]:
    """Convert a batch of new LangGraph messages into SSE event dicts."""
    events: list[dict] = []
    for msg in new_messages:
        if isinstance(msg, AIMessage):
            tool_calls = getattr(msg, "tool_calls", None) or []
            for call in tool_calls:
                if isinstance(call, dict) and call.get("name"):
                    events.append({"type": "skill_start", "skill": call["name"]})
            # Final message with content and no tool calls
            if not tool_calls:
                content = ""
                if isinstance(msg.content, str):
                    content = msg.content
                elif isinstance(msg.content, list):
                    parts = [
                        item.get("text", "") if isinstance(item, dict) else str(item)
                        for item in msg.content
                    ]
                    content = "\n".join(p for p in parts if p)
                if content.strip():
                    events.append({"type": "reasoning_text", "text": content.strip()})
        elif isinstance(msg, ToolMessage):
            summary = _skill_summary_from_tool_message(msg)
            try:
                payload = json.loads(msg.content) if isinstance(msg.content, str) else {}
            except (json.JSONDecodeError, TypeError):
                payload = {}
            ok = isinstance(payload, dict) and bool(payload.get("ok", True))
            events.append({
                "type": "skill_complete",
                "skill": msg.name or "unknown",
                "ok": ok,
                "summary": summary,
            })
    return events


async def stream_analysis(
    uid: int,
    email_address: str,
    raw_email: str,
) -> AsyncGenerator[dict, None]:
    """
    Yield SSE event dicts for a single email analysis.
    If a cached result exists in SQLite, yield a synthetic agent_complete immediately.
    Otherwise run the LangGraph agent and stream live events.
    """
    from skills.imap_monitor.storage import get_email_result, insert_email_result, utc_now_iso

    cached = get_email_result(email_address, uid)
    if cached:
        yield {
            "type": "agent_complete",
            "verdict": str(cached["final_verdict"]),
            "summary": str(cached.get("summary", "")),
            "elapsed_ms": 0,
            "cached": True,
        }
        return

    from langchain_mcp_adapters.client import MultiServerMCPClient
    from langgraph.prebuilt import create_react_agent
    from examples.model_factory import build_chat_model, resolve_provider, resolve_default_model
    from harness.prompts import build_single_turn_prompt

    provider = resolve_provider(None)
    model_name = resolve_default_model(provider)
    rspamd_base_url = os.getenv("RSPAMD_BASE_URL", "http://127.0.0.1:11333")

    env = dict(os.environ)
    env.pop("PS1", None)
    env["RSPAMD_BASE_URL"] = rspamd_base_url

    model = build_chat_model(provider=provider, model_name=model_name, temperature=0)
    server_config = {
        "email-security": {
            "transport": "stdio",
            "command": sys.executable,
            "args": [str(MCP_SERVER_PATH)],
            "cwd": str(PROJECT_ROOT),
            "env": env,
        }
    }

    client = MultiServerMCPClient(server_config)
    tools = await client.get_tools()
    agent = create_react_agent(model=model, tools=tools)

    prompt = build_single_turn_prompt(
        "Analyze this email for security threats. Provide a verdict and confidence.",
        raw_email=raw_email,
        raw_headers=None,
    )

    messages = [SystemMessage(content="You are an email security analyst."), HumanMessage(content=prompt)]
    start_ms = int(time.time() * 1000)
    prev_count = 0
    final_verdict = "suspicious"
    final_text = ""

    try:
        async for state in agent.astream({"messages": messages}, stream_mode="values"):
            if not isinstance(state, dict) or not isinstance(state.get("messages"), list):
                continue
            all_messages: list[BaseMessage] = state["messages"]
            new_messages = all_messages[prev_count:]
            prev_count = len(all_messages)
            for event in _events_from_new_messages(new_messages):
                if event["type"] == "reasoning_text":
                    final_text = event["text"]
                    final_verdict = _extract_verdict(final_text)
                yield event
    except Exception as exc:
        yield {"type": "error", "message": str(exc), "retryable": False}
        return

    elapsed_ms = int(time.time() * 1000) - start_ms

    # Persist to SQLite so re-opens are instant
    try:
        insert_email_result({
            "email_address": email_address,
            "uid": uid,
            "subject": "",
            "from_address": "",
            "analyzed_at_utc": utc_now_iso(),
            "final_verdict": final_verdict,
            "summary": final_text[:500],
        })
    except Exception:
        pass  # caching is best-effort

    yield {
        "type": "agent_complete",
        "verdict": final_verdict,
        "summary": final_text,
        "elapsed_ms": elapsed_ms,
        "cached": False,
    }
```

- [ ] **Step 4: Run the unit tests**

```bash
pytest tests/web/test_agent_runner.py -v
```

Expected: all 5 verdict extraction tests pass.

- [ ] **Step 5: Commit**

```bash
git add web/agent_runner.py tests/web/test_agent_runner.py
git commit -m "feat: add agent_runner SSE event generator with verdict extraction"
```

---

## Task 4: HTML Shell — Split Pane Layout

**Files:**
- Create: `web/static/index.html`

This replaces the placeholder from Task 2. Contains the full HTML structure — no logic yet, just the skeleton that `app.js` will populate.

- [ ] **Step 1: Create web/static/index.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Intelligent Mail</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #0f172a; color: #94a3b8; font-family: 'Menlo', 'Monaco', 'Consolas', monospace; font-size: 13px; height: 100vh; display: flex; flex-direction: column; overflow: hidden; }

    /* Top bar */
    #topbar { background: #1e293b; border-bottom: 1px solid #0f172a; padding: 10px 18px; display: flex; align-items: center; justify-content: space-between; flex-shrink: 0; }
    #topbar .brand { color: #7c3aed; font-weight: 700; font-size: 13px; letter-spacing: 1px; }
    #topbar .account { display: flex; align-items: center; gap: 8px; font-size: 11px; color: #64748b; }
    #status-dot { width: 7px; height: 7px; border-radius: 50%; background: #475569; display: inline-block; }
    #status-dot.connected { background: #22c55e; }

    /* Split pane */
    #split { display: flex; flex: 1; overflow: hidden; }

    /* Inbox panel */
    #inbox { width: 30%; border-right: 1px solid #1e293b; display: flex; flex-direction: column; overflow: hidden; }
    #inbox-header { padding: 8px 12px; border-bottom: 1px solid #1e293b; font-size: 10px; color: #475569; letter-spacing: 1px; flex-shrink: 0; }
    #inbox-list { flex: 1; overflow-y: auto; }
    .email-row { padding: 9px 12px; border-left: 3px solid transparent; border-bottom: 1px solid #0f172a; cursor: pointer; }
    .email-row:hover { background: #131f30; }
    .email-row.selected { background: #1e1035; border-left-color: #7c3aed; }
    .email-row .row-top { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 3px; gap: 6px; }
    .email-row .subject { color: #e2e8f0; font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex: 1; }
    .email-row .subject.unread { font-weight: 600; }
    .email-row .sender { color: #334155; font-size: 10px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .badge { border-radius: 2px; padding: 1px 5px; font-size: 9px; font-weight: 600; flex-shrink: 0; }
    .badge-benign { background: #052e16; color: #4ade80; }
    .badge-suspicious { background: #431407; color: #fb923c; }
    .badge-phishing { background: #450a0a; color: #fca5a5; }
    .badge-error { background: #1e293b; color: #64748b; }
    .badge-none { background: #1e293b; color: #334155; }

    /* Analysis panel */
    #analysis { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
    #analysis-empty { flex: 1; display: flex; align-items: center; justify-content: center; color: #1e293b; font-size: 13px; }
    #analysis-content { flex: 1; display: none; flex-direction: column; overflow: hidden; }
    #analysis-content.visible { display: flex; }

    /* Email header bar */
    #email-header-bar { padding: 10px 16px; border-bottom: 1px solid #1e293b; flex-shrink: 0; background: #0f172a; }
    #email-subject { color: #e2e8f0; font-size: 13px; font-weight: 600; margin-bottom: 3px; }
    #email-meta { color: #475569; font-size: 10px; }

    /* Scrollable analysis body */
    #analysis-body { flex: 1; overflow-y: auto; padding: 14px 16px; display: flex; flex-direction: column; gap: 10px; }

    /* Timeline */
    #timeline { display: flex; flex-direction: column; gap: 0; }
    .timeline-section-label { font-size: 9px; color: #475569; letter-spacing: 1px; margin-bottom: 8px; }
    .skill-node { display: flex; gap: 10px; align-items: flex-start; }
    .skill-node-connector { display: flex; flex-direction: column; align-items: center; flex-shrink: 0; }
    .skill-dot { width: 18px; height: 18px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 9px; flex-shrink: 0; }
    .skill-dot.pending { background: #0f172a; border: 2px solid #1e293b; }
    .skill-dot.running { background: #0f172a; border: 2px solid #3b82f6; }
    .skill-dot.running::after { content: ''; display: block; width: 6px; height: 6px; border-radius: 50%; background: #3b82f6; animation: pulse 1s infinite; }
    .skill-dot.done-purple { background: #7c3aed; color: white; }
    .skill-dot.done-green  { background: #16a34a; color: white; }
    .skill-dot.done-amber  { background: #d97706; color: white; }
    .skill-dot.done-red    { background: #dc2626; color: white; }
    .skill-dot.done-slate  { background: #475569; color: white; }
    .skill-dot.done-error  { background: #450a0a; border: 1px solid #dc2626; color: #fca5a5; }
    .connector-line { width: 1px; height: 14px; background: #1e293b; }
    .skill-card { flex: 1; border-radius: 4px; padding: 6px 10px; margin-bottom: 4px; border: 1px solid; }
    .skill-card.pending { background: #0f172a; border-color: #1e293b; color: #334155; }
    .skill-card.running { background: #0c1a2e; border-color: #1d4ed8; }
    .skill-card.done { border-color: #1e293b; }
    .skill-card.skill-rspamd.done    { background: #1d1040; border-color: #3b1d6e; }
    .skill-card.skill-header.done    { background: #0b1f14; border-color: #14532d; }
    .skill-card.skill-urgency.done   { background: #1c1a08; border-color: #5a3a00; }
    .skill-card.skill-url.done       { background: #1a0c0c; border-color: #7f1d1d; }
    .skill-card.skill-memory.done    { background: #0f172a; border-color: #334155; }
    .skill-card .skill-name { font-size: 10px; font-weight: 600; margin-bottom: 2px; }
    .skill-card .skill-result { font-size: 9px; color: #64748b; }
    .skill-card.skill-rspamd .skill-name { color: #a78bfa; }
    .skill-card.skill-header .skill-name { color: #4ade80; }
    .skill-card.skill-urgency .skill-name { color: #fbbf24; }
    .skill-card.skill-url .skill-name    { color: #f87171; }
    .skill-card.skill-memory .skill-name { color: #94a3b8; }
    .skill-card.running .skill-name { color: #93c5fd; }
    .skill-card.pending .skill-name { color: #334155; }

    /* Reasoning box */
    #reasoning-box { background: #0c1220; border-left: 2px solid #334155; border-radius: 0 4px 4px 0; padding: 8px 10px; color: #64748b; font-size: 10px; line-height: 1.7; font-style: italic; display: none; white-space: pre-wrap; }
    #reasoning-box.visible { display: block; }
    #reasoning-cursor { display: inline-block; width: 1px; height: 11px; background: #94a3b8; vertical-align: text-bottom; animation: blink 1s step-end infinite; }

    /* Verdict bar */
    #verdict-bar { border-radius: 4px; padding: 8px 14px; display: none; align-items: center; justify-content: space-between; flex-shrink: 0; }
    #verdict-bar.visible { display: flex; }
    #verdict-bar.benign   { background: #052e16; border: 1px solid #16a34a; }
    #verdict-bar.suspicious { background: #1c1917; border: 1px solid #78716c; }
    #verdict-bar.phishing_or_spoofing { background: #450a0a; border: 1px solid #dc2626; }
    #verdict-bar.error    { background: #1e293b; border: 1px solid #475569; }
    #verdict-label { font-size: 11px; font-weight: 700; }
    #verdict-bar.benign   #verdict-label { color: #4ade80; }
    #verdict-bar.suspicious #verdict-label { color: #fb923c; }
    #verdict-bar.phishing_or_spoofing #verdict-label { color: #fca5a5; }
    #verdict-bar.error    #verdict-label { color: #64748b; }
    #verdict-meta { font-size: 9px; color: #475569; }

    /* Email body */
    #body-section { display: none; }
    #body-section.visible { display: block; }
    #body-section-label { font-size: 9px; color: #475569; letter-spacing: 1px; margin-bottom: 6px; }
    #body-wrapper { position: relative; background: #1e293b; border-radius: 4px; overflow: hidden; }
    #body-content { padding: 12px; font-size: 10px; line-height: 1.7; color: #94a3b8; white-space: pre-wrap; max-height: 300px; overflow-y: auto; }
    #body-content.blurred { filter: blur(4px); pointer-events: none; user-select: none; }
    #body-overlay { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; background: rgba(15,23,42,0.7); }
    #body-overlay.hidden { display: none; }
    #reveal-btn { background: #374151; border: 1px solid #4b5563; border-radius: 3px; padding: 5px 14px; font-size: 10px; color: #d1d5db; cursor: pointer; font-family: inherit; }
    #reveal-btn:hover { background: #4b5563; }
    #body-overlay-label { font-size: 10px; color: #fca5a5; margin-bottom: 8px; text-align: center; }

    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
    @keyframes blink  { 50%{opacity:0} }
  </style>
</head>
<body>

  <div id="topbar">
    <span class="brand">✦ INTELLIGENT MAIL</span>
    <span class="account">
      <span id="status-dot"></span>
      <span id="account-label">not connected</span>
    </span>
  </div>

  <div id="split">

    <!-- Inbox -->
    <div id="inbox">
      <div id="inbox-header">INBOX</div>
      <div id="inbox-list">
        <div style="padding:16px;color:#334155;font-size:11px;">Loading…</div>
      </div>
    </div>

    <!-- Analysis -->
    <div id="analysis">
      <div id="analysis-empty">Select an email to analyze</div>

      <div id="analysis-content">
        <div id="email-header-bar">
          <div id="email-subject"></div>
          <div id="email-meta"></div>
        </div>

        <div id="analysis-body">
          <div id="timeline">
            <div class="timeline-section-label">ANALYSIS</div>
          </div>
          <div id="reasoning-box"></div>
          <div id="verdict-bar">
            <span id="verdict-label"></span>
            <span id="verdict-meta"></span>
          </div>
          <div id="body-section">
            <div id="body-section-label">EMAIL BODY</div>
            <div id="body-wrapper">
              <div id="body-content"></div>
              <div id="body-overlay" class="hidden">
                <div>
                  <div id="body-overlay-label"></div>
                  <button id="reveal-btn">Show body anyway</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

  </div>

  <script src="/static/app.js"></script>
</body>
</html>
```

- [ ] **Step 2: Restart the server and verify the shell loads**

```bash
uvicorn web.server:app --reload --port 8000
```

Open `http://localhost:8000` — should show the dark split-pane shell with "Select an email to analyze" on the right, "Loading…" on the left.

- [ ] **Step 3: Commit**

```bash
git add web/static/index.html
git commit -m "feat: add HTML shell with split pane layout and CSS"
```

---

## Task 5: Frontend JavaScript — Inbox, SSE Timeline, Verdict, Body

**Files:**
- Create: `web/static/app.js`

All interactivity lives here. No frameworks — plain DOM APIs and `EventSource`.

- [ ] **Step 1: Create web/static/app.js**

```javascript
// ── helpers ──────────────────────────────────────────────────────────────────

const SKILL_CLASS = {
  rspamd_scan_email:           'skill-rspamd',
  email_header_auth_check:     'skill-header',
  urgency_check:               'skill-urgency',
  url_reputation_check:        'skill-url',
  error_pattern_memory_check:  'skill-memory',
};

const SKILL_DONE_DOT = {
  rspamd_scan_email:           'done-purple',
  email_header_auth_check:     'done-green',
  urgency_check:               'done-amber',
  url_reputation_check:        'done-red',
  error_pattern_memory_check:  'done-slate',
};

const VERDICT_DISPLAY = {
  benign:               { label: '✓ BENIGN',   cls: 'benign' },
  suspicious:           { label: '⚠ SUSPICIOUS', cls: 'suspicious' },
  phishing_or_spoofing: { label: '⚠ PHISHING',  cls: 'phishing_or_spoofing' },
  error:                { label: '✕ ERROR',     cls: 'error' },
};

function verdictBadgeHtml(verdict) {
  if (!verdict) return '<span class="badge badge-none">—</span>';
  const map = {
    benign:               'badge badge-benign',
    suspicious:           'badge badge-suspicious',
    phishing_or_spoofing: 'badge badge-phishing',
    error:                'badge badge-error',
  };
  const labels = { benign: 'BENIGN', suspicious: 'SUSPICIOUS', phishing_or_spoofing: 'PHISHING', error: 'ERROR' };
  const cls = map[verdict] || 'badge badge-none';
  const text = labels[verdict] || verdict.toUpperCase();
  return `<span class="${cls}">${text}</span>`;
}

// ── state ────────────────────────────────────────────────────────────────────

let activeUid = null;
let activeEventSource = null;
const skillNodes = {};   // uid → { skillName → {dotEl, cardEl} }

// ── inbox ────────────────────────────────────────────────────────────────────

async function loadEmails() {
  const resp = await fetch('/api/emails');
  const emails = await resp.json();

  const list = document.getElementById('inbox-list');
  const header = document.getElementById('inbox-header');
  header.textContent = `INBOX · ${emails.length} messages`;

  if (emails.length === 0) {
    list.innerHTML = '<div style="padding:16px;color:#334155;font-size:11px;">No emails found</div>';
    return;
  }

  list.innerHTML = emails.map(e => `
    <div class="email-row" data-uid="${e.uid}" onclick="selectEmail(${e.uid}, ${JSON.stringify(e).replace(/"/g, '&quot;')})">
      <div class="row-top">
        <span class="subject ${e.analyzed ? '' : 'unread'}">${escHtml(e.subject)}</span>
        ${verdictBadgeHtml(e.final_verdict)}
      </div>
      <div class="sender">${escHtml(e.from_address)}</div>
    </div>
  `).join('');

  updateStatus();
}

function escHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function updateStatus() {
  const resp = await fetch('/api/status');
  const data = await resp.json();
  const dot = document.getElementById('status-dot');
  const label = document.getElementById('account-label');
  dot.className = data.monitor_running ? 'connected' : '';
  label.textContent = data.monitor_running ? 'monitor running' : 'monitor stopped';
}

// ── email selection ──────────────────────────────────────────────────────────

function selectEmail(uid, emailData) {
  if (activeEventSource) {
    activeEventSource.close();
    activeEventSource = null;
  }
  activeUid = uid;

  // Highlight selected row
  document.querySelectorAll('.email-row').forEach(r => r.classList.remove('selected'));
  const row = document.querySelector(`.email-row[data-uid="${uid}"]`);
  if (row) row.classList.add('selected');

  // Show analysis panel
  document.getElementById('analysis-empty').style.display = 'none';
  const content = document.getElementById('analysis-content');
  content.classList.add('visible');

  // Set header
  document.getElementById('email-subject').textContent = emailData.subject || '(no subject)';
  document.getElementById('email-meta').textContent =
    `From: ${emailData.from_address || ''}`;

  // Reset panels
  resetAnalysisPanel();

  // Start streaming
  streamAnalysis(uid);
}

function resetAnalysisPanel() {
  // Clear timeline (keep label)
  const timeline = document.getElementById('timeline');
  timeline.innerHTML = '<div class="timeline-section-label">ANALYSIS</div>';
  skillNodes[activeUid] = {};

  // Hide/reset reasoning
  const rb = document.getElementById('reasoning-box');
  rb.textContent = '';
  rb.classList.remove('visible');

  // Hide verdict
  const vb = document.getElementById('verdict-bar');
  vb.className = '';
  vb.style.display = 'none';

  // Hide body
  const bs = document.getElementById('body-section');
  bs.classList.remove('visible');
  document.getElementById('body-content').textContent = '';
  document.getElementById('body-content').classList.remove('blurred');
  document.getElementById('body-overlay').classList.add('hidden');
}

// ── SSE streaming ────────────────────────────────────────────────────────────

function streamAnalysis(uid) {
  const es = new EventSource(`/api/stream/${uid}`);
  activeEventSource = es;

  es.onmessage = (event) => {
    const data = JSON.parse(event.data);
    handleEvent(uid, data);
    if (data.type === 'agent_complete' || data.type === 'done' || data.type === 'error') {
      es.close();
      activeEventSource = null;
      if (data.type === 'agent_complete') {
        loadEmailBody(uid, data.verdict);
        refreshInboxBadge(uid, data.verdict);
      }
    }
  };

  es.onerror = () => {
    es.close();
    activeEventSource = null;
  };
}

function handleEvent(uid, data) {
  if (uid !== activeUid) return;

  switch (data.type) {
    case 'skill_start':
      addSkillNode(uid, data.skill, 'running');
      break;
    case 'skill_complete':
      completeSkillNode(uid, data.skill, data.ok, data.summary || '');
      break;
    case 'reasoning_text':
      showReasoning(data.text);
      break;
    case 'agent_complete':
      if (data.cached) {
        showCachedResult(data);
      } else {
        showVerdict(data.verdict, data.elapsed_ms);
      }
      break;
    case 'error':
      showError(data.message);
      break;
  }
}

// ── timeline nodes ───────────────────────────────────────────────────────────

function addSkillNode(uid, skillName, state) {
  const nodes = skillNodes[uid] || (skillNodes[uid] = {});
  if (nodes[skillName]) return;  // already added

  const timeline = document.getElementById('timeline');
  const skillCls = SKILL_CLASS[skillName] || 'skill-memory';

  const wrapper = document.createElement('div');
  wrapper.style.display = 'flex';
  wrapper.style.flexDirection = 'column';

  const nodeEl = document.createElement('div');
  nodeEl.className = 'skill-node';

  const connEl = document.createElement('div');
  connEl.className = 'skill-node-connector';

  const dotEl = document.createElement('div');
  dotEl.className = `skill-dot ${state}`;

  const lineEl = document.createElement('div');
  lineEl.className = 'connector-line';

  connEl.appendChild(dotEl);
  connEl.appendChild(lineEl);

  const cardEl = document.createElement('div');
  cardEl.className = `skill-card ${skillCls} ${state}`;
  cardEl.innerHTML = `<div class="skill-name">${escHtml(skillName)}</div><div class="skill-result"></div>`;

  nodeEl.appendChild(connEl);
  nodeEl.appendChild(cardEl);
  wrapper.appendChild(nodeEl);
  timeline.appendChild(wrapper);

  nodes[skillName] = { dotEl, cardEl };
}

function completeSkillNode(uid, skillName, ok, summary) {
  const nodes = skillNodes[uid] || {};
  if (!nodes[skillName]) {
    addSkillNode(uid, skillName, 'running');
  }
  const { dotEl, cardEl } = nodes[skillName];
  const skillCls = SKILL_CLASS[skillName] || 'skill-memory';
  const dotCls = ok ? (SKILL_DONE_DOT[skillName] || 'done-slate') : 'done-error';

  dotEl.className = `skill-dot ${dotCls}`;
  dotEl.textContent = ok ? '✓' : '✕';

  cardEl.className = `skill-card ${skillCls} done`;
  cardEl.querySelector('.skill-result').textContent = summary;
}

// ── reasoning ────────────────────────────────────────────────────────────────

function showReasoning(text) {
  const rb = document.getElementById('reasoning-box');
  rb.classList.add('visible');
  rb.textContent = text;
}

// ── verdict ───────────────────────────────────────────────────────────────────

function showVerdict(verdict, elapsedMs) {
  const vb = document.getElementById('verdict-bar');
  const info = VERDICT_DISPLAY[verdict] || { label: verdict.toUpperCase(), cls: 'error' };
  vb.className = `visible ${info.cls}`;
  vb.style.display = 'flex';
  document.getElementById('verdict-label').textContent = info.label;
  document.getElementById('verdict-meta').textContent =
    elapsedMs ? `${(elapsedMs / 1000).toFixed(1)}s` : '';
}

function showCachedResult(data) {
  const rb = document.getElementById('reasoning-box');
  if (data.summary) {
    rb.textContent = data.summary;
    rb.classList.add('visible');
  }
  showVerdict(data.verdict, 0);
}

function showError(message) {
  const rb = document.getElementById('reasoning-box');
  rb.textContent = `Error: ${message}`;
  rb.classList.add('visible');
  rb.style.borderLeftColor = '#dc2626';
}

// ── email body ────────────────────────────────────────────────────────────────

async function loadEmailBody(uid, verdict) {
  const resp = await fetch(`/api/email/${uid}/raw`);
  if (!resp.ok) return;
  const data = await resp.json();

  const bodySection = document.getElementById('body-section');
  const bodyContent = document.getElementById('body-content');
  const overlay = document.getElementById('body-overlay');
  const overlayLabel = document.getElementById('body-overlay-label');

  bodyContent.textContent = data.body || '(empty body)';
  bodySection.classList.add('visible');

  const blur = verdict === 'suspicious' || verdict === 'phishing_or_spoofing';
  if (blur) {
    bodyContent.classList.add('blurred');
    overlay.classList.remove('hidden');
    overlayLabel.textContent =
      verdict === 'phishing_or_spoofing'
        ? '⚠ Blurred — classified as phishing'
        : '⚠ Blurred — classified as suspicious';
  }
}

document.getElementById('reveal-btn').addEventListener('click', () => {
  document.getElementById('body-content').classList.remove('blurred');
  document.getElementById('body-overlay').classList.add('hidden');
});

// ── inbox badge refresh ───────────────────────────────────────────────────────

function refreshInboxBadge(uid, verdict) {
  const row = document.querySelector(`.email-row[data-uid="${uid}"]`);
  if (!row) return;
  const badgeEl = row.querySelector('.badge');
  if (badgeEl) badgeEl.outerHTML = verdictBadgeHtml(verdict);
  row.querySelector('.subject')?.classList.remove('unread');
}

// ── init ─────────────────────────────────────────────────────────────────────

loadEmails();
```

- [ ] **Step 2: Start the server and test the full flow manually**

```bash
uvicorn web.server:app --reload --port 8000
```

1. Open `http://localhost:8000`
2. Verify inbox list loads with emails from `runtime/imap_monitor/messages/`
3. Click an email — verify analysis panel shows, timeline feed appears, agent runs
4. Verify skill nodes appear as `running` then flip to `done` with summaries
5. Verify reasoning text appears
6. Verify verdict bar appears with correct color
7. Verify email body loads, blurred for phishing/suspicious
8. Click "Show body anyway" — verify blur removed
9. Click the same email again — verify it loads instantly from cache (no skill nodes animate)

- [ ] **Step 3: Commit**

```bash
git add web/static/app.js
git commit -m "feat: add app.js with inbox list, SSE timeline, verdict bar, and body reveal"
```

---

## Task 6: Wire Up and Final Smoke Test

- [ ] **Step 1: Run full test suite**

```bash
pytest tests/ -v
```

Expected: all unit tests pass.

- [ ] **Step 2: End-to-end smoke test**

Start the server:
```bash
uvicorn web.server:app --port 8000
```

Checklist:
- [ ] `GET /api/status` returns `{ monitor_running, bound_mailboxes, result_count }`
- [ ] `GET /api/emails` returns list including unanalyzed emails from disk
- [ ] Clicking an unanalyzed email triggers the SSE stream and shows live skill nodes
- [ ] Each skill node transitions: dim → pulsing blue → colored ✓
- [ ] Reasoning text box appears after skills complete
- [ ] Verdict bar shows correct color and label
- [ ] `phishing_or_spoofing` and `suspicious` emails show blurred body
- [ ] `benign` and `error` emails show body directly
- [ ] Re-clicking an already-analyzed email loads instantly with no skill animation
- [ ] Status dot turns green when monitor is running

- [ ] **Step 3: Final commit**

```bash
git add .
git commit -m "feat: Intelligent Mail web UI — FastAPI + SSE + Vanilla JS complete"
```

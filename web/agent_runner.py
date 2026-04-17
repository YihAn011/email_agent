from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import AsyncGenerator

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
        score = data.get("urgency_score")
        score_str = f"{score:.2f}" if isinstance(score, float) else str(score or "?")
        return f"score {score_str} · {data.get('urgency_label', '?')}"
    if name == "url_reputation_check":
        score = data.get("phishing_score")
        score_str = f"{score:.2f}" if isinstance(score, float) else str(score or "?")
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

    messages = [
        SystemMessage(content="You are an email security analyst."),
        HumanMessage(content=prompt),
    ]
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
        pass

    yield {
        "type": "agent_complete",
        "verdict": final_verdict,
        "summary": final_text,
        "elapsed_ms": elapsed_ms,
        "cached": False,
    }

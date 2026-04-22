from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Callable

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

from examples.model_factory import build_chat_model

from .capability_registry import get_capability
from .prompts import build_system_prompt
from .request_router import EmailAgentRouter

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MCP_SERVER_PATH = PROJECT_ROOT / "mcp_server.py"


def build_mcp_env(base_url: str) -> dict[str, str]:
    env = dict(os.environ)
    env.pop("PS1", None)
    env["RSPAMD_BASE_URL"] = base_url
    return env


def render_content(content: object) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
            else:
                parts.append(str(item))
        return "\n".join(part for part in parts if part)
    return str(content)


def parse_tool_payload(message: ToolMessage) -> object:
    raw = render_content(message.content).strip()
    if not raw:
        return raw
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def summarize_tool_message(message: ToolMessage) -> str:
    payload = parse_tool_payload(message)
    if not isinstance(payload, dict):
        return f"- `{message.name}`: {str(payload)[:240]}"
    if payload.get("ok") is False:
        error = payload.get("error") or {}
        return f"- `{message.name}` failed: {error.get('message') or 'tool failed'}"

    data = payload.get("data")
    if message.name == "rspamd_scan_email" and isinstance(data, dict):
        return (
            f"- `rspamd_scan_email`: risk={data.get('risk_level')} "
            f"score={data.get('score')} action={data.get('action')} "
            f"summary={data.get('summary')}"
        )
    if message.name == "email_header_auth_check" and isinstance(data, dict):
        return f"- `email_header_auth_check`: risk={data.get('risk_level')} summary={data.get('summary')}"
    if message.name == "scan_recent_imap_emails" and isinstance(data, dict):
        items = data.get("emails") or []
        previews = [
            f"{item.get('subject', '(no subject)')} -> {item.get('final_verdict', 'unknown')}"
            for item in items[:3]
            if isinstance(item, dict)
        ]
        suffix = f" examples: {', '.join(previews)}" if previews else ""
        return f"- `scan_recent_imap_emails`: scanned={data.get('scanned_count', 0)}{suffix}"
    if message.name == "list_bound_imap_mailboxes" and isinstance(data, dict):
        items = data.get("mailboxes")
        if isinstance(items, list):
            return f"- `list_bound_imap_mailboxes`: found {len(items)} stored mailbox bindings"
    if message.name == "list_recent_email_results" and isinstance(data, dict):
        items = data.get("results")
        if isinstance(items, list):
            return f"- `list_recent_email_results`: returned {len(items)} stored results"
    if message.name == "record_email_correction" and isinstance(data, dict):
        return f"- `record_email_correction`: stored a correction pattern for future similar emails"
    if message.name == "list_decision_memory" and isinstance(data, dict):
        items = data.get("entries")
        if isinstance(items, list):
            return f"- `list_decision_memory`: returned {len(items)} correction patterns"
    if message.name == "error_pattern_memory_check" and isinstance(data, dict):
        return f"- `error_pattern_memory_check`: matched={data.get('matched')} suggested={data.get('suggested_verdict')}"
    if message.name == "list_error_patterns" and isinstance(data, dict):
        items = data.get("entries")
        if isinstance(items, list):
            return f"- `list_error_patterns`: returned {len(items)} stored error patterns"
    if message.name == "imap_monitor_status" and isinstance(data, dict):
        return (
            f"- `imap_monitor_status`: running={data.get('running')} "
            f"bound_mailboxes={data.get('bound_mailboxes')} stored_results={data.get('stored_results')}"
        )
    if isinstance(data, dict):
        keys = ", ".join(sorted(data.keys())[:8])
        return f"- `{message.name}`: completed successfully (keys: {keys})"
    return f"- `{message.name}`: completed successfully"


def summarize_tool_messages(messages: list[BaseMessage], start_idx: int) -> str:
    tool_messages = [message for message in messages[start_idx:] if isinstance(message, ToolMessage)]
    return "\n".join(summarize_tool_message(message) for message in tool_messages)


def expand_invoked_tool_names(name: str) -> list[str]:
    capability = get_capability(name)
    if capability is None or not capability.nested_tools:
        return [name]
    return [name, *capability.nested_tools]


def summarize_invoked_tools(messages: list[BaseMessage], start_idx: int) -> str:
    tool_messages = [message for message in messages[start_idx:] if isinstance(message, ToolMessage)]
    counts: dict[str, int] = {}
    ordered: list[str] = []
    for message in tool_messages:
        for expanded_name in expand_invoked_tool_names(message.name or "unknown_tool"):
            if expanded_name not in counts:
                ordered.append(expanded_name)
                counts[expanded_name] = 0
            counts[expanded_name] += 1
    parts = [f"`{name}` x{counts[name]}" if counts[name] > 1 else f"`{name}`" for name in ordered]
    return ", ".join(parts)


def invoked_tool_names(messages: list[BaseMessage], start_idx: int) -> set[str]:
    return {
        message.name
        for message in messages[start_idx:]
        if isinstance(message, ToolMessage) and message.name
    }


def extract_final_output(result: dict[str, Any]) -> str:
    messages = result.get("messages", [])
    for message in reversed(messages):
        if isinstance(message, AIMessage):
            return render_content(message.content)
    return json.dumps(result, indent=2, ensure_ascii=False, default=str)


def latest_ai_message(messages: list[BaseMessage]) -> str:
    for message in reversed(messages):
        if isinstance(message, AIMessage):
            return render_content(message.content)
    return "No AI response was produced."


def latest_ai_has_tool_calls(messages: list[BaseMessage]) -> bool:
    for message in reversed(messages):
        if isinstance(message, AIMessage):
            return bool(getattr(message, "tool_calls", None))
    return False


def needs_email_verdict_workflow(prompt: str) -> bool:
    lowered = prompt.lower()
    verdict_terms = (
        "required workflow",
        "raw rfc822 email",
        "raw email headers",
        "analyze this email",
        "check this email",
        "html email",
        "email template",
        "phishing",
        "spam",
        "verdict",
        "referenced email",
        "<html",
        "<table",
        "unsubscribe",
        "tracking pixel",
        "coupon",
        "offer",
        "分析邮件",
        "检查邮件",
        "钓鱼",
        "垃圾邮件",
    )
    return any(term in lowered for term in verdict_terms)


def needs_empty_response_recovery(
    messages: list[BaseMessage],
    start_idx: int,
    prompt: str,
) -> bool:
    if not needs_email_verdict_workflow(prompt):
        return False
    if latest_ai_message(messages).strip():
        return False
    if latest_ai_has_tool_calls(messages):
        return False
    tools = invoked_tool_names(messages, start_idx)
    if "rspamd_scan_email" in tools or "email_header_auth_check" in tools or "scan_recent_imap_emails" in tools:
        return False
    return "list_error_patterns" in tools


def needs_missing_tool_recovery(
    messages: list[BaseMessage],
    start_idx: int,
    prompt: str,
) -> bool:
    if not needs_email_verdict_workflow(prompt):
        return False
    tools = invoked_tool_names(messages, start_idx)
    security_tools = {
        "list_error_patterns",
        "rspamd_scan_email",
        "email_header_auth_check",
        "url_reputation_check",
        "urgency_check",
        "error_pattern_memory_check",
        "scan_recent_imap_emails",
    }
    if tools & security_tools:
        return False
    body = latest_ai_message(messages).strip()
    if not body:
        return False
    return not body.lower().startswith("email:")


def build_missing_tool_recovery_prompt() -> str:
    return (
        "The previous response summarized the email content instead of performing an email security verdict. "
        "Redo the same user request now as an email security check. First call `list_error_patterns`, then use "
        "`rspamd_scan_email` for the raw email or HTML email content, plus `url_reputation_check` and "
        "`urgency_check` when possible. Use `email_header_auth_check` only if full raw headers are available as a string. "
        "Before the final answer, call `error_pattern_memory_check`. Do not summarize the HTML template structure. Give only the short template: "
        "Email, Type, Verdict, Evidence. The Verdict must be exactly one of Normal, Spam, Phishing."
    )


def build_empty_response_recovery_prompt() -> str:
    return (
        "The previous assistant turn ended with empty content after only the preliminary memory tool. "
        "Continue the same user request now. Complete the mandatory email verdict workflow: run the "
        "normal security tool that fits the provided evidence, such as `rspamd_scan_email` for raw "
        "email content or `email_header_auth_check` for headers, then call "
        "`error_pattern_memory_check`, then give a concise final verdict. If a tool is unavailable, "
        "say so and still provide a plain-language assessment from the visible email content."
    )


def needs_broader_email_checks(
    messages: list[BaseMessage],
    start_idx: int,
    prompt: str,
) -> bool:
    if not needs_email_verdict_workflow(prompt):
        return False
    lowered = prompt.lower()
    if "raw rfc822 email" not in lowered and "referenced email" not in lowered:
        return False
    tools = invoked_tool_names(messages, start_idx)
    if "rspamd_scan_email" not in tools:
        return False
    expected = {
        "url_reputation_check",
        "urgency_check",
        "error_pattern_memory_check",
    }
    return bool(expected - tools)


def build_broader_email_checks_prompt(messages: list[BaseMessage], start_idx: int) -> str:
    tools = invoked_tool_names(messages, start_idx)
    missing = [
        name
        for name in (
            "url_reputation_check",
            "urgency_check",
            "error_pattern_memory_check",
        )
        if name not in tools
    ]
    return (
        "Continue the same email analysis before giving the final verdict. "
        f"The current tool evidence is incomplete; run these missing checks if possible: {', '.join(missing)}. "
        "Do not classify the email as Spam or Phishing from Rspamd score alone. "
        "Let Rspamd decide the branch: phishing/spoof/url cases need URL and sender corroboration; spam/reputation/BAYES cases need spam-campaign corroboration; urgency is only supporting evidence. "
        "Then answer briefly with the exact template: Email, Type, Verdict, Evidence. "
        "The Verdict must be exactly one of Normal, Spam, Phishing."
    )


def is_quota_error(exc: Exception) -> bool:
    text = str(exc)
    return "RESOURCE_EXHAUSTED" in text or "429" in text or "quota" in text.lower()


def describe_progress_message(message: BaseMessage) -> list[str]:
    if isinstance(message, HumanMessage):
        return []

    if isinstance(message, AIMessage):
        tool_calls = getattr(message, "tool_calls", None) or []
        if tool_calls:
            lines: list[str] = []
            for call in tool_calls:
                if isinstance(call, dict) and call.get("name"):
                    lines.append(progress_label_for_tool(str(call["name"]), phase="start"))
            return lines or ["Thinking..."]
        content = render_content(message.content).strip()
        if content:
            return ["Preparing the final answer"]
        return ["Thinking..."]

    if isinstance(message, ToolMessage):
        payload = parse_tool_payload(message)
        if isinstance(payload, dict) and payload.get("ok") is False:
            error = payload.get("error") or {}
            return [f"{progress_label_for_tool(message.name or 'tool', phase='error')}: {error.get('message') or 'tool failed'}"]
        if isinstance(payload, dict):
            data = payload.get("data")
            if message.name == "rspamd_scan_email" and isinstance(data, dict):
                return [
                    f"{progress_label_for_tool(message.name, phase='done')}: "
                    f"risk={data.get('risk_level')} score={data.get('score')}"
                ]
            if message.name == "email_header_auth_check" and isinstance(data, dict):
                return [f"{progress_label_for_tool(message.name, phase='done')}: risk={data.get('risk_level')}"]
            if message.name == "scan_recent_imap_emails" and isinstance(data, dict):
                return [
                    f"{progress_label_for_tool(message.name, phase='done')}: "
                    f"scanned {data.get('scanned_count', 0)} emails"
                ]
            if message.name == "list_bound_imap_mailboxes" and isinstance(data, dict):
                items = data.get("mailboxes") or []
                return [
                    f"{progress_label_for_tool(message.name, phase='done')}: "
                    f"found {len(items)} saved mailbox bindings"
                ]
            if message.name == "imap_monitor_status" and isinstance(data, dict):
                return [
                    f"{progress_label_for_tool(message.name, phase='done')}: "
                    f"running={data.get('running')} bound={data.get('bound_mailboxes')}"
                ]
            if message.name == "list_recent_email_results" and isinstance(data, dict):
                items = data.get("results") or []
                return [
                    f"{progress_label_for_tool(message.name, phase='done')}: "
                    f"loaded {len(items)} stored email results"
                ]
            if message.name == "record_email_correction" and isinstance(data, dict):
                return [f"{progress_label_for_tool(message.name, phase='done')}: future similar emails can use it"]
            if message.name == "list_decision_memory" and isinstance(data, dict):
                items = data.get("entries") or []
                return [
                    f"{progress_label_for_tool(message.name, phase='done')}: "
                    f"loaded {len(items)} correction patterns"
                ]
            if message.name == "error_pattern_memory_check" and isinstance(data, dict):
                return [
                    f"{progress_label_for_tool(message.name, phase='done')}: "
                    f"matched={data.get('matched')} suggested={data.get('suggested_verdict')}"
                ]
            if message.name == "list_error_patterns" and isinstance(data, dict):
                items = data.get("entries") or []
                return [
                    f"{progress_label_for_tool(message.name, phase='done')}: "
                    f"loaded {len(items)} error patterns"
                ]
        return [progress_label_for_tool(message.name or "tool", phase="done")]

    return []


def progress_label_for_tool(tool_name: str, *, phase: str) -> str:
    phase_text = {
        "start": {
            "list_bound_imap_mailboxes": "Checking saved mailbox bindings",
            "bind_imap_mailbox": "Saving mailbox credentials",
            "setup_imap_monitor": "Setting up mailbox monitoring",
            "start_imap_monitor": "Starting background mailbox monitoring",
            "stop_imap_monitor": "Stopping background mailbox monitoring",
            "imap_monitor_status": "Checking monitor status",
            "poll_imap_mailboxes_once": "Checking for new mailbox messages",
            "list_recent_email_results": "Loading recent mailbox scan results",
            "record_email_correction": "Saving a correction pattern",
            "list_decision_memory": "Loading stored correction patterns",
            "error_pattern_memory_check": "Checking known error patterns",
            "list_error_patterns": "Loading stored error patterns",
            "scan_recent_imap_emails": "Scanning recent mailbox emails",
            "rspamd_scan_email": "Running email security scan",
            "email_header_auth_check": "Checking email authentication headers",
            "urgency_check": "Scoring urgency and pressure signals",
            "url_reputation_check": "Checking links and URL reputation",
        },
        "done": {
            "list_bound_imap_mailboxes": "Saved mailbox check complete",
            "bind_imap_mailbox": "Mailbox binding complete",
            "setup_imap_monitor": "Mailbox monitoring setup complete",
            "start_imap_monitor": "Background monitoring started",
            "stop_imap_monitor": "Background monitoring stopped",
            "imap_monitor_status": "Monitor status loaded",
            "poll_imap_mailboxes_once": "Mailbox poll complete",
            "list_recent_email_results": "Recent results loaded",
            "record_email_correction": "Correction pattern saved",
            "list_decision_memory": "Stored correction patterns loaded",
            "error_pattern_memory_check": "Error pattern check complete",
            "list_error_patterns": "Stored error patterns loaded",
            "scan_recent_imap_emails": "Recent email scan complete",
            "rspamd_scan_email": "Email security scan complete",
            "email_header_auth_check": "Authentication header check complete",
            "urgency_check": "Urgency scoring complete",
            "url_reputation_check": "URL reputation check complete",
        },
        "error": {
            "list_bound_imap_mailboxes": "Saved mailbox check failed",
            "bind_imap_mailbox": "Mailbox binding failed",
            "setup_imap_monitor": "Mailbox monitoring setup failed",
            "start_imap_monitor": "Starting background monitoring failed",
            "stop_imap_monitor": "Stopping background monitoring failed",
            "imap_monitor_status": "Monitor status check failed",
            "poll_imap_mailboxes_once": "Mailbox poll failed",
            "list_recent_email_results": "Loading recent results failed",
            "record_email_correction": "Saving the correction pattern failed",
            "list_decision_memory": "Loading stored correction patterns failed",
            "error_pattern_memory_check": "Checking known error patterns failed",
            "list_error_patterns": "Loading stored error patterns failed",
            "scan_recent_imap_emails": "Recent email scan failed",
            "rspamd_scan_email": "Email security scan failed",
            "email_header_auth_check": "Authentication header check failed",
            "urgency_check": "Urgency scoring failed",
            "url_reputation_check": "URL reputation check failed",
        },
    }
    return phase_text.get(phase, {}).get(tool_name, f"{tool_name} {phase}")


class _BaseRuntime:
    def __init__(
        self,
        *,
        provider: str,
        model_name: str,
        rspamd_base_url: str,
        ollama_base_url: str,
        persona: str,
        show_messages: bool = False,
    ) -> None:
        self.provider = provider
        self.model_name = model_name
        self.rspamd_base_url = rspamd_base_url
        self.ollama_base_url = ollama_base_url
        self.persona = persona
        self.show_messages = show_messages
        self.router = EmailAgentRouter()
        self.agent = None
        self.system_prompt = build_system_prompt(persona)

    async def setup(self) -> None:
        model = build_chat_model(
            provider=self.provider,
            model_name=self.model_name,
            temperature=0,
            ollama_base_url=self.ollama_base_url,
        )
        server_config = {
            "email-security": {
                "transport": "stdio",
                "command": sys.executable,
                "args": [str(MCP_SERVER_PATH)],
                "cwd": str(PROJECT_ROOT),
                "env": build_mcp_env(self.rspamd_base_url),
            }
        }
        client = MultiServerMCPClient(server_config)
        tools = await client.get_tools()
        self.agent = create_react_agent(model=model, tools=tools)

    def routed_hint(self, prompt: str, limit: int = 3) -> str:
        matches = self.router.route(prompt, limit=limit)
        names: list[str] = []
        lowered = prompt.lower()
        raw_email_request = any(
            token in lowered
            for token in (
                "raw rfc822",
                "begin raw rfc822",
                "referenced email",
                "<html",
                "<table",
                "unsubscribe",
                "coupon",
                "offer",
            )
        )
        if raw_email_request:
            names.extend(
                [
                    "list_error_patterns",
                    "rspamd_scan_email",
                    "url_reputation_check",
                    "urgency_check",
                    "error_pattern_memory_check",
                ]
            )
        if any(
            token in lowered
            for token in (
                "email",
                "mailbox",
                "headers",
                "phishing",
                "spam",
                "verdict",
                "<html",
                "<table",
                "unsubscribe",
                "coupon",
                "offer",
            )
        ):
            for name in ("list_error_patterns", "error_pattern_memory_check"):
                if name not in names:
                    names.append(name)
        for item in matches:
            if item.name not in names:
                names.append(item.name)
        if not names:
            return ""
        rendered = ", ".join(names[: max(limit + 2, len(names))])
        return f"Routing hints: {rendered}"


class EmailAgentRuntime(_BaseRuntime):
    def __init__(
        self,
        *,
        provider: str,
        model_name: str,
        rspamd_base_url: str,
        ollama_base_url: str,
        show_messages: bool = False,
    ) -> None:
        super().__init__(
            provider=provider,
            model_name=model_name,
            rspamd_base_url=rspamd_base_url,
            ollama_base_url=ollama_base_url,
            persona="an email security chatbot named Email Guardian",
            show_messages=show_messages,
        )
        self.history: list[BaseMessage] = [SystemMessage(content=self.system_prompt)]

    def reset(self) -> None:
        self.history = [SystemMessage(content=self.system_prompt)]

    async def ask(
        self,
        prompt: str,
        *,
        progress_callback: Callable[[str], None] | None = None,
    ) -> tuple[list[BaseMessage], int]:
        if self.agent is None:
            raise RuntimeError("Agent has not been initialized")
        start_idx = len(self.history)
        hint = self.routed_hint(prompt)
        content = f"{hint}\n\n{prompt}" if hint else prompt
        latest_messages = [*self.history, HumanMessage(content=content)]
        emitted_count = len(self.history)
        if progress_callback:
            if hint:
                progress_callback(f"Routing: {hint.removeprefix('Routing hints:').strip()}")
            progress_callback("Thinking...")
        try:
            async for state in self.agent.astream({"messages": latest_messages}, stream_mode="values"):
                if isinstance(state, dict) and isinstance(state.get("messages"), list):
                    latest_messages = state["messages"]
                    if progress_callback and len(latest_messages) > emitted_count:
                        for message in latest_messages[emitted_count:]:
                            for line in describe_progress_message(message):
                                progress_callback(line)
                        emitted_count = len(latest_messages)
            if needs_missing_tool_recovery(latest_messages, start_idx, content):
                recovery_message = HumanMessage(content=build_missing_tool_recovery_prompt())
                latest_messages = [*latest_messages, recovery_message]
                if progress_callback:
                    progress_callback("Running email security tools")
                async for state in self.agent.astream({"messages": latest_messages}, stream_mode="values"):
                    if isinstance(state, dict) and isinstance(state.get("messages"), list):
                        latest_messages = state["messages"]
                        if progress_callback and len(latest_messages) > emitted_count:
                            for message in latest_messages[emitted_count:]:
                                for line in describe_progress_message(message):
                                    progress_callback(line)
                            emitted_count = len(latest_messages)
            if needs_empty_response_recovery(latest_messages, start_idx, content):
                recovery_message = HumanMessage(content=build_empty_response_recovery_prompt())
                latest_messages = [*latest_messages, recovery_message]
                if progress_callback:
                    progress_callback("Continuing incomplete email analysis")
                async for state in self.agent.astream({"messages": latest_messages}, stream_mode="values"):
                    if isinstance(state, dict) and isinstance(state.get("messages"), list):
                        latest_messages = state["messages"]
                        if progress_callback and len(latest_messages) > emitted_count:
                            for message in latest_messages[emitted_count:]:
                                for line in describe_progress_message(message):
                                    progress_callback(line)
                            emitted_count = len(latest_messages)
            if needs_broader_email_checks(latest_messages, start_idx, content):
                recovery_message = HumanMessage(content=build_broader_email_checks_prompt(latest_messages, start_idx))
                latest_messages = [*latest_messages, recovery_message]
                if progress_callback:
                    progress_callback("Running additional safety checks")
                async for state in self.agent.astream({"messages": latest_messages}, stream_mode="values"):
                    if isinstance(state, dict) and isinstance(state.get("messages"), list):
                        latest_messages = state["messages"]
                        if progress_callback and len(latest_messages) > emitted_count:
                            for message in latest_messages[emitted_count:]:
                                for line in describe_progress_message(message):
                                    progress_callback(line)
                            emitted_count = len(latest_messages)
        except Exception:
            self.history = latest_messages
            raise
        self.history = latest_messages
        return latest_messages, start_idx


class SingleTurnAgentRuntime(_BaseRuntime):
    def __init__(
        self,
        *,
        provider: str,
        model_name: str,
        rspamd_base_url: str,
        ollama_base_url: str,
    ) -> None:
        super().__init__(
            provider=provider,
            model_name=model_name,
            rspamd_base_url=rspamd_base_url,
            ollama_base_url=ollama_base_url,
            persona="an email security analyst",
        )

    async def invoke(self, prompt: str) -> dict[str, Any]:
        if self.agent is None:
            raise RuntimeError("Agent has not been initialized")
        hint = self.routed_hint(prompt)
        content = f"{hint}\n\n{prompt}" if hint else prompt
        return await self.agent.ainvoke(
            {"messages": [SystemMessage(content=self.system_prompt), HumanMessage(content=content)]}
        )

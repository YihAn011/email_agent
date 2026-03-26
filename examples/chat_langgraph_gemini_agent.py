from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MCP_SERVER_PATH = PROJECT_ROOT / "mcp_server.py"

DEFAULT_EMAIL = """Return-Path: <do-not-reply@jobs.amazon.com>
From: do-not-reply@jobs.amazon.com
To: xx2211@columbia.edu
Subject: Please share your feedback: Your recent interview experience at Amazon
Date: Mon, 09 Mar 2026 12:03:00 -0500
Message-ID: <example-msgid-20260309@amazonses.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Reminder: Share your feedback

Dear xx2211,

A quick reminder to share your feedback about your recent interview at Amazon.

This 5-minute survey will help improve our interview process. Your responses will have no impact on your interview outcome.

Get started

We appreciate your time and feedback.

The Amazon Recruiting Team

By clicking on the survey link, you are agreeing to the terms in the Amazon privacy policy.
Click here to unsubscribe from future survey invitations.
"""

SYSTEM_PROMPT = """You are an email security chatbot named Email Guardian.

You have access to MCP tools exposed by the local email security server.

Tool usage guidance:
- Use `rspamd_scan_email` when raw RFC822 email content is available and you need a scanner-backed verdict.
- Use `email_header_auth_check` when the user provides headers only or asks about SPF, DKIM, DMARC, ARC, routing, or sender-domain mismatches.
- If the evidence is incomplete, you may use both tools when helpful.
- Use `bind_imap_mailbox` when the user wants continuous mailbox monitoring over IMAP.
- Prefer `setup_imap_monitor` when the user provides enough IMAP credentials and wants one-step setup.
- After binding a mailbox, use `start_imap_monitor` to begin background polling.
- Use `poll_imap_mailboxes_once` for immediate testing after binding credentials.
- Use `imap_monitor_status` and `list_recent_email_results` to report monitoring progress and recent verdicts.
- Use `scan_recent_imap_emails` when the user asks about the latest or most recent emails in a bound mailbox, especially queries like "latest 2 emails", "recent 50 emails", or "are the newest emails spam?".

Response requirements:
- Start with a concise verdict and confidence.
- Separate tool evidence from your own inference.
- Mention the most important findings and recommended next step.
- When the user wants mailbox monitoring, behave like a helpful chatbot: explain what you are doing briefly, use the monitor tools, and confirm the current state in plain language.
- Prefer natural conversation. The slash commands are conveniences, not the only way to interact.
- If the user asks for judgment about recent mailbox emails, prefer scanning the requested latest emails on demand instead of only reading cached results.
"""

HELP_TEXT = """Commands:
  /help                    Show this help
  /reset                   Clear chat history and start fresh
  /sample                  Analyze the built-in sample email
  /email-file <path>       Load a raw RFC822 email file and analyze it
  /headers-file <path>     Load a headers-only text file and analyze it
  /paste-email             Paste a raw RFC822 email, end with a line containing only END
  /paste-headers           Paste raw headers, end with a line containing only END
  /trace on|off            Toggle tool/message trace output
  /quit                    Exit

Anything else is sent as a normal user chat message.
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the Email Guardian chatbot in the terminal."
    )
    parser.add_argument(
        "--model",
        default="gemini-2.5-flash",
        help="Gemini model name for ChatGoogleGenerativeAI.",
    )
    parser.add_argument(
        "--base-url",
        default=os.getenv("RSPAMD_BASE_URL", "http://127.0.0.1:11333"),
        help="Rspamd base URL passed through to the MCP server.",
    )
    parser.add_argument(
        "--show-messages",
        action="store_true",
        help="Print tool and message trace for each turn.",
    )
    return parser.parse_args()


def ensure_google_api_key() -> None:
    if os.getenv("GOOGLE_API_KEY"):
        return
    gemini_key = os.getenv("GEMINI_API_KEY")
    if gemini_key:
        os.environ["GOOGLE_API_KEY"] = gemini_key
        return
    raise RuntimeError(
        "Missing Google API credentials. Set GOOGLE_API_KEY or GEMINI_API_KEY before running the agent."
    )


def read_text_file(path_text: str) -> str:
    path = Path(path_text).expanduser()
    return path.read_text(encoding="utf-8")


def collect_multiline_input(kind: str) -> str:
    print(f"Paste {kind}. End with a line containing only END.")
    lines: list[str] = []
    while True:
        line = input()
        if line == "END":
            break
        lines.append(line)
    return "\n".join(lines)


def build_analysis_prompt(question: str, *, raw_email: str | None = None, raw_headers: str | None = None) -> str:
    sections = [question.strip()]
    if raw_email:
        sections.append("Use the available MCP tools to analyze the following raw RFC822 email:")
        sections.append(raw_email)
    elif raw_headers:
        sections.append("Use the available MCP tools to analyze the following raw email headers:")
        sections.append(raw_headers)
    return "\n\n".join(sections)


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
        text = str(payload)
        return f"- `{message.name}`: {text[:240]}"

    if payload.get("ok") is False:
        error = payload.get("error") or {}
        error_message = error.get("message") or "tool failed"
        return f"- `{message.name}` failed: {error_message}"

    data = payload.get("data")
    if message.name == "rspamd_scan_email" and isinstance(data, dict):
        return (
            f"- `rspamd_scan_email`: risk={data.get('risk_level')} "
            f"score={data.get('score')} action={data.get('action')} "
            f"summary={data.get('summary')}"
        )
    if message.name == "email_header_auth_check" and isinstance(data, dict):
        return (
            f"- `email_header_auth_check`: risk={data.get('risk_level')} "
            f"summary={data.get('summary')}"
        )
    if message.name == "scan_recent_imap_emails" and isinstance(data, dict):
        emails = data.get("emails") or []
        previews: list[str] = []
        for item in emails[:3]:
            if isinstance(item, dict):
                previews.append(
                    f"{item.get('subject', '(no subject)')} -> {item.get('final_verdict', 'unknown')}"
                )
        suffix = f" examples: {', '.join(previews)}" if previews else ""
        return (
            f"- `scan_recent_imap_emails`: scanned={data.get('scanned_count', 0)}"
            f"{suffix}"
        )
    if message.name == "list_recent_email_results" and isinstance(data, dict):
        items = data.get("data")
        if isinstance(items, list):
            return f"- `list_recent_email_results`: returned {len(items)} stored results"
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
    tool_messages = [
        message for message in messages[start_idx:] if isinstance(message, ToolMessage)
    ]
    if not tool_messages:
        return ""
    summaries = [summarize_tool_message(message) for message in tool_messages]
    return "\n".join(summaries)


def expand_invoked_tool_names(name: str) -> list[str]:
    nested_map = {
        "scan_recent_imap_emails": [
            "scan_recent_imap_emails",
            "rspamd_scan_email",
            "email_header_auth_check",
        ],
        "poll_imap_mailboxes_once": [
            "poll_imap_mailboxes_once",
            "rspamd_scan_email",
            "email_header_auth_check",
        ],
        "setup_imap_monitor": [
            "setup_imap_monitor",
            "bind_imap_mailbox",
            "poll_imap_mailboxes_once",
            "start_imap_monitor",
            "rspamd_scan_email",
            "email_header_auth_check",
        ],
    }
    return nested_map.get(name, [name])


def summarize_invoked_tools(messages: list[BaseMessage], start_idx: int) -> str:
    tool_messages = [
        message for message in messages[start_idx:] if isinstance(message, ToolMessage)
    ]
    if not tool_messages:
        return ""

    counts: dict[str, int] = {}
    ordered_names: list[str] = []
    for message in tool_messages:
        name = message.name or "unknown_tool"
        for expanded_name in expand_invoked_tool_names(name):
            if expanded_name not in counts:
                ordered_names.append(expanded_name)
                counts[expanded_name] = 0
            counts[expanded_name] += 1

    parts: list[str] = []
    for name in ordered_names:
        count = counts[name]
        parts.append(f"`{name}` x{count}" if count > 1 else f"`{name}`")
    return ", ".join(parts)


def is_quota_error(exc: Exception) -> bool:
    text = str(exc)
    return "RESOURCE_EXHAUSTED" in text or "429" in text or "quota" in text.lower()


def latest_ai_message(messages: list[BaseMessage]) -> str:
    for message in reversed(messages):
        if isinstance(message, AIMessage):
            return render_content(message.content)
    return "No AI response was produced."


def render_trace(messages: list[BaseMessage], start_idx: int) -> None:
    for message in messages[start_idx:]:
        if isinstance(message, ToolMessage):
            print(f"\n[Tool] {message.name}")
            print(render_content(message.content))
        elif isinstance(message, AIMessage):
            print("\n[AI]")
            print(render_content(message.content))


class InteractiveEmailAgent:
    def __init__(self, model_name: str, base_url: str, show_messages: bool) -> None:
        self.model_name = model_name
        self.base_url = base_url
        self.show_messages = show_messages
        self.agent = None
        self.history: list[BaseMessage] = [SystemMessage(content=SYSTEM_PROMPT)]

    async def setup(self) -> None:
        model = ChatGoogleGenerativeAI(model=self.model_name, temperature=0)
        mcp_env = dict(os.environ)
        mcp_env["RSPAMD_BASE_URL"] = self.base_url

        server_config = {
            "email-security": {
                "transport": "stdio",
                "command": sys.executable,
                "args": [str(MCP_SERVER_PATH)],
                "cwd": str(PROJECT_ROOT),
                "env": mcp_env,
            }
        }

        client = MultiServerMCPClient(server_config)
        tools = await client.get_tools()
        self.agent = create_react_agent(model=model, tools=tools)

    def reset(self) -> None:
        self.history = [SystemMessage(content=SYSTEM_PROMPT)]

    async def ask(self, prompt: str) -> None:
        if self.agent is None:
            raise RuntimeError("Agent has not been initialized")

        start_idx = len(self.history)
        latest_messages = [*self.history, HumanMessage(content=prompt)]

        try:
            async for state in self.agent.astream(
                {"messages": latest_messages},
                stream_mode="values",
            ):
                if isinstance(state, dict) and isinstance(state.get("messages"), list):
                    latest_messages = state["messages"]
        except Exception as exc:
            self.history = latest_messages
            print()
            if is_quota_error(exc):
                print("模型额度已耗尽，请稍后再试。")
            else:
                print(f"本轮请求失败：{exc}")

            tool_summary = summarize_tool_messages(latest_messages, start_idx)
            if tool_summary:
                print()
                print("已完成的工具结果摘要：")
                print(tool_summary)

            return

        self.history = latest_messages

        if self.show_messages:
            render_trace(latest_messages, start_idx)
            return

        print()
        tool_list = summarize_invoked_tools(latest_messages, start_idx)
        if tool_list:
            print(f"Skills/tools used: {tool_list}")
            print()
        print(latest_ai_message(latest_messages))


def normalize_command(raw: str) -> tuple[str, str]:
    if " " not in raw.strip():
        return raw.strip(), ""
    command, arg = raw.strip().split(" ", 1)
    return command, arg.strip()


async def repl(args: argparse.Namespace) -> None:
    ensure_google_api_key()

    chat = InteractiveEmailAgent(
        model_name=args.model,
        base_url=args.base_url,
        show_messages=args.show_messages,
    )
    await chat.setup()

    print(f"Model: {args.model}")
    print(f"MCP server: {MCP_SERVER_PATH}")
    print(f"Rspamd base URL: {args.base_url}")
    print()
    print("Email Guardian is ready.")
    print("You can chat naturally, for example:")
    print('- "Analyze this email for phishing."')
    print('- "Bind my Gmail and start monitoring."')
    print('- "Show my recent suspicious emails."')
    print("Type /help for optional slash commands.")

    while True:
        try:
            user_input = input("\nYou> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not user_input:
            continue

        command, arg = normalize_command(user_input)

        if command in {"/quit", "/exit"}:
            print("Exiting.")
            break

        if command == "/help":
            print(HELP_TEXT)
            continue

        if command == "/reset":
            chat.reset()
            print("Conversation history cleared.")
            continue

        if command == "/trace":
            if arg not in {"on", "off"}:
                print("Usage: /trace on|off")
                continue
            chat.show_messages = arg == "on"
            print(f"Trace output {'enabled' if chat.show_messages else 'disabled'}.")
            continue

        if command == "/sample":
            prompt = build_analysis_prompt(
                "Analyze this email and decide whether it is benign, suspicious, spam, or phishing.",
                raw_email=DEFAULT_EMAIL,
            )
            await chat.ask(prompt)
            continue

        if command == "/email-file":
            if not arg:
                print("Usage: /email-file /path/to/message.eml")
                continue
            try:
                raw_email = read_text_file(arg)
            except OSError as exc:
                print(f"Failed to read email file: {exc}")
                continue
            prompt = build_analysis_prompt(
                "Analyze this email and decide whether it is benign, suspicious, spam, or phishing.",
                raw_email=raw_email,
            )
            await chat.ask(prompt)
            continue

        if command == "/headers-file":
            if not arg:
                print("Usage: /headers-file /path/to/headers.txt")
                continue
            try:
                raw_headers = read_text_file(arg)
            except OSError as exc:
                print(f"Failed to read headers file: {exc}")
                continue
            prompt = build_analysis_prompt(
                "Analyze these headers for SPF, DKIM, DMARC, ARC, routing anomalies, and sender-domain mismatches.",
                raw_headers=raw_headers,
            )
            await chat.ask(prompt)
            continue

        if command == "/paste-email":
            raw_email = collect_multiline_input("a raw RFC822 email")
            prompt = build_analysis_prompt(
                "Analyze this email and decide whether it is benign, suspicious, spam, or phishing.",
                raw_email=raw_email,
            )
            await chat.ask(prompt)
            continue

        if command == "/paste-headers":
            raw_headers = collect_multiline_input("raw email headers")
            prompt = build_analysis_prompt(
                "Analyze these headers for SPF, DKIM, DMARC, ARC, routing anomalies, and sender-domain mismatches.",
                raw_headers=raw_headers,
            )
            await chat.ask(prompt)
            continue

        await chat.ask(user_input)


def main() -> None:
    args = parse_args()
    asyncio.run(repl(args))


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

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

SYSTEM_PROMPT = """You are an email security analyst.

You have access to MCP tools exposed by the local email security server.

Tool usage guidance:
- Use `rspamd_scan_email` when raw RFC822 email content is available and you need a scanner-backed verdict.
- Use `email_header_auth_check` when the user provides headers only or asks about SPF, DKIM, DMARC, ARC, routing, or sender-domain mismatches.
- If the evidence is incomplete, you may use both tools when helpful.
- Use `bind_imap_mailbox` when the user wants continuous mailbox monitoring over IMAP.
- Prefer `setup_imap_monitor` when the user provides enough IMAP credentials and wants one-step setup.
- After binding a mailbox, use `start_imap_monitor` to begin background polling.
- Use `poll_imap_mailboxes_once` for immediate testing after binding credentials.
- Use `imap_monitor_status` and `list_recent_email_results` to inspect monitoring state and stored verdicts.
- Use `scan_recent_imap_emails` when the user asks about the newest emails in a bound mailbox and wants fresh analysis on demand.

Response requirements:
- Start with a concise verdict and confidence.
- Separate tool evidence from your own inference.
- Mention the most important findings and recommended next step.
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a LangGraph agent with Gemini 2.5 Flash against the local MCP server."
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
        "--email-file",
        help="Path to a raw RFC822 email file. If omitted, a built-in sample is used.",
    )
    parser.add_argument(
        "--headers-file",
        help="Path to a raw header block. When set without --email-file, the agent should prefer header-only analysis.",
    )
    parser.add_argument(
        "--question",
        default="Analyze this email and decide whether it is benign, suspicious, spam, or phishing.",
        help="User request passed to the Gemini agent.",
    )
    parser.add_argument(
        "--show-messages",
        action="store_true",
        help="Print the full LangGraph message trace including tool messages.",
    )
    return parser.parse_args()


def read_text_file(path: str | None) -> str | None:
    if not path:
        return None
    return Path(path).expanduser().read_text(encoding="utf-8")


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


def build_user_prompt(question: str, raw_email: str | None, raw_headers: str | None) -> str:
    sections = [question.strip()]

    if raw_email:
        sections.append("Use the available MCP tools to analyze the following raw RFC822 email:")
        sections.append(raw_email)
    elif raw_headers:
        sections.append("Use the available MCP tools to analyze the following raw email headers:")
        sections.append(raw_headers)
    else:
        sections.append("Use the available MCP tools to analyze the following raw RFC822 email:")
        sections.append(DEFAULT_EMAIL)

    return "\n\n".join(sections)


def format_message(message: BaseMessage) -> str:
    header = message.__class__.__name__
    if isinstance(message, ToolMessage):
        return f"[{header}] {message.name}\n{message.content}"
    if isinstance(message, AIMessage):
        return f"[{header}]\n{message.content}"
    return f"[{header}]\n{message.content}"


def extract_final_output(result: dict[str, Any]) -> str:
    messages = result.get("messages", [])
    for message in reversed(messages):
        if isinstance(message, AIMessage):
            return str(message.content)
    return json.dumps(result, indent=2, ensure_ascii=False, default=str)


async def run_agent(args: argparse.Namespace) -> None:
    ensure_google_api_key()

    raw_email = read_text_file(args.email_file)
    raw_headers = read_text_file(args.headers_file)

    model = ChatGoogleGenerativeAI(model=args.model, temperature=0)

    mcp_env = dict(os.environ)
    mcp_env["RSPAMD_BASE_URL"] = args.base_url

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
    agent = create_react_agent(model=model, tools=tools)

    result = await agent.ainvoke(
        {
            "messages": [
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(content=build_user_prompt(args.question, raw_email, raw_headers)),
            ]
        }
    )

    print(f"Model: {args.model}")
    print(f"MCP server: {MCP_SERVER_PATH}")
    print(f"Rspamd base URL: {args.base_url}")
    print()

    if args.show_messages:
        for message in result.get("messages", []):
            print(format_message(message))
            print()
    else:
        print(extract_final_output(result))


def main() -> None:
    args = parse_args()
    asyncio.run(run_agent(args))


if __name__ == "__main__":
    main()

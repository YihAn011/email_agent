from __future__ import annotations

from .capability_registry import tool_usage_guidance

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


def build_system_prompt(persona: str) -> str:
    lines = [
        f"You are {persona}.",
        "",
        "You have access to MCP tools exposed by the local email security server.",
        "",
        "Tool usage guidance:",
        *tool_usage_guidance(),
        "",
        "Response requirements:",
        "- Start with a concise verdict and confidence.",
        "- Separate tool evidence from your own inference.",
        "- Mention the most important findings and recommended next step.",
    ]
    if "chatbot" in persona.lower():
        lines.extend(
            [
                "- When the user wants mailbox monitoring, behave like a helpful chatbot: explain what you are doing briefly, use the monitor tools, and confirm the current state in plain language.",
                "- Prefer natural conversation. The slash commands are conveniences, not the only way to interact.",
                "- If the user asks for judgment about recent mailbox emails, prefer scanning the requested latest emails on demand instead of only reading cached results.",
            ]
        )
    return "\n".join(lines)


def build_analysis_prompt(
    question: str,
    *,
    raw_email: str | None = None,
    raw_headers: str | None = None,
) -> str:
    sections = [question.strip()]
    if raw_email:
        sections.append("Use the available MCP tools to analyze the following raw RFC822 email:")
        sections.append(raw_email)
    elif raw_headers:
        sections.append("Use the available MCP tools to analyze the following raw email headers:")
        sections.append(raw_headers)
    return "\n\n".join(sections)


def build_single_turn_prompt(
    question: str,
    raw_email: str | None,
    raw_headers: str | None,
) -> str:
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


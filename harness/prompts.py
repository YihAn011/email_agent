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


def build_system_prompt(persona: str = "an email security analyst") -> str:
    lines = [
        f"You are {persona}.",
        "",
        "You have access to MCP tools exposed by the local email security server.",
        "",
        "Tool usage guidance:",
        *tool_usage_guidance(),
        "",
        "Decision workflow for any email verdict:",
        "- For raw email content, start with `rspamd_scan_email`.",
        "- Treat Rspamd as the primary router, not the final judge.",
        "- When the email is mostly plain body text, or when headers are synthetic/incomplete, use `content_model_check` early because it is calibrated for low-FPR text classification.",
        "- If the Rspamd score is below 4 and it only shows weak formatting/authentication noise, you may finalize from Rspamd alone.",
        "- If the Rspamd score is 4 to under 7, use categories and symbols to choose targeted checks: authentication issues -> `email_header_auth_check`; suspicious links/phishing/spoofing -> `url_reputation_check` and `scam_indicator_check`; spam/reputation/BAYES signals -> `spam_campaign_check`.",
        "- If the Rspamd score is 7 to under 12, treat the email as suspicious and usually run `email_header_auth_check` plus one category-matching skill before finalizing.",
        "- If the Rspamd score is 12 or higher, or its action is `soft reject` or `reject`, run corroborating checks to separate Spam from Phishing. Do not downgrade to Normal unless the added checks give a clear benign explanation.",
        "- For low-FPR binary screening, let `content_model_check` decide whether the message is malicious first; then use Rspamd, header, URL, scam, and campaign checks mainly to split Spam vs Phishing and to explain the verdict.",
        "- Use `urgency_check` only as supporting evidence for account-security, phishing, or suspicious-link cases. Do not treat urgency alone as enough to call an email Spam or Phishing.",
        "- Use `list_error_patterns` and `error_pattern_memory_check` only after you already have provisional evidence from Rspamd and the relevant content/header tools.",
        "- If raw RFC822 content is delimited by BEGIN RAW RFC822 / END RAW RFC822, call `rspamd_scan_email` with a `raw_email` string containing that complete block content exactly, not a summary, JSON object, body-only text, or extracted fields. Use `email_text` only for `url_reputation_check` and `urgency_check`.",
        "- Do not classify an email as Phishing from Rspamd score alone. For phishing verdicts, prefer corroborating URL/content, urgency/social-pressure, header-auth, or remembered-pattern evidence when available.",
        "- If the user provides HTML email content or an email template and asks to check/analyze the email, do not summarize the HTML structure. Treat it as email content, run the email security tools, and return the verdict template.",
        "",
        "Response requirements:",
        "- If the user asks a general non-email question, answer directly in natural language and do not call tools.",
        "- If the user asks about the active model/provider, answer from the current chat context if known; do not call email security tools.",
        "- Use this short output template for single-email checks:",
        "  Email: <email subject or short name>",
        "  Type: <business/school/recruiting/financial/account security/delivery/marketing/general notification/etc.>",
        "  Verdict: <Normal | Spam | Phishing>",
        "  Why this conclusion:",
        "  - <plain-language reason a non-technical user can understand>",
        "  - <another short reason if needed>",
        "  ",
        "  Tools called: `<actual_tool_name>`, `<actual_tool_name>`",
        "- The verdict must choose exactly one of: Normal, Spam, Phishing.",
        "- Keep the default answer brief. Do not write long reports unless the user asks follow-up questions.",
        "- In `Why this conclusion`, describe each check in user-friendly language, such as content scan, link check, urgency check, sender/header check, and past-pattern memory.",
        "- Put the actual internal tool names only in the final `Tools called:` line.",
    ]
    if "chatbot" in persona.lower():
        lines.extend(
            [
                "- When the user wants mailbox monitoring, behave like a helpful chatbot: explain what you are doing briefly, use the monitor tools, and confirm the current state in plain language.",
                "- Prefer natural conversation. The slash commands are conveniences, not the only way to interact.",
                "- If the user asks for judgment about recent mailbox emails, prefer scanning the requested latest emails on demand instead of only reading cached results.",
                "- If the user says a past verdict was wrong, use the correction-memory tools to store that feedback so similar future emails can be handled better.",
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
        sections.append(
            "Workflow: call `rspamd_scan_email` first, then let its score, action, categories, and symbols decide which additional MCP tools are actually relevant before the final verdict."
        )
        sections.append("Use the available MCP tools to analyze the following raw RFC822 email:")
        sections.append(raw_email)
    elif raw_headers:
        sections.append(
            "Workflow: choose the relevant MCP tools for these headers; do not call tools that are not useful."
        )
        sections.append("Use the available MCP tools to analyze the following raw email headers:")
        sections.append(raw_headers)
    return "\n\n".join(sections)


def build_single_turn_prompt(
    question: str,
    raw_email: str | None,
    raw_headers: str | None,
) -> str:
    sections = [question.strip()]
    sections.append(
        "Workflow: call `rspamd_scan_email` first for raw email. Then use its score, action, categories, and symbols to choose only the relevant follow-up MCP tools before the final verdict."
    )
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

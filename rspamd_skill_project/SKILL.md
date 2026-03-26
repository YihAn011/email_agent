---
name: rspamd-email-scan
description: Analyzes RFC822 raw emails with Rspamd `/checkv2` and returns normalized spam, phishing, spoofing, authentication, link, reputation, MIME, and attachment risk signals. Use when the user wants to analyze an `.eml` or raw email, triage suspicious email content, inspect email security posture, check spam/phishing likelihood, or route an email through `rspamd_scan_email`.
---

# Rspamd Email Scan

## Purpose

Use this skill to analyze a raw RFC822 email with Rspamd and convert the response into agent-friendly risk signals.

Primary tool:

- `rspamd_scan_email`

Primary outcomes:

- spam and phishing triage
- authentication issue detection
- suspicious link and sender reputation signals
- attachment and MIME anomaly hints
- normalized summary for downstream agent decisions

## When To Use

Use this skill when the user asks to:

- scan or classify a suspicious email
- inspect a raw email, `.eml`, or RFC822 message
- check spam score or Rspamd action
- investigate phishing, spoofing, DKIM, SPF, DMARC, ARC, URL, MIME, or attachment indicators
- obtain structured email-security signals before further reasoning

Typical trigger terms:

- `rspamd`
- `raw email`
- `RFC822`
- `.eml`
- `spam score`
- `phishing email`
- `email headers`
- `DKIM`
- `SPF`
- `DMARC`
- `spoofing`
- `suspicious links`

## When Not To Use

Do not use this skill when:

- the user only wants a plain-language summary without scanning
- the email body is unavailable and no raw RFC822 content can be produced
- the task requires modifying Rspamd configuration
- the task requires training or learning endpoints
- the task is attachment sandboxing, malware detonation, or deep URL analysis by itself

Use a different tool or follow-up skill for:

- URL reputation enrichment
- attachment analysis
- header-only forensic review
- broader phishing reasoning across message content and business context

## Required Input

The tool requires:

- `raw_email`: complete RFC822 email text

Optional context that improves scan fidelity:

- `mail_from`: SMTP envelope sender
- `rcpt_to`: SMTP envelope recipients
- `ip`: client IP
- `helo`: SMTP `HELO` or `EHLO`
- `hostname`: client hostname
- `log_tag`: request correlation tag
- `timeout_seconds`: between `1.0` and `60.0`
- `include_raw_result`: include original Rspamd JSON in output
- `base_url`: override the default Rspamd service URL

If the user provides only fragments, first reconstruct a valid raw email when possible. Minimum useful structure:

```text
From: sender@example.com
To: recipient@example.com
Subject: Example subject

Email body text here.
```

Do not invent security-relevant headers or transport metadata unless the user explicitly gives them.

## Default Behavior

The tool sends:

- `POST /checkv2`
- body as raw RFC822 email
- `Content-Type: message/rfc822`

The service URL defaults to `RSPAMD_BASE_URL` or `http://127.0.0.1:11333`.

## Working Process

Follow this sequence:

1. Confirm you have raw RFC822 email content.
2. Collect any available SMTP context such as envelope sender, recipient list, client IP, and `HELO`.
3. Call `rspamd_scan_email`.
4. Read normalized fields first: `risk_level`, `action`, `score`, `categories`, `summary`.
5. Review top `symbols` for the strongest evidence.
6. If needed, use `recommended_next_skills` to decide the next investigation step.
7. Report findings conservatively. Distinguish scanner evidence from your own interpretation.

## Output Interpretation

The normalized result includes:

- `score`: numeric Rspamd score
- `required_score`: threshold if returned by the service
- `action`: Rspamd action such as reject, add header, or no action
- `risk_level`: normalized `low`, `medium`, `high`, or `unknown`
- `categories`: inferred buckets such as `phishing`, `spoofing`, `authentication_issue`, `suspicious_links`, `reputation_issue`, `spam`, `content_anomaly`, `attachment_risk`
- `symbols`: evidence entries sorted by absolute score
- `summary`: short agent-friendly explanation
- `recommended_next_skills`: suggested follow-up capabilities
- `raw_result`: original Rspamd payload when enabled

Interpretation rules:

- Treat `risk_level` as a triage signal, not a final verdict.
- High score plus `phishing` or `suspicious_links` usually warrants deeper review.
- Authentication failures alone do not prove phishing, but they increase suspicion.
- Negative or low scores do not guarantee safety.

## Recommended Follow-Up

Use the normalized recommendations as defaults:

- `url_reputation_check` for phishing or suspicious-link categories
- `email_header_auth_check` for SPF, DKIM, DMARC, or ARC issues
- `attachment_analyzer` for attachment-related signals
- `llm_phishing_reasoner` when the score is elevated or phishing indicators appear

If those exact skills are unavailable, perform the equivalent analysis manually.

## Failure Handling

Possible error types:

- `validation_error`: the raw email is missing or invalid
- `connection_error`: Rspamd is unreachable
- `response_error`: Rspamd returned HTTP errors or invalid JSON
- `unexpected_error`: uncategorized runtime failure

Handling guidance:

- On `validation_error`, ask for the full raw email.
- On `connection_error`, verify the base URL and whether Rspamd is listening on `11333`.
- On `response_error`, surface the status and short response excerpt.
- Do not pretend a scan succeeded when the tool returned `ok: false`.

## Constraints

This skill:

- scans emails only
- does not modify Rspamd configuration
- does not call learning endpoints
- does not guarantee malware or phishing confirmation
- should not replace analyst judgment for high-risk decisions

## Response Style

When reporting results to the user:

- start with the overall verdict from `risk_level`, `action`, and `score`
- name the most important categories
- cite the strongest 3-5 symbols when relevant
- separate confirmed scanner output from your own inference
- suggest the next best investigation step when risk is medium or high

Preferred compact format:

```markdown
Verdict: [low|medium|high] risk
Rspamd action: [action]
Score: [score] / [required_score if present]
Key categories: [comma-separated list]
Top signals: [symbol names]
Next step: [follow-up check]
```

## Example Invocation

```python
rspamd_scan_email(
    raw_email="From: a@example.com\nTo: b@example.com\nSubject: Test\n\nHello",
    mail_from="a@example.com",
    rcpt_to=["b@example.com"],
    timeout_seconds=15.0,
    include_raw_result=True,
)
```

## Example Agent Framing

Good requests for this skill:

- "Scan this raw email with Rspamd and tell me if it looks phishy."
- "Check the spam score for this `.eml`."
- "Analyze this message for SPF, DKIM, DMARC, and spoofing signals."
- "Run email security triage on this RFC822 message."

## Additional Resources

- Project usage and local setup: [README.md](README.md)

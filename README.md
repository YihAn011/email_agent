# Email Agent

## 1. Introduction

`email_agent` is a terminal chatbot for email security analysis. It uses Gemini as the agent model, exposes local capabilities through an MCP server, scans raw emails with `rspamd`, checks headers for SPF/DKIM/DMARC signals, and can bind a mailbox over IMAP to monitor new emails or scan the latest emails on demand.

## 2. Usage Flow

Start `rspamd` and `redis`:

```bash
sudo systemctl start redis-server
sudo systemctl start rspamd
```


If this is the first time running the project:

```bash
cd ~/Desktop/email_agent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Then put your real values into `.env`:

```bash
GOOGLE_API_KEY="your-google-api-key"
RSPAMD_BASE_URL="http://127.0.0.1:11333"
```

Start the chatbot:

```bash
cd ~/Desktop/email_agent
python chatbot.py
```

Typical things you can ask after startup:

```text
Analyze this email for phishing.
Bind my Gmail and start monitoring.
Check my latest 2 emails.
Show my recent suspicious emails.
```

## 3. Skills And Tools

Skills:

- `skills/rspamd/skill.py`
- `skills/header_auth/skill.py`
- `skills/imap_monitor/skill.py`

MCP tools:

- `rspamd_scan_email`
- `email_header_auth_check`
- `bind_imap_mailbox`
- `setup_imap_monitor`
- `start_imap_monitor`
- `stop_imap_monitor`
- `imap_monitor_status`
- `poll_imap_mailboxes_once`
- `list_recent_email_results`
- `scan_recent_imap_emails`

# Email Agent

## 1. Introduction

`email_agent` is a terminal chatbot for email security analysis. It uses Gemini by default, while still supporting local Ollama-hosted `Qwen3` as an optional provider. It exposes local capabilities through an MCP server, scans raw emails with `rspamd`, checks headers for SPF/DKIM/DMARC signals, and can bind a mailbox over IMAP to monitor new emails or scan the latest emails on demand.

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
LLM_PROVIDER="gemini"
GOOGLE_API_KEY="your-google-api-key"
GEMINI_MODEL="gemini-2.5-flash"
RSPAMD_BASE_URL="http://127.0.0.1:11333"
```

If you want to run locally with Ollama / Qwen3 instead, set:

```bash
LLM_PROVIDER="ollama"
OLLAMA_MODEL="qwen3:latest"
OLLAMA_BASE_URL="http://127.0.0.1:11434"
```

Start the chatbot:

```bash
cd ~/Desktop/email_agent
python chatbot.py
```

Override the provider or model at runtime if needed:

```bash
python chatbot.py --provider gemini --model gemini-2.5-flash
python chatbot.py --provider ollama --model qwen3:latest
python examples/run_langgraph_gemini_agent.py --provider gemini --model gemini-2.5-flash
python examples/run_langgraph_gemini_agent.py --provider ollama --model qwen3:latest
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

## 4. Architecture Layer

The project now includes an explicit harness layer inspired by Claude Code-style architecture separation:

- `harness/capability_registry.py`
- `harness/request_router.py`
- `harness/system_manifest.py`
- `harness/query_engine.py`
- `harness/audit.py`
- `harness/runtime.py`

Useful inspection commands:

```bash
python -m harness.main summary
python -m harness.main manifest
python -m harness.main audit
python -m harness.main route "check my latest 5 emails"
```

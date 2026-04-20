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

Start the Ubuntu desktop pet UI:

```bash
cd ~/Desktop/email_agent
source .venv/bin/activate
pip install -r requirements.txt
python desktop_pet.py
```

If Qt fails with an `xcb` platform plugin error on Ubuntu, install the missing
system dependency and run it again:

```bash
sudo apt-get update
sudo apt-get install -y libxcb-cursor0
```

Override the provider or model at runtime if needed:

```bash
python chatbot.py --provider gemini --model gemini-2.5-flash
python chatbot.py --provider ollama --model qwen3:latest
python desktop_pet.py --provider gemini --model gemini-2.5-flash
python desktop_pet.py --provider ollama --model qwen3:latest
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
# Email Agent — Quick Start

Minimal steps to run the desktop pet UI or the full local stack.

Prerequisites
- Python 3
- (Optional) `redis-server` and `rspamd` for full features, or use the mock server.

Initial setup (once):
```bash
cd ~/Desktop/email_agent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # edit .env with your keys and models
```

Run options
- Run UI only (uses `.env` or flags):
```bash
python desktop_pet.py [--provider gemini|ollama] [--model MODEL]
```
- Start full local stack (starts/ensures redis, rspamd, optional Ollama or mock, then runs pet):
```bash
./scripts/start_full_stack.sh [--provider ollama --model qwen3:latest]
USE_MOCK_RSPAMD=1 ./scripts/start_full_stack.sh
```

Notes
- Set environment defaults in `.env`: `LLM_PROVIDER`, `GEMINI_MODEL`, `OLLAMA_MODEL`, `RSPAMD_BASE_URL`.
- Ubuntu Qt `xcb` plugin error: `sudo apt-get install -y libxcb-cursor0`.
- `start_full_stack.sh` will export `EMAIL_AGENT_STACK_CHILD_PIDS` so `desktop_pet.py` can shut down spawned services.

Commands reference
- Launch UI: `python desktop_pet.py`
- Launch full stack + UI: `./scripts/start_full_stack.sh`

# Rspamd Scan Email Skill

A minimal but complete Python implementation of an `rspamd_scan_email` skill.

## What is included

- `skills/base_skill.py` — shared base abstractions
- `skills/rspamd/schemas.py` — input/output schemas
- `skills/rspamd/client.py` — HTTP client for Rspamd `/checkv2`
- `skills/rspamd/normalize.py` — normalization layer from raw Rspamd output to agent-friendly signals
- `skills/rspamd/skill.py` — the skill implementation
- `examples/run_skill.py` — simple demo entry point
- `requirements.txt` — dependencies

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Environment

Set the Rspamd base URL if needed:

```bash
export RSPAMD_BASE_URL="http://127.0.0.1:11333"
```

## Run with a real rspamd service (Linux)

Install and start rspamd + redis:

```bash
sudo apt update
sudo apt install -y rspamd redis-server
sudo systemctl enable --now redis-server rspamd
```

Verify rspamd is listening on `11333`:

```bash
ss -ltnp | grep 11333
```

Optional quick endpoint check:

```bash
cat > /tmp/rspamd-probe.eml <<'EOF'
From: probe@example.com
To: probe@example.com
Subject: probe

hello
EOF

curl -sS \
  -H "Content-Type: message/rfc822" \
  --data-binary @/tmp/rspamd-probe.eml \
  "$RSPAMD_BASE_URL/checkv2"
```

## Run the example (real rspamd)

```bash
python3 examples/run_skill.py
```

This script now performs a preflight connectivity check against `/checkv2` first.

If needed, override URL or skip preflight:

```bash
python3 examples/run_skill.py --base-url "http://127.0.0.1:11333"
python3 examples/run_skill.py --skip-preflight
```

## Run as an MCP server (AI-callable)

Start the MCP server over stdio:

```bash
.venv/bin/python3 mcp_server.py
```

Exposed tool:

- `rspamd_scan_email`

Example MCP client config (Cursor/Claude Desktop style):

```json
{
  "mcpServers": {
    "rspamd-skill": {
      "command": "/absolute/path/to/rspamd_skill_project/.venv/bin/python3",
      "args": ["/absolute/path/to/rspamd_skill_project/mcp_server.py"],
      "env": {
        "RSPAMD_BASE_URL": "http://127.0.0.1:11333"
      }
    }
  }
}
```

If your client supports working-directory based commands, you can also run:

```json
{
  "mcpServers": {
    "rspamd-skill": {
      "command": "/absolute/path/to/rspamd_skill_project/.venv/bin/python3",
      "args": ["mcp_server.py"],
      "cwd": "/absolute/path/to/rspamd_skill_project"
    }
  }
}
```

## Mock server (optional local testing)

If you do not have rspamd installed yet, you can still run a local mock:

```bash
python3 examples/mock_rspamd_server.py
```

## Expected Rspamd endpoint

This project uses the official HTTP scan endpoint:

- `POST /checkv2`

The request body is the raw RFC822 email.

## Notes

- The skill only performs scanning.
- It does not modify Rspamd configuration.
- It does not call learning endpoints.
- It returns structured results suitable for an agent pipeline.

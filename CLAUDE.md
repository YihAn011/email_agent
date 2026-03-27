# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Setup

```bash
cd rspamd_skill_project
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Set the Rspamd URL (defaults to `http://127.0.0.1:11333`):
```bash
export RSPAMD_BASE_URL="http://127.0.0.1:11333"
```

## Running

**Demo against a live rspamd instance:**
```bash
python3 rspamd_skill_project/examples/run_skill.py
python3 rspamd_skill_project/examples/run_skill.py --base-url "http://127.0.0.1:11333"
python3 rspamd_skill_project/examples/run_skill.py --skip-preflight
```

**Local mock server (no rspamd needed):**
```bash
python3 rspamd_skill_project/examples/mock_rspamd_server.py
# then in another terminal:
python3 rspamd_skill_project/examples/run_skill.py
```

**MCP server (stdio transport, for AI clients):**
```bash
rspamd_skill_project/.venv/bin/python3 rspamd_skill_project/mcp_server.py
```

## Architecture

All code lives under `rspamd_skill_project/`. The project exposes a single skill — `rspamd_scan_email` — in two ways: as a Python library and as an MCP server tool.

**Data flow:**
```
MCP client / run_skill.py
    → RspamdScanEmailInput (schemas.py)
    → RspamdScanEmailSkill.run() (skill.py)
        → RspamdClient.scan_email() (client.py)  -- POST /checkv2 to rspamd
        → normalize_rspamd_result() (normalize.py) -- raw JSON → RspamdNormalizedResult
    → SkillResult[RspamdNormalizedResult] (base_skill.py)
```

**Key abstractions (`skills/base_skill.py`):**
- `BaseSkill[InputT, OutputT]` — abstract base with a single `run(payload)` method
- `SkillResult[OutputT]` — typed envelope with `ok`, `data`, `error`, and `meta` fields
- `SkillMeta` — latency, timestamp, endpoint, and service version tracking

**Normalization (`skills/rspamd/normalize.py`):**
- Converts raw Rspamd JSON into `RspamdNormalizedResult` with `risk_level`, `categories`, `symbols`, and `recommended_next_skills`
- `CATEGORY_RULES` maps symbol name substrings (e.g. `PHISH`, `SPF`, `DMARC`) to semantic categories
- `recommend_next_skills()` suggests downstream agent skills based on detected categories

**MCP server (`mcp_server.py`):**
- Built with `FastMCP`; exposes `rspamd_scan_email` as a single tool over stdio
- Thin wrapper that constructs `RspamdScanEmailInput`, instantiates the skill, and returns `result.model_dump()`

## Dependencies

- `httpx` — synchronous HTTP client for Rspamd calls
- `pydantic` v2 — input/output schemas and validation
- `mcp` — MCP server framework (`FastMCP`)

#!/usr/bin/env bash
# Start Email Guardian as a URL-addressable MCP server for clients that support
# streamable HTTP (for example ChatGPT Developer Mode, MCP Inspector, or Codex).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -d "$ROOT/.venv" ]]; then
  echo "[start_mcp_http] ERROR: .venv not found. Create it first:" >&2
  echo "  cd \"$ROOT\" && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt" >&2
  exit 1
fi

# shellcheck source=/dev/null
source "$ROOT/.venv/bin/activate"

MCP_HOST="${MCP_HOST:-127.0.0.1}"
MCP_PORT="${MCP_PORT:-8000}"
MCP_PATH="${MCP_STREAMABLE_HTTP_PATH:-/mcp}"

echo "[start_mcp_http] Starting Email Guardian MCP server"
echo "[start_mcp_http] URL: http://${MCP_HOST}:${MCP_PORT}${MCP_PATH}"
echo "[start_mcp_http] Transport: streamable-http"

exec "$ROOT/.venv/bin/python" "$ROOT/mcp_server.py" \
  --transport streamable-http \
  --host "$MCP_HOST" \
  --port "$MCP_PORT" \
  --path "$MCP_PATH" \
  "$@"

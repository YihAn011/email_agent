#!/usr/bin/env bash
# Start local dependencies (Redis, Rspamd or mock, Ollama if configured) then run the desktop pet.
#
# Usage (from repo root or any directory):
#   ./scripts/start_full_stack.sh
#   ./scripts/start_full_stack.sh --provider ollama --model qwen3:latest
#
# Environment overrides:
#   USE_MOCK_RSPAMD=1   Do not use systemd rspamd; run examples/mock_rspamd_server.py on :11333 instead.
#   SKIP_SYSTEMD=1      Do not start redis-server / rspamd via systemctl (you manage them yourself).
#   START_APP=pet       Default. Use START_APP=chatbot to run chatbot.py instead of desktop_pet.py.
#
# When mock rspamd and/or ollama are started by this script, their PIDs are exported as
# EMAIL_AGENT_STACK_CHILD_PIDS so desktop_pet.py "Quit and shut down all" can SIGTERM them on exit.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

USE_MOCK_RSPAMD="${USE_MOCK_RSPAMD:-0}"
SKIP_SYSTEMD="${SKIP_SYSTEMD:-0}"
START_APP="${START_APP:-pet}"

CHILD_PIDS=()
cleanup() {
  local pid
  for pid in "${CHILD_PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT INT TERM

read_env_value() {
  local key="$1"
  local file="${2:-$ROOT/.env}"
  [[ -f "$file" ]] || return 0
  local line
  line="$(grep -E "^[[:space:]]*${key}=" "$file" | tail -n1)" || true
  [[ -n "$line" ]] || return 0
  local val="${line#*=}"
  val="${val#"${val%%[![:space:]]*}"}"
  val="${val%"${val##*[![:space:]]}"}"
  if [[ "${#val}" -ge 2 ]]; then
    local q="${val:0:1}"
    if [[ "$q" == "'" || "$q" == '"' ]] && [[ "${val: -1}" == "$q" ]]; then
      val="${val:1:${#val}-2}"
    fi
  fi
  printf '%s' "$val"
}

LLM_PROVIDER="$(read_env_value LLM_PROVIDER)"
LLM_PROVIDER="${LLM_PROVIDER:-gemini}"
OLLAMA_BASE_URL="$(read_env_value OLLAMA_BASE_URL)"
OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://127.0.0.1:11434}"
RSPAMD_BASE_URL="$(read_env_value RSPAMD_BASE_URL)"
RSPAMD_BASE_URL="${RSPAMD_BASE_URL:-http://127.0.0.1:11333}"

ollama_host_port() {
  # crude parse host:port from OLLAMA_BASE_URL for health checks
  local url="$OLLAMA_BASE_URL"
  url="${url#http://}"
  url="${url#https://}"
  url="${url%%/*}"
  if [[ "$url" == *:* ]]; then
    printf '%s' "${url##*:}"
  else
    printf '11434'
  fi
}

O_PORT="$(ollama_host_port)"
O_HOST="127.0.0.1"

tcp_open() {
  local host="$1" port="$2"
  if command -v nc >/dev/null 2>&1; then
    nc -z -w 2 "$host" "$port" >/dev/null 2>&1
    return $?
  fi
  timeout 1 bash -c "echo >/dev/tcp/${host}/${port}" >/dev/null 2>&1
}

wait_tcp() {
  local host="$1" port="$2" label="$3" tries="${4:-30}"
  local i=0
  while [[ "$i" -lt "$tries" ]]; do
    if tcp_open "$host" "$port"; then
      echo "[start_full_stack] ${label} is up (${host}:${port})."
      return 0
    fi
    i=$((i + 1))
    sleep 0.2
  done
  echo "[start_full_stack] ERROR: ${label} did not become ready on ${host}:${port}." >&2
  return 1
}

if [[ ! -d "$ROOT/.venv" ]]; then
  echo "[start_full_stack] ERROR: .venv not found. Create it first:" >&2
  echo "  cd \"$ROOT\" && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt" >&2
  exit 1
fi

# shellcheck source=/dev/null
source "$ROOT/.venv/bin/activate"

PY="$ROOT/.venv/bin/python"

if [[ "$USE_MOCK_RSPAMD" == "1" ]]; then
  if tcp_open 127.0.0.1 11333; then
    echo "[start_full_stack] Port 11333 already in use; assuming Rspamd or mock is already running."
  else
    echo "[start_full_stack] Starting mock Rspamd on http://127.0.0.1:11333 ..."
    "$PY" "$ROOT/examples/mock_rspamd_server.py" &
    CHILD_PIDS+=("$!")
    wait_tcp 127.0.0.1 11333 "Mock Rspamd" 50
  fi
elif [[ "$SKIP_SYSTEMD" != "1" ]] && command -v systemctl >/dev/null 2>&1; then
  if ! systemctl is-active --quiet redis-server 2>/dev/null; then
    echo "[start_full_stack] Starting redis-server (sudo may prompt) ..."
    sudo systemctl start redis-server
  else
    echo "[start_full_stack] redis-server already active."
  fi
  if ! systemctl is-active --quiet rspamd 2>/dev/null; then
    echo "[start_full_stack] Starting rspamd (sudo may prompt) ..."
    sudo systemctl start rspamd
  else
    echo "[start_full_stack] rspamd already active."
  fi
  wait_tcp 127.0.0.1 11333 "Rspamd" 50
else
  echo "[start_full_stack] SKIP_SYSTEMD=1 or no systemctl: not starting redis/rspamd."
  if ! tcp_open 127.0.0.1 11333; then
    echo "[start_full_stack] WARNING: nothing is listening on 11333. Set RSPAMD_BASE_URL or start Rspamd/mock." >&2
  fi
fi

if [[ "${LLM_PROVIDER,,}" == "ollama" ]]; then
  if curl -fsS "http://${O_HOST}:${O_PORT}/api/tags" >/dev/null 2>&1; then
    echo "[start_full_stack] Ollama already responding at http://${O_HOST}:${O_PORT}."
  else
    if ! command -v ollama >/dev/null 2>&1; then
      echo "[start_full_stack] ERROR: LLM_PROVIDER=ollama but 'ollama' is not on PATH." >&2
      exit 1
    fi
    echo "[start_full_stack] Starting ollama serve ..."
    ollama serve >/tmp/email_agent_ollama.log 2>&1 &
    CHILD_PIDS+=("$!")
    ok=0
    for _ in $(seq 1 75); do
      if curl -fsS "http://${O_HOST}:${O_PORT}/api/tags" >/dev/null 2>&1; then
        ok=1
        break
      fi
      sleep 0.2
    done
    if [[ "$ok" -ne 1 ]]; then
      echo "[start_full_stack] ERROR: Ollama did not start (see /tmp/email_agent_ollama.log)." >&2
      exit 1
    fi
    echo "[start_full_stack] Ollama is up (logs: /tmp/email_agent_ollama.log)."
  fi
fi

echo "[start_full_stack] RSPAMD_BASE_URL=${RSPAMD_BASE_URL}"
echo "[start_full_stack] LLM_PROVIDER=${LLM_PROVIDER}"

_stack_csv=""
for pid in "${CHILD_PIDS[@]}"; do
  if [[ -n "${pid:-}" ]]; then
    if [[ -n "$_stack_csv" ]]; then
      _stack_csv+=","
    fi
    _stack_csv+="$pid"
  fi
done
if [[ -n "$_stack_csv" ]]; then
  export EMAIL_AGENT_STACK_CHILD_PIDS="$_stack_csv"
  echo "[start_full_stack] EMAIL_AGENT_STACK_CHILD_PIDS=${_stack_csv}"
fi

case "${START_APP,,}" in
  chatbot)
    echo "[start_full_stack] Launching chatbot.py ..."
    "$PY" "$ROOT/chatbot.py" "$@"
    ;;
  pet|desktop_pet|"")
    echo "[start_full_stack] Launching desktop_pet.py ..."
    "$PY" "$ROOT/desktop_pet.py" "$@"
    ;;
  *)
    echo "[start_full_stack] ERROR: unknown START_APP='${START_APP}' (use pet or chatbot)." >&2
    exit 1
    ;;
esac

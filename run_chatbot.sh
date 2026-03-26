#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -x "$PROJECT_ROOT/.venv/bin/python3" ]]; then
  echo "Missing virtual environment at $PROJECT_ROOT/.venv"
  echo "Run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
  exit 1
fi

if [[ ! -f "$PROJECT_ROOT/.env" ]]; then
  echo "Missing $PROJECT_ROOT/.env"
  echo "Create it from the template:"
  echo "  cp .env.example .env"
  exit 1
fi

cd "$PROJECT_ROOT"
env -u PS1 "$PROJECT_ROOT/.venv/bin/python3" chatbot.py "$@"

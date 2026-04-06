#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p dataset/processed/eval_chunks dataset/logs

INPUT="$ROOT_DIR/dataset/processed/spam_binary_train.csv"
PYTHON="$ROOT_DIR/.venv/bin/python3"
SCRIPT="$ROOT_DIR/dataset/evaluate_dataset_with_skills.py"

declare -a OFFSETS=(0 122876 245752 368628)
declare -a LIMITS=(122876 122876 122876 122875)

for i in "${!OFFSETS[@]}"; do
  chunk="$(printf "%02d" "$i")"
  unit="email-agent-pattern-chunk-${chunk}"
  output="$ROOT_DIR/dataset/processed/eval_chunks/train_chunk_${chunk}.jsonl"
  log="$ROOT_DIR/dataset/logs/train_chunk_${chunk}.log"
  offset="${OFFSETS[$i]}"
  limit="${LIMITS[$i]}"
  completed=0
  if [[ -f "$output" ]]; then
    completed="$(wc -l < "$output" | tr -d ' ')"
  fi

  if (( completed >= limit )); then
    echo "Skipping ${unit}: already complete (${completed}/${limit})"
    continue
  fi

  if (( completed > 0 )); then
    echo "Resuming ${unit}: existing=${completed} remaining=$((limit - completed))"
    systemd-run --user --unit="$unit" --collect --same-dir \
      "$PYTHON" "$SCRIPT" \
      --input "$INPUT" \
      --output "$output" \
      --offset "$offset" \
      --limit "$limit" \
      --append \
      --progress-every 500 \
      >>"$log" 2>&1
  else
    echo "Starting ${unit}: offset=${offset} limit=${limit}"
    systemd-run --user --unit="$unit" --collect --same-dir \
      "$PYTHON" "$SCRIPT" \
      --input "$INPUT" \
      --output "$output" \
      --offset "$offset" \
      --limit "$limit" \
      --progress-every 500 \
      >>"$log" 2>&1
  fi
done

echo "Launched all chunk services."

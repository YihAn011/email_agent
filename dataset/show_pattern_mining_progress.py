from __future__ import annotations

import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHUNK_DIR = ROOT / "dataset" / "processed" / "eval_chunks"

CHUNKS = [
    ("00", 122876),
    ("01", 122876),
    ("02", 122876),
    ("03", 122875),
]


def count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        return sum(1 for _ in handle)


def read_service_state(unit: str) -> str:
    cmd = f"systemctl --user is-active {unit} 2>/dev/null || true"
    return os.popen(cmd).read().strip() or "inactive"


def main() -> None:
    total_done = 0
    total_target = sum(limit for _, limit in CHUNKS)

    print("Pattern Mining Progress")
    print(f"Target rows: {total_target}")
    print()

    for chunk, limit in CHUNKS:
        unit = f"email-agent-pattern-chunk-{chunk}"
        output = CHUNK_DIR / f"train_chunk_{chunk}.jsonl"
        done = count_lines(output)
        total_done += done
        pct = (done / limit * 100.0) if limit else 0.0
        raw_state = read_service_state(unit)
        if done >= limit:
            state = "complete"
        elif raw_state == "active":
            state = "active"
        elif done > 0:
            state = "paused"
        else:
            state = raw_state
        print(f"Chunk {chunk}  {done:>7}/{limit:<7}  {pct:6.2f}%  {state}")

    total_pct = (total_done / total_target * 100.0) if total_target else 0.0
    print()
    print(f"Total     {total_done:>7}/{total_target:<7}  {total_pct:6.2f}%")


if __name__ == "__main__":
    main()

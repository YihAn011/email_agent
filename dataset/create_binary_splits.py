import csv
import hashlib
import sys
from collections import Counter, defaultdict
from pathlib import Path


csv.field_size_limit(sys.maxsize)

ROOT = Path(__file__).resolve().parent
INPUT = ROOT / "processed" / "spam_binary_dataset.csv"
TRAIN = ROOT / "processed" / "spam_binary_train.csv"
VAL = ROOT / "processed" / "spam_binary_val.csv"
TEST = ROOT / "processed" / "spam_binary_test.csv"
SUMMARY = ROOT / "processed" / "binary_split_summary.md"

SPLIT_BUCKETS = (
    ("train", 80),
    ("val", 10),
    ("test", 10),
)


def choose_split(source: str, source_record_id: str, binary_label: str) -> str:
    key = f"{source}:{source_record_id}:{binary_label}"
    bucket = int(hashlib.sha256(key.encode("utf-8")).hexdigest()[:8], 16) % 100

    start = 0
    for split, width in SPLIT_BUCKETS:
        if start <= bucket < start + width:
            return split
        start += width
    return "test"


def main() -> None:
    if not INPUT.exists():
        raise SystemExit(f"Missing input dataset: {INPUT}")

    with INPUT.open(newline="", encoding="utf-8", errors="ignore") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames or []
        rows = list(reader)

    counts = Counter()
    by_split_label = defaultdict(Counter)
    by_split_source = defaultdict(Counter)

    outputs = {
        "train": TRAIN,
        "val": VAL,
        "test": TEST,
    }

    grouped_rows = {"train": [], "val": [], "test": []}
    for row in rows:
        split = choose_split(row["source"], row["source_record_id"], row["binary_label"])
        grouped_rows[split].append(row)
        counts[split] += 1
        by_split_label[split][row["binary_label"]] += 1
        by_split_source[split][row["source"]] += 1

    for split, path in outputs.items():
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(grouped_rows[split])

    lines = [
        "# Binary Split Summary",
        "",
        f"- Total rows: {sum(counts.values())}",
        f"- Train rows: {counts['train']}",
        f"- Val rows: {counts['val']}",
        f"- Test rows: {counts['test']}",
        "",
        "## Label Counts By Split",
    ]

    for split in ("train", "val", "test"):
        lines.append(f"- {split}: {dict(by_split_label[split])}")

    lines.extend(["", "## Source Counts By Split"])
    for split in ("train", "val", "test"):
        lines.append(f"- {split}: {dict(by_split_source[split])}")

    SUMMARY.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Wrote {TRAIN}")
    print(f"Wrote {VAL}")
    print(f"Wrote {TEST}")
    print(f"Wrote {SUMMARY}")
    print(f"Split counts: {dict(counts)}")


if __name__ == "__main__":
    main()

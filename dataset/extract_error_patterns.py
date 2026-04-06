from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from skills.error_patterns.skill import (
    PATTERNS_PATH,
    extract_subject_keywords,
    normalize_subject,
)


DEFAULT_INPUT = PROJECT_ROOT / "dataset" / "processed" / "skill_eval_results.jsonl"
DEFAULT_REPORT = PROJECT_ROOT / "dataset" / "reports" / "error_patterns_report.md"

LEGACY_FALSE_POSITIVE_SOURCES = {
    "enron",
}

LEGACY_FALSE_POSITIVE_DOMAINS = {
    "enron.com",
    "mailman.enron.com",
    "calpx.com",
    "nisource.com",
    "columbiaenergygroup.com",
    "bracepatt.com",
    "monkey.org",
}


def is_modern_relevant_exact_pattern(record: dict, error_type: str) -> bool:
    sender_domain = (record.get("sender_domain") or "").strip().lower()
    source = (record.get("source") or "").strip().lower()

    if error_type == "false_positive":
        if source in LEGACY_FALSE_POSITIVE_SOURCES:
            return False
        if sender_domain in LEGACY_FALSE_POSITIVE_DOMAINS:
            return False

    return True


def is_modern_relevant_template_record(record: dict) -> bool:
    sender_domain = (record.get("sender_domain") or "").strip().lower()
    source = (record.get("source") or "").strip().lower()

    if source in LEGACY_FALSE_POSITIVE_SOURCES:
        return False
    if sender_domain in LEGACY_FALSE_POSITIVE_DOMAINS:
        return False
    return True


def load_records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def make_group_key(record: dict) -> tuple:
    keywords = tuple(extract_subject_keywords(record.get("subject", ""))[:2])
    return (
        record.get("error_type"),
        record.get("sender_domain") or "",
        keywords,
        record.get("predicted_verdict") or "",
        record.get("rspamd_risk_level") or "",
        record.get("header_risk_level") or "",
        record.get("urgency_label") or "",
        record.get("url_risk_level") or "",
    )


def pattern_from_key(
    key: tuple,
    *,
    error_count: int,
    total_count: int,
    example: dict,
    index: int,
) -> dict:
    (
        error_type,
        sender_domain,
        keywords,
        predicted_verdict,
        rspamd_risk_level,
        header_risk_level,
        urgency_label,
        url_risk_level,
    ) = key
    subject_normalized = normalize_subject(example.get("subject", ""))
    suggested_verdict = "benign" if error_type == "false_positive" else "suspicious"
    return {
        "id": f"pattern-{index:04d}",
        "pattern_type": error_type,
        "suggested_verdict": suggested_verdict,
        "current_verdict": predicted_verdict,
        "sender_domain": sender_domain,
        "subject_normalized": subject_normalized,
        "subject_keywords": list(keywords),
        "rspamd_risk_level": rspamd_risk_level or None,
        "header_risk_level": header_risk_level or None,
        "urgency_label": urgency_label or None,
        "url_risk_level": url_risk_level or None,
        "occurrences": error_count,
        "error_rate": round(error_count / total_count, 4) if total_count else 0.0,
        "example_subject": example.get("subject", ""),
        "example_from_address": example.get("sender", ""),
        "notes": (
            "Auto-extracted from dataset batch evaluation. "
            f"Observed {error_count}/{total_count} errors for this pattern."
        ),
    }


def extract_patterns(records: list[dict]) -> list[dict]:
    totals = Counter()
    errors = Counter()
    examples: dict[tuple, dict] = {}

    for record in records:
        key = make_group_key(record)
        totals[key] += 1
        if key not in examples:
            examples[key] = record
        if record.get("error_type") in {"false_positive", "false_negative"}:
            errors[key] += 1

    patterns: list[dict] = []
    index = 1
    for key, error_count in errors.items():
        total_count = totals[key]
        error_type = key[0]
        sender_domain = key[1]
        keywords = key[2]
        if error_count < 2:
            continue
        if total_count <= 0 or (error_count / total_count) < 0.8:
            continue
        if not sender_domain and not keywords:
            continue
        if not is_modern_relevant_exact_pattern(examples[key], error_type):
            continue
        patterns.append(
            pattern_from_key(
                key,
                error_count=error_count,
                total_count=total_count,
                example=examples[key],
                index=index,
            )
        )
        index += 1

    patterns.sort(key=lambda item: (-item["occurrences"], -item["error_rate"], item["id"]))
    template_patterns = build_keyword_template_patterns(records, start_index=len(patterns) + 1)
    patterns.extend(template_patterns)
    patterns.sort(key=lambda item: (-item["occurrences"], -item["error_rate"], item["id"]))
    return patterns


def build_keyword_template_patterns(records: list[dict], *, start_index: int) -> list[dict]:
    candidate_records = [record for record in records if is_modern_relevant_template_record(record)]
    errors = [record for record in candidate_records if record.get("error_type") == "false_negative"]
    groups = [
        ("account_update_low_signal", {"account", "update"}, "suspicious"),
        ("mailbox_helpdesk_low_signal", {"mailbox", "desk"}, "suspicious"),
        ("payment_transfer_low_signal", {"payment", "transfer"}, "suspicious"),
        ("usaa_account_low_signal", {"usaa", "account"}, "suspicious"),
        ("usaa_checking_low_signal", {"usaa", "checking"}, "suspicious"),
    ]

    patterns: list[dict] = []
    index = start_index
    for name, required_keywords, suggested_verdict in groups:
        matched = []
        total_candidates = []
        for record in candidate_records:
            keywords = set(extract_subject_keywords(record.get("subject", ""), limit=8))
            if required_keywords.issubset(keywords):
                total_candidates.append(record)
                if record.get("error_type") == "false_negative":
                    matched.append(record)

        if len(matched) < 2 or not total_candidates:
            continue
        error_rate = len(matched) / len(total_candidates)
        if error_rate < 0.75:
            continue

        example = matched[0]
        patterns.append(
            {
                "id": f"template-{index:04d}",
                "pattern_type": "false_negative",
                "template_kind": "keyword_template",
                "suggested_verdict": suggested_verdict,
                "current_verdict": str(example.get("predicted_verdict") or "benign"),
                "sender_domain": "",
                "subject_normalized": "",
                "subject_keywords": sorted(required_keywords),
                "required_keywords": sorted(required_keywords),
                "rspamd_risk_level": "low",
                "header_risk_level": "unknown",
                "urgency_label": None,
                "url_risk_level": "low",
                "occurrences": len(matched),
                "error_rate": round(error_rate, 4),
                "example_subject": example.get("subject", ""),
                "example_from_address": example.get("sender", ""),
                "notes": (
                    "Generalized keyword template extracted from repeated false negatives with low-signal scanners. "
                    f"Matched {len(matched)}/{len(total_candidates)} candidate emails."
                ),
            }
        )
        index += 1
    return patterns


def write_report(patterns: list[dict], records: list[dict], report_path: Path) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    counts = Counter(record["error_type"] for record in records)
    domain_counts = Counter((pattern.get("sender_domain") or "-") for pattern in patterns)
    lines = [
        "# Error Pattern Extraction Report",
        "",
        f"- Evaluated rows: {len(records)}",
        f"- Correct rows: {counts.get('correct', 0)}",
        f"- False positives: {counts.get('false_positive', 0)}",
        f"- False negatives: {counts.get('false_negative', 0)}",
        f"- Extracted patterns: {len(patterns)}",
        "",
        "## Top Pattern Domains",
    ]
    for domain, count in domain_counts.most_common(15):
        lines.append(f"- {domain}: {count}")
    lines += [
        "",
        "## Top Patterns",
    ]
    for pattern in patterns[:20]:
        lines.append(
            f"- {pattern['id']}: {pattern['pattern_type']} -> {pattern['suggested_verdict']} | "
            f"domain={pattern['sender_domain'] or '-'} | subject={pattern['subject_normalized'] or '-'} | "
            f"occurrences={pattern['occurrences']} | error_rate={pattern['error_rate']}"
        )
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=str(DEFAULT_INPUT))
    parser.add_argument("--report", default=str(DEFAULT_REPORT))
    parser.add_argument("--output", default=str(PATTERNS_PATH))
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    records = load_records(input_path)
    patterns = extract_patterns(records)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(patterns, indent=2), encoding="utf-8")
    write_report(patterns, records, Path(args.report))
    print(f"Wrote {output_path}")
    print(f"Extracted patterns: {len(patterns)}")


if __name__ == "__main__":
    main()

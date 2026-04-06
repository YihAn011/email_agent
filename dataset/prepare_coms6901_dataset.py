import ast
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse


csv.field_size_limit(sys.maxsize)

ROOT = Path(__file__).resolve().parent
RAW_DIR = ROOT / "raw"
PROCESSED_DIR = ROOT / "processed"

FULL_OUTPUT = PROCESSED_DIR / "normalized_dataset.csv"
BINARY_OUTPUT = PROCESSED_DIR / "spam_binary_dataset.csv"
SUMMARY_OUTPUT = PROCESSED_DIR / "dataset_summary.md"


FULL_COLUMNS = [
    "source",
    "source_record_id",
    "source_label",
    "normalized_label",
    "binary_label",
    "include_in_binary_training",
    "subject",
    "sender",
    "sender_domain",
    "receiver",
    "receiver_domain",
    "date",
    "email_text",
    "num_urls",
    "has_ip_url",
    "email_length",
    "num_exclamation_marks",
    "num_links_in_body",
    "is_html_email",
    "url_domains",
    "attachment_count",
    "has_attachments",
    "content_types",
    "language",
]


def extract_domain(email: str) -> str:
    text = (email or "").strip().lower()
    if "@" not in text:
        return ""
    domain = text.split("@")[-1]
    return domain.replace(">", "").replace("<", "").strip()


def parse_url_list(value: str) -> list[str]:
    if not value:
        return []
    text = str(value).strip()
    if not text:
        return []
    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = ast.literal_eval(text)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except (ValueError, SyntaxError):
            pass
    return re.findall(r"https?://[^\s,'\"\]]+", text)


def extract_urls(text: str) -> list[str]:
    if not text:
        return []
    return re.findall(r"https?://[^\s,'\"\]]+", str(text))


def url_domains(urls: Iterable[str]) -> list[str]:
    domains: list[str] = []
    for url in urls:
        try:
            parsed = urlparse(url)
        except ValueError:
            continue
        domain = parsed.netloc.lower().strip()
        if domain:
            domains.append(domain)
    return sorted(set(domains))


def has_ip_url(urls: Iterable[str]) -> int:
    ip_pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    return int(any(ip_pattern.search(url or "") for url in urls))


def normalize_label(source: str, raw_label: str) -> tuple[str, int, int]:
    text = (raw_label or "").strip().lower()

    if source == "github":
        if text in {"valid", "legitimate", "ham"}:
            return "legitimate", 0, 1
        if text == "spam":
            return "spam", 1, 1
        if text in {"phishing", "phishing simulation"}:
            return "phishing", 1, 1
        return "unknown", -1, 0

    if source == "nazario":
        if text == "1":
            return "phishing", 1, 1
        if text == "0":
            return "legitimate", 0, 1
        return "unknown", -1, 0

    if source == "spamassassin":
        if text == "1":
            return "spam", 1, 1
        if text == "0":
            return "legitimate", 0, 1
        return "unknown", -1, 0

    if source == "meajor":
        if text == "1.0":
            return "spam", 1, 1
        if text == "0.0":
            return "legitimate", 0, 1
        return "unknown", -1, 0

    if source == "enron":
        if text == "1":
            # These are fraud-oriented positives, not classic inbox spam.
            return "fraud_internal", 1, 0
        if text == "0":
            return "legitimate", 0, 1
        return "unknown", -1, 0

    return "unknown", -1, 0


def build_row(
    *,
    source: str,
    source_record_id: str,
    raw_label: str,
    subject: str,
    sender: str,
    receiver: str,
    date: str,
    email_text: str,
    content_types: str = "",
    language: str = "",
    urls_value: str = "",
    attachment_count: str = "",
    has_attachments: str = "",
) -> dict[str, object]:
    normalized, binary_label, include_in_binary = normalize_label(source, raw_label)
    combined_urls = sorted(set(parse_url_list(urls_value) + extract_urls(email_text)))
    sender_domain = extract_domain(sender)
    receiver_domain = extract_domain(receiver)

    email_text = email_text or ""
    attachment_count = attachment_count or "0"
    has_attachments = has_attachments or "0"

    return {
        "source": source,
        "source_record_id": source_record_id,
        "source_label": raw_label,
        "normalized_label": normalized,
        "binary_label": binary_label,
        "include_in_binary_training": include_in_binary,
        "subject": subject or "",
        "sender": sender or "",
        "sender_domain": sender_domain,
        "receiver": receiver or "",
        "receiver_domain": receiver_domain,
        "date": date or "",
        "email_text": email_text,
        "num_urls": len(combined_urls),
        "has_ip_url": has_ip_url(combined_urls),
        "email_length": len(email_text),
        "num_exclamation_marks": email_text.count("!"),
        "num_links_in_body": email_text.lower().count("http"),
        "is_html_email": int(bool(re.search(r"<html|<body|<a", email_text, re.I))),
        "url_domains": "|".join(url_domains(combined_urls)),
        "attachment_count": attachment_count,
        "has_attachments": has_attachments,
        "content_types": content_types or "",
        "language": language or "",
    }


def iter_nazario() -> Iterable[dict[str, object]]:
    path = RAW_DIR / "Nazario_5.csv"
    with path.open(newline="", encoding="utf-8", errors="ignore") as handle:
        reader = csv.DictReader(handle)
        for idx, row in enumerate(reader, start=1):
            yield build_row(
                source="nazario",
                source_record_id=str(idx),
                raw_label=row.get("label", ""),
                subject=row.get("subject", ""),
                sender=row.get("sender", ""),
                receiver=row.get("receiver", ""),
                date=row.get("date", ""),
                email_text=row.get("body", ""),
                urls_value=row.get("urls", ""),
            )


def iter_spamassassin() -> Iterable[dict[str, object]]:
    path = RAW_DIR / "email_text.csv"
    with path.open(newline="", encoding="utf-8", errors="ignore") as handle:
        reader = csv.DictReader(handle)
        for idx, row in enumerate(reader, start=1):
            yield build_row(
                source="spamassassin",
                source_record_id=str(idx),
                raw_label=row.get("label", ""),
                subject="",
                sender="",
                receiver="",
                date="",
                email_text=row.get("text", ""),
            )


def iter_enron() -> Iterable[dict[str, object]]:
    path = RAW_DIR / "enron_data_fraud_labeled.csv"
    with path.open(newline="", encoding="utf-8", errors="ignore") as handle:
        reader = csv.DictReader(handle)
        for idx, row in enumerate(reader, start=1):
            yield build_row(
                source="enron",
                source_record_id=row.get("Mail-ID", str(idx)),
                raw_label=row.get("Label", ""),
                subject=row.get("Subject", ""),
                sender=row.get("From", ""),
                receiver=row.get("To", ""),
                date=row.get("Date", ""),
                email_text=row.get("Body", ""),
                content_types=row.get("Content-Type", ""),
            )


def iter_github() -> Iterable[dict[str, object]]:
    path = RAW_DIR / "github_phishing_emails.json"
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    for row in data:
        yield build_row(
            source="github",
            source_record_id=str(row.get("No.", "")),
            raw_label=row.get("Type", ""),
            subject=row.get("Subject", ""),
            sender=row.get("Sender", ""),
            receiver="",
            date=str(row.get("Year", "")),
            email_text=row.get("Body", ""),
            urls_value=row.get("URL(s)", ""),
        )


def iter_meajor() -> Iterable[dict[str, object]]:
    path = RAW_DIR / "meajor.csv"
    with path.open(newline="", encoding="utf-8", errors="ignore") as handle:
        reader = csv.DictReader(handle)
        for idx, row in enumerate(reader, start=1):
            yield build_row(
                source="meajor",
                source_record_id=str(idx),
                raw_label=row.get("label", ""),
                subject=row.get("subject", ""),
                sender=row.get("sender", ""),
                receiver=row.get("receiver", ""),
                date=row.get("date", ""),
                email_text=row.get("body", ""),
                content_types=row.get("content_types", ""),
                language=row.get("language", ""),
                urls_value=row.get("urls", ""),
                attachment_count=row.get("attachment_count", ""),
                has_attachments=row.get("has_attachments", ""),
            )


def write_outputs() -> dict[str, object]:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    stats = {
        "full_rows": 0,
        "binary_rows": 0,
        "source_counts": Counter(),
        "label_counts": Counter(),
        "binary_label_counts": Counter(),
        "source_label_counts": defaultdict(Counter),
    }

    generators = [
        iter_nazario(),
        iter_spamassassin(),
        iter_enron(),
        iter_github(),
        iter_meajor(),
    ]

    with FULL_OUTPUT.open("w", newline="", encoding="utf-8") as full_handle, BINARY_OUTPUT.open(
        "w", newline="", encoding="utf-8"
    ) as binary_handle:
        full_writer = csv.DictWriter(full_handle, fieldnames=FULL_COLUMNS)
        binary_writer = csv.DictWriter(binary_handle, fieldnames=FULL_COLUMNS)
        full_writer.writeheader()
        binary_writer.writeheader()

        for generator in generators:
            for row in generator:
                full_writer.writerow(row)
                stats["full_rows"] += 1
                stats["source_counts"][row["source"]] += 1
                stats["label_counts"][row["normalized_label"]] += 1
                stats["source_label_counts"][row["source"]][row["normalized_label"]] += 1

                if row["include_in_binary_training"] == 1 and row["binary_label"] in {0, 1}:
                    binary_writer.writerow(row)
                    stats["binary_rows"] += 1
                    stats["binary_label_counts"][row["binary_label"]] += 1

    return stats


def write_summary(stats: dict[str, object]) -> None:
    lines = [
        "# Dataset Summary",
        "",
        f"- Full normalized rows: {stats['full_rows']}",
        f"- Binary training rows: {stats['binary_rows']}",
        "",
        "## Full Label Counts",
    ]

    for label, count in stats["label_counts"].most_common():
        lines.append(f"- {label}: {count}")

    lines.extend(["", "## Binary Label Counts"])
    for label, count in sorted(stats["binary_label_counts"].items()):
        lines.append(f"- {label}: {count}")

    lines.extend(["", "## Per-Source Label Counts"])
    for source, counter in sorted(stats["source_label_counts"].items()):
        lines.append(f"- {source}:")
        for label, count in counter.most_common():
            lines.append(f"  - {label}: {count}")

    lines.extend(
        [
            "",
            "## Notes",
            "- `fraud_internal` positives from Enron are preserved in the full dataset but excluded from the binary spam-training export.",
            "- The binary export only keeps rows with reliable `legitimate`, `spam`, or `phishing` semantics.",
        ]
    )

    SUMMARY_OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    stats = write_outputs()
    write_summary(stats)
    print(f"Wrote {FULL_OUTPUT}")
    print(f"Wrote {BINARY_OUTPUT}")
    print(f"Wrote {SUMMARY_OUTPUT}")
    print(f"Full rows: {stats['full_rows']}")
    print(f"Binary rows: {stats['binary_rows']}")
    print(f"Full labels: {dict(stats['label_counts'])}")
    print(f"Binary labels: {dict(stats['binary_label_counts'])}")


if __name__ == "__main__":
    main()

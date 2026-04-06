from __future__ import annotations

import argparse
import csv
import json
import sys
from email.message import EmailMessage
from pathlib import Path

csv.field_size_limit(sys.maxsize)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from skills.header_auth.schemas import EmailHeaderAuthCheckInput
from skills.header_auth.skill import EmailHeaderAuthCheckSkill
from skills.imap_monitor.skill import _compose_final_verdict
from skills.rspamd.schemas import RspamdScanEmailInput
from skills.rspamd.skill import RspamdScanEmailSkill
from skills.urgency.schemas import UrgencyCheckInput
from skills.urgency.skill import UrgencyCheckSkill
from skills.url_reputation.schemas import UrlReputationInput
from skills.url_reputation.skill import UrlReputationSkill


DEFAULT_INPUT = PROJECT_ROOT / "dataset" / "processed" / "spam_binary_test.csv"
DEFAULT_OUTPUT = PROJECT_ROOT / "dataset" / "processed" / "skill_eval_results.jsonl"


def build_raw_email(row: dict[str, str]) -> str:
    def clean_header(value: str, fallback: str) -> str:
        text = (value or "").replace("\r", " ").replace("\n", " ").strip()
        return text or fallback

    msg = EmailMessage()
    msg["From"] = clean_header(row.get("sender", ""), "unknown@example.com")
    msg["To"] = clean_header(row.get("receiver", ""), "recipient@example.com")
    if row.get("date"):
        msg["Date"] = clean_header(row["date"], "")
    msg["Subject"] = clean_header(row.get("subject", ""), "(no subject)")
    msg["Message-ID"] = f"<dataset-{row.get('source','unknown')}-{row.get('source_record_id','0')}@email-agent.local>"
    msg.set_content(row.get("email_text") or "")
    return msg.as_string()


def evaluate_row(
    row: dict[str, str],
    *,
    rspamd_skill: RspamdScanEmailSkill,
    header_skill: EmailHeaderAuthCheckSkill,
    urgency_skill: UrgencyCheckSkill,
    url_skill: UrlReputationSkill,
) -> dict[str, object]:
    raw_email = build_raw_email(row)
    rspamd_result = rspamd_skill.run(
        RspamdScanEmailInput(raw_email=raw_email, include_raw_result=False)
    )
    header_result = header_skill.run(
        EmailHeaderAuthCheckInput(raw_email=raw_email, include_raw_headers=False)
    )
    urgency_result = urgency_skill.run(
        UrgencyCheckInput(subject=row.get("subject", ""), email_text=row.get("email_text", ""))
    )
    url_result = url_skill.run(
        UrlReputationInput(
            subject=row.get("subject", ""),
            email_text=row.get("email_text", ""),
            num_urls=int(float(row.get("num_urls", 0) or 0)),
            has_ip_url=int(float(row.get("has_ip_url", 0) or 0)),
            email_length=int(float(row.get("email_length", 0) or 0)),
            num_exclamation_marks=int(float(row.get("num_exclamation_marks", 0) or 0)),
            num_links_in_body=int(float(row.get("num_links_in_body", 0) or 0)),
            is_html_email=int(float(row.get("is_html_email", 0) or 0)),
            attachment_count=int(float(row.get("attachment_count", 0) or 0)),
            has_attachments=int(float(row.get("has_attachments", 0) or 0)),
        )
    )

    predicted_verdict, summary = _compose_final_verdict(rspamd_result, header_result)
    predicted_binary = 0 if predicted_verdict == "benign" else 1
    actual_binary = int(row["binary_label"])

    if actual_binary == 0 and predicted_binary == 1:
        error_type = "false_positive"
    elif actual_binary == 1 and predicted_binary == 0:
        error_type = "false_negative"
    else:
        error_type = "correct"

    return {
        "source": row.get("source", ""),
        "source_record_id": row.get("source_record_id", ""),
        "actual_binary": actual_binary,
        "actual_label": row.get("normalized_label", ""),
        "predicted_binary": predicted_binary,
        "predicted_verdict": predicted_verdict,
        "error_type": error_type,
        "subject": row.get("subject", ""),
        "sender": row.get("sender", ""),
        "sender_domain": row.get("sender_domain", ""),
        "rspamd_ok": rspamd_result.ok,
        "rspamd_risk_level": rspamd_result.data.risk_level if rspamd_result.ok and rspamd_result.data else None,
        "rspamd_score": rspamd_result.data.score if rspamd_result.ok and rspamd_result.data else None,
        "rspamd_action": rspamd_result.data.action if rspamd_result.ok and rspamd_result.data else None,
        "header_ok": header_result.ok,
        "header_risk_level": header_result.data.risk_level if header_result.ok and header_result.data else None,
        "urgency_ok": urgency_result.ok,
        "urgency_label": urgency_result.data.urgency_label if urgency_result.ok and urgency_result.data else None,
        "urgency_score": urgency_result.data.urgency_score if urgency_result.ok and urgency_result.data else None,
        "url_ok": url_result.ok,
        "url_risk_level": url_result.data.risk_level if url_result.ok and url_result.data else None,
        "url_score": url_result.data.phishing_score if url_result.ok and url_result.data else None,
        "summary": summary,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=str(DEFAULT_INPUT))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--limit", type=int, default=0, help="Optional row limit for incremental runs.")
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument(
        "--append",
        action="store_true",
        help="Append to an existing output file and resume from its non-empty line count.",
    )
    parser.add_argument("--progress-every", type=int, default=50)
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    effective_offset = args.offset
    mode = "w"
    if args.append and output_path.exists():
        with output_path.open(encoding="utf-8", errors="ignore") as existing:
            completed = sum(1 for line in existing if line.strip())
        effective_offset += completed
        mode = "a"
        print(
            f"Resuming from existing output: completed={completed}, effective_offset={effective_offset}",
            flush=True,
        )

    rspamd_skill = RspamdScanEmailSkill()
    header_skill = EmailHeaderAuthCheckSkill()
    urgency_skill = UrgencyCheckSkill()
    url_skill = UrlReputationSkill()

    processed = 0
    with input_path.open(newline="", encoding="utf-8", errors="ignore") as handle, output_path.open(
        mode, encoding="utf-8"
    ) as out:
        reader = csv.DictReader(handle)
        for idx, row in enumerate(reader):
            if idx < effective_offset:
                continue
            if args.limit and processed >= args.limit:
                break
            record = evaluate_row(
                row,
                rspamd_skill=rspamd_skill,
                header_skill=header_skill,
                urgency_skill=urgency_skill,
                url_skill=url_skill,
            )
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            out.flush()
            processed += 1
            if processed % args.progress_every == 0:
                print(
                    f"processed={processed} total_offset={effective_offset + processed}",
                    flush=True,
                )

    print(f"Wrote {output_path}")
    print(f"Processed rows: {processed}")


if __name__ == "__main__":
    main()

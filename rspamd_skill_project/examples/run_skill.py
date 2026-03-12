from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from skills.rspamd.schemas import RspamdScanEmailInput
from skills.rspamd.skill import RspamdScanEmailSkill


SAMPLE_EMAIL = """Return-Path: <do-not-reply@jobs.amazon.com>
From: do-not-reply@jobs.amazon.com
To: xx2211@columbia.edu
Subject: Please share your feedback: Your recent interview experience at Amazon
Date: Mon, 09 Mar 2026 12:03:00 -0500
Message-ID: <example-msgid-20260309@amazonses.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Reminder: Share your feedback

Dear xx2211,

A quick reminder to share your feedback about your recent interview at Amazon.

This 5-minute survey will help improve our interview process. Your responses will have no impact on your interview outcome.

Get started

We appreciate your time and feedback.

The Amazon Recruiting Team

By clicking on the survey link, you are agreeing to the terms in the Amazon privacy policy.
Click here to unsubscribe from future survey invitations.
"""


def preflight_check(base_url: str, timeout_seconds: float = 5.0) -> None:
    """Verify rspamd /checkv2 is reachable before running the full demo."""
    probe_email = "From: probe@example.com\nTo: probe@example.com\nSubject: probe\n\nhealth-check\n"
    try:
        response = httpx.post(
            f"{base_url.rstrip('/')}/checkv2",
            content=probe_email.encode("utf-8"),
            headers={"Content-Type": "message/rfc822"},
            timeout=timeout_seconds,
        )
    except httpx.RequestError as exc:
        raise RuntimeError(
            "Cannot connect to rspamd.\n"
            f"Base URL: {base_url}\n"
            "Please make sure rspamd is running, for example:\n"
            "  sudo apt install -y rspamd redis-server\n"
            "  sudo systemctl enable --now redis-server rspamd\n"
            f"Original error: {exc}"
        ) from exc

    if response.status_code >= 400:
        raise RuntimeError(
            "rspamd responded with an error during preflight check.\n"
            f"Base URL: {base_url}\n"
            f"HTTP: {response.status_code}\n"
            f"Body (first 300 chars): {response.text[:300]}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run rspamd skill against a real rspamd instance.")
    parser.add_argument(
        "--base-url",
        default=os.getenv("RSPAMD_BASE_URL", "http://127.0.0.1:11333"),
        help="Rspamd base URL (default: env RSPAMD_BASE_URL or http://127.0.0.1:11333).",
    )
    parser.add_argument(
        "--skip-preflight",
        action="store_true",
        help="Skip connectivity preflight check.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    base_url = args.base_url

    if not args.skip_preflight:
        preflight_check(base_url=base_url)

    skill = RspamdScanEmailSkill(base_url=base_url)

    payload = RspamdScanEmailInput(
        raw_email=SAMPLE_EMAIL,
        mail_from="do-not-reply@jobs.amazon.com",
        rcpt_to=["xx2211@columbia.edu"],
        helo="amazonses.com",
        hostname="amazonses.com",
        log_tag="amazon-feedback-demo-001",
        timeout_seconds=15,
        include_raw_result=True,
    )

    result = skill.run(payload)
    print(f"Using rspamd endpoint: {base_url.rstrip('/')}/checkv2")
    print(json.dumps(result.model_dump(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

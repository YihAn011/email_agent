from __future__ import annotations

import os
from typing import Any

from mcp.server.fastmcp import FastMCP

from skills.header_auth.schemas import EmailHeaderAuthCheckInput
from skills.header_auth.skill import EmailHeaderAuthCheckSkill
from skills.rspamd.schemas import RspamdScanEmailInput
from skills.rspamd.skill import RspamdScanEmailSkill


DEFAULT_BASE_URL = os.getenv("RSPAMD_BASE_URL", "http://127.0.0.1:11333")

mcp = FastMCP(
    name="rspamd-email-skill",
    instructions=(
        "Use rspamd_scan_email to scan RFC822 raw emails with rspamd, and "
        "email_header_auth_check to quickly triage header authentication signals."
    ),
)


@mcp.tool(
    name="rspamd_scan_email",
    description=(
        "Scan an RFC822 raw email with rspamd /checkv2 and return normalized "
        "security signals."
    ),
)
def rspamd_scan_email(
    raw_email: str,
    mail_from: str | None = None,
    rcpt_to: list[str] | None = None,
    ip: str | None = None,
    helo: str | None = None,
    hostname: str | None = None,
    log_tag: str | None = None,
    timeout_seconds: float = 15.0,
    include_raw_result: bool = True,
    base_url: str | None = None,
) -> dict[str, Any]:
    """MCP tool wrapper around the existing RspamdScanEmailSkill."""
    payload = RspamdScanEmailInput(
        raw_email=raw_email,
        mail_from=mail_from,
        rcpt_to=rcpt_to or [],
        ip=ip,
        helo=helo,
        hostname=hostname,
        log_tag=log_tag,
        timeout_seconds=timeout_seconds,
        include_raw_result=include_raw_result,
    )

    skill = RspamdScanEmailSkill(base_url=base_url or DEFAULT_BASE_URL)
    result = skill.run(payload)
    return result.model_dump()


@mcp.tool(
    name="email_header_auth_check",
    description=(
        "Parse email headers only (ignores body) and return lightweight authentication/"
        "routing signals based on common headers like Authentication-Results and DKIM-Signature."
    ),
)
def email_header_auth_check(
    raw_email: str | None = None,
    raw_headers: str | None = None,
    include_raw_headers: bool = False,
) -> dict[str, Any]:
    """MCP tool wrapper around the EmailHeaderAuthCheckSkill."""
    payload = EmailHeaderAuthCheckInput(
        raw_email=raw_email,
        raw_headers=raw_headers,
        include_raw_headers=include_raw_headers,
    )
    skill = EmailHeaderAuthCheckSkill()
    result = skill.run(payload)
    return result.model_dump()


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

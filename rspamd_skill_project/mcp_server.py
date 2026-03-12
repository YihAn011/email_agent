from __future__ import annotations

import os
from typing import Any

from mcp.server.fastmcp import FastMCP

from skills.rspamd.schemas import RspamdScanEmailInput
from skills.rspamd.skill import RspamdScanEmailSkill


DEFAULT_BASE_URL = os.getenv("RSPAMD_BASE_URL", "http://127.0.0.1:11333")

mcp = FastMCP(
    name="rspamd-email-skill",
    instructions=(
        "Use rspamd_scan_email to scan RFC822 raw emails and return normalized "
        "spam/phishing/security signals."
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


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

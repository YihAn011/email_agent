from __future__ import annotations

from typing import Any, Dict, Optional

import httpx


class RspamdClientError(Exception):
    pass


class RspamdConnectionError(RspamdClientError):
    pass


class RspamdResponseError(RspamdClientError):
    pass


class RspamdClient:
    def __init__(self, base_url: str, default_timeout: float = 15.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.default_timeout = default_timeout

    def scan_email(
        self,
        raw_email: str,
        mail_from: Optional[str] = None,
        rcpt_to: Optional[list[str]] = None,
        ip: Optional[str] = None,
        helo: Optional[str] = None,
        hostname: Optional[str] = None,
        log_tag: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
    ) -> Dict[str, Any]:
        headers = {
            "Content-Type": "message/rfc822",
        }

        if mail_from:
            headers["From"] = mail_from
        if ip:
            headers["Ip"] = ip
        if helo:
            headers["Helo"] = helo
        if hostname:
            headers["Hostname"] = hostname
        if log_tag:
            headers["Log-Tag"] = log_tag
        if rcpt_to:
            headers["Rcpt"] = ",".join(rcpt_to)

        timeout = timeout_seconds if timeout_seconds is not None else self.default_timeout

        try:
            response = httpx.post(
                f"{self.base_url}/checkv2",
                content=raw_email.encode("utf-8"),
                headers=headers,
                timeout=timeout,
            )
        except httpx.RequestError as exc:
            raise RspamdConnectionError(f"Failed to connect to Rspamd: {exc}") from exc

        if response.status_code >= 400:
            raise RspamdResponseError(
                f"Rspamd returned HTTP {response.status_code}: {response.text[:500]}"
            )

        try:
            return response.json()
        except ValueError as exc:
            raise RspamdResponseError("Rspamd returned non-JSON response") from exc

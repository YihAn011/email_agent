from __future__ import annotations

import os
from datetime import datetime, timezone
from time import perf_counter

from skills.base_skill import BaseSkill, SkillError, SkillMeta, SkillResult

from .client import RspamdClient, RspamdConnectionError, RspamdResponseError
from .normalize import normalize_rspamd_result
from .schemas import RspamdNormalizedResult, RspamdScanEmailInput


class RspamdScanEmailSkill(BaseSkill[RspamdScanEmailInput, RspamdNormalizedResult]):
    name = "rspamd_scan_email"
    description = "Scan an email with Rspamd and return normalized spam/phishing/security signals."
    version = "0.1.0"

    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = base_url or os.getenv("RSPAMD_BASE_URL", "http://localhost:11333")
        self.client = RspamdClient(base_url=self.base_url)

    def run(self, payload: RspamdScanEmailInput) -> SkillResult[RspamdNormalizedResult]:
        start = perf_counter()
        timestamp_utc = datetime.now(timezone.utc).isoformat()

        try:
            raw_result = self.client.scan_email(
                raw_email=payload.raw_email,
                mail_from=payload.mail_from,
                rcpt_to=payload.rcpt_to,
                ip=payload.ip,
                helo=payload.helo,
                hostname=payload.hostname,
                log_tag=payload.log_tag,
                timeout_seconds=payload.timeout_seconds,
            )

            normalized = normalize_rspamd_result(
                raw_result=raw_result,
                include_raw_result=payload.include_raw_result,
            )

            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=True,
                data=normalized,
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                    endpoint=f"{self.base_url}/checkv2",
                    service_version=str(raw_result.get("version")) if raw_result.get("version") else None,
                ),
            )

        except ValueError as exc:
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=False,
                error=SkillError(
                    type="validation_error",
                    message=str(exc),
                    retryable=False,
                ),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                    endpoint=f"{self.base_url}/checkv2",
                ),
            )
        except RspamdConnectionError as exc:
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=False,
                error=SkillError(
                    type="connection_error",
                    message=str(exc),
                    retryable=True,
                ),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                    endpoint=f"{self.base_url}/checkv2",
                ),
            )
        except RspamdResponseError as exc:
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=False,
                error=SkillError(
                    type="response_error",
                    message=str(exc),
                    retryable=False,
                ),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                    endpoint=f"{self.base_url}/checkv2",
                ),
            )
        except Exception as exc:
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=False,
                error=SkillError(
                    type="unexpected_error",
                    message=str(exc),
                    retryable=False,
                ),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                    endpoint=f"{self.base_url}/checkv2",
                ),
            )

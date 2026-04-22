from __future__ import annotations

from datetime import datetime, timezone
from email import policy
from email.parser import Parser
from email.utils import parseaddr
import re
from time import perf_counter

from skills.base_skill import BaseSkill, SkillError, SkillMeta, SkillResult

from .schemas import EmailHeaderAuthCheckInput, EmailHeaderAuthCheckResult, HeaderFinding

COMMON_SECOND_LEVEL_SUFFIXES = {
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "co.jp",
    "com.au",
    "net.au",
    "org.au",
    "co.nz",
    "com.br",
    "com.mx",
    "co.za",
}
FREEMAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "aol.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
    "gmx.com",
    "mail.com",
}
TRUSTED_BRAND_DOMAINS = {
    "paypal.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "google.com",
    "bankofamerica.com",
    "chase.com",
    "wellsfargo.com",
    "citibank.com",
    "usaa.com",
    "americanexpress.com",
    "amex.com",
}


def _extract_header_block_from_raw_email(raw_email: str) -> str:
    # RFC822 header/body separator is the first blank line.
    # Keep it robust for both \n and \r\n by normalizing to \n for splitting.
    normalized = raw_email.replace("\r\n", "\n")
    parts = normalized.split("\n\n", 1)
    return parts[0].strip("\n")


def _domain_from_addr(addr: str | None) -> str | None:
    if not addr:
        return None
    _, email_addr = parseaddr(addr)
    if "@" not in email_addr:
        return None
    domain = email_addr.split("@", 1)[1].strip().lower()
    return domain or None


def _domain_from_message_id(message_id: str | None) -> str | None:
    if not message_id:
        return None
    s = message_id.strip().lstrip("<").rstrip(">")
    if "@" not in s:
        return None
    domain = s.split("@", 1)[1].strip().lower()
    return domain or None


def _registrable_domain(domain: str | None) -> str | None:
    if not domain:
        return None
    parts = [part for part in domain.strip(".").lower().split(".") if part]
    if len(parts) < 2:
        return domain.lower()
    tail = ".".join(parts[-2:])
    if len(parts) >= 3 and tail in COMMON_SECOND_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    return tail


def _domains_align(left: str | None, right: str | None) -> bool:
    return bool(left and right and _registrable_domain(left) == _registrable_domain(right))


def _sender_looks_like_brand(text: str) -> str | None:
    lowered = (text or "").lower()
    for brand_domain in TRUSTED_BRAND_DOMAINS:
        brand_name = brand_domain.split(".", 1)[0]
        if brand_name in lowered or brand_domain in lowered:
            return brand_domain
    return None


def _parse_authentication_results(headers: list[str]) -> dict[str, str | None]:
    # Extremely lightweight parser: look for "spf=pass", "dkim=fail", etc.
    # Different MTAs format this differently; best-effort only.
    merged = " ".join(h.replace("\n", " ") for h in headers).lower()
    out: dict[str, str | None] = {"spf": None, "dkim": None, "dmarc": None, "arc": None}
    for key in ("spf", "dkim", "dmarc", "arc"):
        # Guard against substring matches (e.g. "arc=" inside "dmarc=").
        m = re.search(rf"(?:^|[;\s]){re.escape(key)}=([a-z0-9_+-]+)", merged)
        if m:
            out[key] = m.group(1)
    return out


def _basic_risk_and_findings(
    *,
    from_domain: str | None,
    reply_to_domain: str | None,
    return_path_domain: str | None,
    message_id_domain: str | None,
    dkim_domains: list[str],
    from_header: str | None,
    reply_to: str | None,
    auth_results: dict[str, str | None],
    authentication_header_count: int,
) -> tuple[str, list[HeaderFinding], list[str]]:
    findings: list[HeaderFinding] = []
    recommended: list[str] = []

    mismatch_domains = {
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
    }
    distinct = {d for d in mismatch_domains.values() if d}
    if len(distinct) >= 2:
        findings.append(
            HeaderFinding(
                type="domain_mismatch",
                severity="medium",
                message="Sender-related domains differ across headers (From/Reply-To/Return-Path).",
                evidence=mismatch_domains,
            )
        )
        recommended.append("url_reputation_check")
        recommended.append("llm_phishing_reasoner")

    if reply_to_domain and from_domain and not _domains_align(reply_to_domain, from_domain):
        findings.append(
            HeaderFinding(
                type="reply_to_mismatch",
                severity="medium",
                message="Reply-To uses a different organizational domain than From.",
                evidence={"from_domain": from_domain, "reply_to_domain": reply_to_domain},
            )
        )

    if return_path_domain and from_domain and not _domains_align(return_path_domain, from_domain):
        findings.append(
            HeaderFinding(
                type="return_path_mismatch",
                severity="medium",
                message="Return-Path uses a different organizational domain than From.",
                evidence={"from_domain": from_domain, "return_path_domain": return_path_domain},
            )
        )

    if message_id_domain and from_domain and not _domains_align(message_id_domain, from_domain):
        findings.append(
            HeaderFinding(
                type="message_id_domain_mismatch",
                severity="low",
                message="Message-ID domain does not align with the visible From domain.",
                evidence={"from_domain": from_domain, "message_id_domain": message_id_domain},
            )
        )

    aligned_dkim_domains = [domain for domain in dkim_domains if _domains_align(domain, from_domain)]
    if dkim_domains and from_domain and not aligned_dkim_domains:
        findings.append(
            HeaderFinding(
                type="dkim_domain_mismatch",
                severity="medium",
                message="DKIM signatures are present but none align with the visible From domain.",
                evidence={"from_domain": from_domain, "dkim_domains": dkim_domains},
            )
        )

    if authentication_header_count == 0 and not dkim_domains:
        findings.append(
            HeaderFinding(
                type="missing_authentication_signals",
                severity="low",
                message="No Authentication-Results or DKIM signatures were present in the header block.",
                evidence={"authentication_header_count": authentication_header_count, "dkim_signature_count": len(dkim_domains)},
            )
        )

    dmarc = auth_results.get("dmarc")
    spf = auth_results.get("spf")
    dkim = auth_results.get("dkim")

    if dmarc in {"fail", "temperror", "permerror"}:
        findings.append(
            HeaderFinding(
                type="dmarc_fail",
                severity="high",
                message=f"DMARC reported as {dmarc}.",
                evidence={"dmarc": dmarc, "spf": spf, "dkim": dkim},
            )
        )
        recommended.append("rspamd_scan_email")
    elif dmarc == "pass":
        findings.append(
            HeaderFinding(
                type="dmarc_pass",
                severity="info",
                message="DMARC reported as pass.",
                evidence={"dmarc": dmarc},
            )
        )

    if spf in {"fail", "softfail"}:
        findings.append(
            HeaderFinding(
                type="spf_not_pass",
                severity="medium" if spf == "softfail" else "high",
                message=f"SPF reported as {spf}.",
                evidence={"spf": spf},
            )
        )

    if dkim in {"fail", "neutral", "temperror", "permerror"}:
        findings.append(
            HeaderFinding(
                type="dkim_not_pass",
                severity="medium",
                message=f"DKIM reported as {dkim}.",
                evidence={"dkim": dkim},
            )
        )

    brand_domain = _sender_looks_like_brand(" ".join(item for item in (from_header, reply_to) if item))
    if brand_domain:
        visible_domains = {domain for domain in (from_domain, reply_to_domain, return_path_domain) if domain}
        if visible_domains and all(not _domains_align(domain, brand_domain) for domain in visible_domains):
            findings.append(
                HeaderFinding(
                    type="brand_impersonation_domain_mismatch",
                    severity="high",
                    message="The sender references a well-known brand, but the sender domains do not align with that brand.",
                    evidence={"brand_domain": brand_domain, "visible_domains": sorted(visible_domains)},
                )
            )
            recommended.append("url_reputation_check")

    if reply_to_domain in FREEMAIL_DOMAINS and from_domain and reply_to_domain != from_domain:
        findings.append(
            HeaderFinding(
                type="freemail_reply_to",
                severity="medium",
                message="Reply-To points to a freemail mailbox instead of the visible sender domain.",
                evidence={"from_domain": from_domain, "reply_to_domain": reply_to_domain},
            )
        )

    risk = "low"
    if any(f.severity == "high" for f in findings):
        risk = "high"
    elif any(f.severity == "medium" for f in findings):
        risk = "medium"
    elif not findings:
        risk = "unknown"

    # Keep it deterministic and minimal.
    recommended = list(dict.fromkeys(recommended))
    return risk, findings, recommended


class EmailHeaderAuthCheckSkill(
    BaseSkill[EmailHeaderAuthCheckInput, EmailHeaderAuthCheckResult]
):
    name = "email_header_auth_check"
    description = "Parse and triage email headers for authentication and routing signals."
    version = "0.1.0"

    def run(self, payload: EmailHeaderAuthCheckInput) -> SkillResult[EmailHeaderAuthCheckResult]:
        start = perf_counter()
        timestamp_utc = datetime.now(timezone.utc).isoformat()

        try:
            raw_headers = (
                payload.raw_headers
                if payload.raw_headers and payload.raw_headers.strip()
                else _extract_header_block_from_raw_email(payload.raw_email or "")
            )

            msg = Parser(policy=policy.default).parsestr(raw_headers + "\n\n")

            from_header = msg.get("From")
            reply_to = msg.get("Reply-To")
            return_path = msg.get("Return-Path")
            message_id = msg.get("Message-ID")

            from_domain = _domain_from_addr(from_header)
            reply_to_domain = _domain_from_addr(reply_to)
            return_path_domain = _domain_from_addr(return_path)
            message_id_domain = _domain_from_message_id(message_id)

            auth_headers = msg.get_all("Authentication-Results", []) or []
            arc_auth_headers = msg.get_all("ARC-Authentication-Results", []) or []
            all_auth_headers = [*auth_headers, *arc_auth_headers]
            auth_results = _parse_authentication_results(all_auth_headers)

            dkim_sigs = msg.get_all("DKIM-Signature", []) or []
            dkim_domains: list[str] = []
            for sig in dkim_sigs:
                # Very lightweight extraction of "d=" tag.
                lower = sig.lower()
                idx = lower.find(" d=")
                if idx == -1:
                    idx = lower.find("d=")
                if idx == -1:
                    continue
                rest = sig[idx:].split("d=", 1)[-1]
                d = rest.split(";", 1)[0].strip().lower()
                if d:
                    dkim_domains.append(d)

            received = msg.get_all("Received", []) or []

            risk_level, findings, recommended = _basic_risk_and_findings(
                from_domain=from_domain,
                reply_to_domain=reply_to_domain,
                return_path_domain=return_path_domain,
                message_id_domain=message_id_domain,
                dkim_domains=sorted(set(dkim_domains)),
                from_header=from_header,
                reply_to=reply_to,
                auth_results=auth_results,
                authentication_header_count=len(all_auth_headers),
            )

            summary_parts: list[str] = []
            if from_domain:
                summary_parts.append(f"from_domain={from_domain}")
            if reply_to_domain and reply_to_domain != from_domain:
                summary_parts.append(f"reply_to_domain={reply_to_domain}")
            if return_path_domain and return_path_domain != from_domain:
                summary_parts.append(f"return_path_domain={return_path_domain}")
            if message_id_domain and message_id_domain != from_domain:
                summary_parts.append(f"message_id_domain={message_id_domain}")
            if auth_results.get("spf") or auth_results.get("dkim") or auth_results.get("dmarc"):
                summary_parts.append(
                    "auth="
                    + ",".join(
                        f"{k}:{v}"
                        for k, v in (
                            ("spf", auth_results.get("spf")),
                            ("dkim", auth_results.get("dkim")),
                            ("dmarc", auth_results.get("dmarc")),
                            ("arc", auth_results.get("arc")),
                        )
                        if v
                    )
                )
            if dkim_domains:
                summary_parts.append(f"dkim_domains={','.join(sorted(set(dkim_domains))[:3])}")
            summary_parts.append(f"received_count={len(received)}")
            summary = " | ".join(summary_parts) if summary_parts else "Parsed email headers."

            result = EmailHeaderAuthCheckResult(
                risk_level=risk_level,
                summary=summary,
                from_address=from_header,
                from_domain=from_domain,
                reply_to=reply_to,
                reply_to_domain=reply_to_domain,
                return_path=return_path,
                return_path_domain=return_path_domain,
                message_id=message_id,
                message_id_domain=message_id_domain,
                auth_results=auth_results,
                dkim_signature_count=len(dkim_sigs),
                dkim_domains=sorted(set(dkim_domains)),
                authentication_results_headers=all_auth_headers,
                received_count=len(received),
                findings=findings,
                recommended_next_skills=recommended,
                raw_headers=raw_headers if payload.include_raw_headers else None,
            )

            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=True,
                data=result,
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                    endpoint=None,
                    service_version=None,
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
                    endpoint=None,
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
                    endpoint=None,
                ),
            )

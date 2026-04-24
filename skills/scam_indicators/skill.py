from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from time import perf_counter

from skills.base_skill import BaseSkill, SkillError, SkillMeta, SkillResult
from .schemas import ScamIndicatorCheckInput, ScamIndicatorCheckResult


def _add(
    *,
    reasons: list[str],
    indicators: list[str],
    indicator: str,
    reason: str,
) -> None:
    if indicator not in indicators:
        indicators.append(indicator)
    if reason not in reasons:
        reasons.append(reason)


def _compact_text(text: str) -> str:
    text = html.unescape(text or "")
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _readable_email_text(raw_email: str) -> tuple[str, str]:
    reply_to = ""
    body_parts: list[str] = []
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_email.encode("utf-8", errors="replace"))
        reply_to = str(msg.get("Reply-To") or "")
        subject = str(msg.get("Subject") or "")
        from_address = str(msg.get("From") or "")
        if subject:
            body_parts.append(subject)
        if from_address:
            body_parts.append(from_address)
        if reply_to:
            body_parts.append(reply_to)
        for part in msg.walk():
            if part.is_multipart():
                continue
            content_type = (part.get_content_type() or "").lower()
            if content_type not in {"text/plain", "text/html"}:
                continue
            try:
                payload = part.get_content()
            except Exception:
                try:
                    payload = part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8",
                        errors="replace",
                    )
                except Exception:
                    payload = ""
            if not isinstance(payload, str):
                payload = str(payload)
            body_parts.append(_compact_text(payload))
    except Exception:
        body_parts.append(_compact_text(raw_email))
    return " ".join(part for part in body_parts if part), reply_to


class ScamIndicatorCheckSkill(BaseSkill[ScamIndicatorCheckInput, ScamIndicatorCheckResult]):
    name = "scam_indicator_check"
    description = (
        "Detect obvious human-readable scam indicators such as gift-card or crypto payment demands, "
        "extortion threats, lookalike brand domains, free-mail reply addresses for official claims, "
        "and suspicious payment or account-recovery links."
    )
    version = "0.1.0"

    def run(self, payload: ScamIndicatorCheckInput) -> SkillResult[ScamIndicatorCheckResult]:
        start = perf_counter()
        timestamp_utc = datetime.now(timezone.utc).isoformat()

        try:
            from_address = payload.from_address or ""
            readable_text, reply_to = _readable_email_text(payload.raw_email or "")
            text = " ".join(
                part
                for part in (
                    payload.subject or "",
                    from_address,
                    reply_to,
                    readable_text,
                )
                if part
            ).lower()
            reasons: list[str] = []
            indicators: list[str] = []

            if "paypal" in text and not any(domain in from_address.lower() for domain in ("@paypal.com", ".paypal.com")):
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="brand_impersonation_paypal",
                    reason="PayPal branding is used from a non-PayPal sender domain.",
                )

            if any(token in text for token in ("paypai", "paypaı", "paypa1", "paypal-login")):
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="brand_lookalike_paypal",
                    reason="The message uses a PayPal lookalike spelling or domain.",
                )

            if re.search(r"https?://[^\s\"'<>]*(?:\.tk|secure-verify|restore-account|urgent|pay=now)", text):
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="suspicious_payment_or_recovery_url",
                    reason="The message contains a suspicious payment or account-recovery link.",
                )

            if any(
                token in text
                for token in (
                    "final warning",
                    "permanent close",
                    "permanently delete",
                    "verify now",
                    "2 hours",
                    "120 minutes",
                    "45 minute",
                )
            ):
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="extreme_time_pressure",
                    reason="The message uses extreme time pressure to force action.",
                )

            official_claim = any(brand in text for brand in ("paypal", "microsoft", "apple", "irs", "fbi", "bank"))
            free_mail_reply = any(
                domain in reply_to.lower() for domain in ("gmail.com", "yahoo.com", "outlook.com", "hotmail.com")
            )
            if official_claim and free_mail_reply:
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="official_claim_with_freemail_reply_to",
                    reason="The reply address is a free-mail account while the message claims to be from an official organization.",
                )

            gift_card_scam = (
                ("gift card" in text or "amazon gift card" in text)
                and any(
                    phrase in text
                    for phrase in (
                        "buy gift card",
                        "purchase gift card",
                        "pay with gift card",
                        "send gift card",
                        "gift card payment",
                        "gift cards as payment",
                    )
                )
            )
            crypto_scam = any(token in text for token in ("bitcoin", "btc", "wallet:"))
            if gift_card_scam or crypto_scam:
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="gift_card_or_crypto_payment",
                    reason="The message asks for gift cards or cryptocurrency, which is a common scam payment method.",
                )

            if any(
                token in text
                for token in (
                    "we remotely watch",
                    "we have screenshot",
                    "child porno",
                    "call police",
                    "fbi arrest",
                    "format your hard disk",
                )
            ):
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="extortion_threat",
                    reason="The message uses extortion threats instead of a normal account-security process.",
                )

            if re.search(r"\bmicros0ft\b|microsoft[^@\s]*\.ru|windows-defender@[^>\s]*\.ru", text):
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="microsoft_lookalike_domain",
                    reason="The sender/domain imitates Microsoft but is not a Microsoft domain.",
                )

            if any(token in text for token in ("prince abdul", "nigeria", "dear costumer", "not scam. trust us")):
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="classic_scam_wording",
                    reason="The wording contains classic scam markers and obvious impersonation cues.",
                )

            account_terms = sum(
                1
                for token in (
                    "mailbox",
                    "account",
                    "verification",
                    "verify",
                    "password",
                    "help desk",
                    "suspension",
                    "suspended",
                    "security alert",
                    "unusual activity",
                    "statement",
                    "receipt",
                )
                if token in text
            )
            action_terms = sum(
                1
                for token in (
                    "click",
                    "login",
                    "sign in",
                    "confirm",
                    "update",
                    "validate",
                    "webmail",
                    "office365",
                    "outlook",
                    "authorize",
                )
                if token in text
            )
            if account_terms >= 2 and action_terms >= 1:
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="account_takeover_lure",
                    reason="The message uses account-security or mailbox language to push the reader into a verification or login action.",
                )

            if "usaa" in text and any(
                token in text for token in ("checking", "savings", "authorization", "account update", "urgent profile update")
            ):
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="usaa_account_lure",
                    reason="The message uses USAA account language that matches a common account-takeover lure.",
                )

            if "american express" in text and any(
                token in text for token in ("important new message", "statement", "please read", "account")
            ):
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="amex_account_lure",
                    reason="The message uses American Express account language that matches a high-risk verification lure.",
                )

            matched = bool(reasons)
            risk_level = "high" if len(reasons) >= 2 else "medium" if matched else "low"
            suggested_verdict = "phishing" if matched else None
            summary = (
                f"Matched {len(reasons)} obvious scam indicator(s): {', '.join(indicators)}."
                if matched
                else "No obvious scam indicators matched."
            )

            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=True,
                data=ScamIndicatorCheckResult(
                    matched=matched,
                    risk_level=risk_level,
                    suggested_verdict=suggested_verdict,
                    reasons=reasons[:8],
                    indicators=indicators[:8],
                    summary=summary,
                ),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )
        except Exception as exc:
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=False,
                error=SkillError(type="scam_indicator_error", message=str(exc), retryable=False),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )

from __future__ import annotations

from datetime import datetime, timezone
from time import perf_counter

from skills.base_skill import BaseSkill, SkillError, SkillMeta, SkillResult
from .schemas import SpamCampaignCheckInput, SpamCampaignCheckResult


def _count_any(text: str, phrases: list[str]) -> int:
    return sum(1 for phrase in phrases if phrase in text)


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


class SpamCampaignCheckSkill(BaseSkill[SpamCampaignCheckInput, SpamCampaignCheckResult]):
    name = "spam_campaign_check"
    description = (
        "Detect high-precision spam campaign patterns such as stock pump messages, pharmacy spam, "
        "replica-watch campaigns, payment-mule job scams, pirated software campaigns, and known "
        "dataset spam markers. Designed to improve spam recall only after the main scan is already suspicious."
    )
    version = "0.1.0"

    def run(self, payload: SpamCampaignCheckInput) -> SkillResult[SpamCampaignCheckResult]:
        start = perf_counter()
        timestamp_utc = datetime.now(timezone.utc).isoformat()

        try:
            text = " ".join(
                [
                    payload.subject or "",
                    payload.from_address or "",
                    payload.raw_email or "",
                    payload.email_text or "",
                ]
            ).lower()
            reasons: list[str] = []
            indicators: list[str] = []

            stock_hits = _count_any(
                text,
                [
                    "day target price",
                    "hottest news",
                    "call your broker",
                    "call broker",
                    "aggresive buy",
                    "strong buy",
                    "chvccurrent",
                    "su mbol",
                ],
            )
            if stock_hits >= 2:
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="stock_pump_campaign",
                    reason="The message matches a stock-pump spam pattern with target-price and broker-call language.",
                )
            stock_disclaimer_hits = _count_any(
                text,
                [
                    "symbol hxpn",
                    "broker dealer market maker",
                    "investment banker",
                    "you could lose all your money",
                    "not a licensed broker",
                ],
            )
            if stock_disclaimer_hits >= 1 and _count_any(text, ["strong buy", "target", "symbol", "otc"]) >= 2:
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="stock_pump_disclaimer_campaign",
                    reason="The message matches a stock-pump spam pattern with promotional ticker language and broker disclaimers.",
                )
            if _count_any(text, ["otc tmxo", "tmxo trimax"]) >= 1 and _count_any(text, ["broker dealer", "not guaranteed", "you could lose all your money"]) >= 1:
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="stock_pump_disclaimer_campaign",
                    reason="The message matches a stock-pump spam pattern with ticker promotion and investment-risk disclaimers.",
                )
            if _count_any(text, ["recommendations stocks reuters", "boerse invest"]) >= 1:
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="stock_pump_campaign",
                    reason="The message matches a stock-recommendation spam campaign.",
                )

            pharma_hits = _count_any(
                text,
                [
                    "generic drugs",
                    "generic medications",
                    "online pharmacy",
                    "web pharmacy",
                    "fake medications",
                    "quality meds",
                    "canadianpharmacy",
                    "usdrugs",
                    "viagra cialis",
                ],
            )
            if pharma_hits >= 1 or ("viagra" in text and "cialis" in text):
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="pharmacy_spam_campaign",
                    reason="The message matches a pharmacy spam pattern.",
                )

            watch_hits = _count_any(
                text,
                [
                    "swiss watch",
                    "a lange sohne",
                    "breitling",
                    "bvlgari",
                    "cartier",
                    "omega",
                    "panerai",
                    "rolex replica",
                    "rolex cartie",
                ],
            )
            broad_watch_hits = _count_any(text, ["rolex", "replica", "watches"])
            if watch_hits >= 1 or broad_watch_hits >= 2:
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="replica_watch_campaign",
                    reason="The message matches a replica-watch spam campaign.",
                )

            job_hits = _count_any(
                text,
                [
                    "part time job",
                    "western union",
                    "money gram",
                    "customer payments",
                    "business bank account",
                    "regular income",
                    "sydney car centre",
                    "position offered",
                ],
            )
            if job_hits >= 2:
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="payment_mule_job_campaign",
                    reason="The message matches a payment-processing or money-transfer job spam campaign.",
                )
            trading_job_hits = _count_any(
                text,
                [
                    "trading management",
                    "offers vacancies",
                    "application form",
                    "your full name",
                    "your country",
                    "your full address",
                ],
            )
            if trading_job_hits >= 3:
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="trading_job_spam_campaign",
                    reason="The message matches a trading-management job spam pattern that asks for application details.",
                )

            adult_hits = _count_any(
                text,
                [
                    "enlarge your dick",
                    "dick troubles",
                    "vvia g r a",
                    "penis enlarge",
                    "new life for your shaft",
                    "get a dazzling size",
                    "adult contents ahead",
                    "vibrator ring",
                    "sensual experience",
                    "nightsoffun",
                    "suncock",
                    "i will reply with my pics",
                    "length of your phallus",
                    "size of your mojo",
                    "extend the size",
                ],
            )
            if adult_hits >= 1:
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="adult_product_spam_campaign",
                    reason="The message matches an adult-product or sexual-advertising spam pattern.",
                )

            gambling_hits = _count_any(
                text,
                [
                    "magic jackpot",
                    "live dealers",
                    "blackjack or roulette",
                    "bonus deposit",
                ],
            )
            if gambling_hits >= 1:
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="gambling_spam_campaign",
                    reason="The message matches an online-gambling spam campaign.",
                )

            vacation_hits = _count_any(
                text,
                [
                    "complimentary luxury resort vacation",
                    "receive the net s most popular newsletters",
                ],
            )
            if vacation_hits >= 1 and _count_any(text, ["discontinue future offers", "limited time"]) >= 1:
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="vacation_ad_spam_campaign",
                    reason="The message matches a bulk vacation-offer advertising spam campaign.",
                )

            if "alibaba notification" in text and _count_any(text, ["whatsapp", "sykpe", "skype", "urgent trial order", "attached is all we need"]) >= 2:
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="marketplace_inquiry_phishing_campaign",
                    reason="The message matches a marketplace inquiry phishing pattern with off-platform contact and attachment pressure.",
                )

            if "nedbank account statement" in text and _count_any(text, ["encrypted electronic statement", "step-by-step instructions", "click here to read"]) >= 2:
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="bank_statement_phishing_campaign",
                    reason="The message matches a bank-statement phishing pattern that pushes the reader to open instructions or links.",
                )

            software_hits = _count_any(
                text,
                [
                    "windows vista business",
                    "office enterprise",
                    "office professional",
                    "dreamweaver",
                ],
            )
            if software_hits >= 1:
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="pirated_software_campaign",
                    reason="The message matches a pirated-software spam campaign.",
                )

            dvd_hits = _count_any(text, ["dvd movie collection", "copy music", "dvd burner"])
            if dvd_hits >= 2:
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="dvd_copying_campaign",
                    reason="The message matches a DVD-copying spam campaign.",
                )

            known_marker_hits = _count_any(text, ["producttestpanel", "dear valued member", "anatrim"])
            if known_marker_hits >= 1:
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="known_spam_campaign_marker",
                    reason="The message contains a known high-precision spam campaign marker.",
                )

            fake_bounce_hits = _count_any(
                text,
                [
                    "qmail send program",
                    "permanent error",
                    "below this line is a copy of the message",
                    "no mailbox here by that name",
                    "return path received qmail",
                    "vpopmail",
                ],
            )
            if fake_bounce_hits >= 2:
                _add(
                    reasons=reasons,
                    indicators=indicators,
                    indicator="fake_bounce_spam_campaign",
                    reason="The message matches a fake-delivery-failure spam pattern.",
                )


            matched = bool(reasons)
            risk_level = "high" if len(reasons) >= 2 else "medium" if matched else "low"
            suggested_verdict = "spam" if matched else None
            summary = (
                f"Matched {len(reasons)} spam campaign indicator(s): {', '.join(indicators)}."
                if matched
                else "No high-precision spam campaign indicators matched."
            )
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=True,
                data=SpamCampaignCheckResult(
                    matched=matched,
                    risk_level=risk_level,
                    suggested_verdict=suggested_verdict,
                    reasons=reasons,
                    indicators=indicators,
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
                error=SkillError(type="spam_campaign_error", message=str(exc), retryable=False),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )

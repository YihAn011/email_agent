from __future__ import annotations

from pydantic import BaseModel


class SpamCampaignCheckInput(BaseModel):
    raw_email: str = ""
    email_text: str = ""
    subject: str = ""
    from_address: str = ""


class SpamCampaignCheckResult(BaseModel):
    matched: bool
    risk_level: str
    suggested_verdict: str | None = None
    reasons: list[str]
    indicators: list[str]
    summary: str

from __future__ import annotations

from pydantic import BaseModel


class ScamIndicatorCheckInput(BaseModel):
    raw_email: str = ""
    subject: str = ""
    from_address: str = ""


class ScamIndicatorCheckResult(BaseModel):
    matched: bool
    risk_level: str
    suggested_verdict: str | None = None
    reasons: list[str]
    indicators: list[str]
    summary: str

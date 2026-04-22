from __future__ import annotations

from pydantic import BaseModel


class ContentModelCheckInput(BaseModel):
    email_text: str
    subject: str = ""
    from_address: str = ""
    sender_domain: str = ""
    content_types: str = ""


class ContentModelCheckResult(BaseModel):
    malicious_score: float
    is_malicious: bool
    risk_level: str
    suggested_verdict: str | None = None
    threshold: float
    summary: str


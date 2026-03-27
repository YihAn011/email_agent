from __future__ import annotations
from typing import Optional
from pydantic import BaseModel


class UrgencyCheckInput(BaseModel):
    email_text: str
    subject: str = ""


class UrgencyCheckResult(BaseModel):
    urgency_label: str          # "not urgent" | "somewhat urgent" | "very urgent"
    urgency_score: float        # P(urgent) in [0, 1]
    is_urgent: bool             # True if score >= threshold
    risk_contribution: str      # "low" | "medium" | "high"
    summary: str

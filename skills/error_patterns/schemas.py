from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field, field_validator


class ErrorPatternEntry(BaseModel):
    id: str
    pattern_type: str
    suggested_verdict: str
    current_verdict: str
    template_kind: str = "exact"
    sender_domain: str = ""
    subject_normalized: str = ""
    subject_keywords: list[str] = Field(default_factory=list)
    required_keywords: list[str] = Field(default_factory=list)
    rspamd_risk_level: Optional[str] = None
    header_risk_level: Optional[str] = None
    urgency_label: Optional[str] = None
    url_risk_level: Optional[str] = None
    occurrences: int = 0
    error_rate: float = 0.0
    example_subject: str = ""
    example_from_address: str = ""
    notes: str = ""


class ErrorPatternMemoryCheckInput(BaseModel):
    subject: str = ""
    from_address: str = ""
    current_verdict: str = Field(..., description="Current pre-memory verdict such as benign or suspicious.")
    rspamd_risk_level: Optional[str] = None
    header_risk_level: Optional[str] = None
    urgency_label: Optional[str] = None
    url_risk_level: Optional[str] = None

    @field_validator("subject", "from_address", "current_verdict")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return value.strip()


class ErrorPatternMatch(BaseModel):
    pattern: ErrorPatternEntry
    score: int
    reason: str


class ErrorPatternMemoryCheckResult(BaseModel):
    matched: bool
    suggested_verdict: Optional[str] = None
    summary: str
    matches: list[ErrorPatternMatch] = Field(default_factory=list)


class ListErrorPatternsInput(BaseModel):
    limit: int = Field(default=20, ge=1, le=200)
    pattern_type: Optional[str] = None


class ListErrorPatternsResult(BaseModel):
    entries: list[ErrorPatternEntry] = Field(default_factory=list)

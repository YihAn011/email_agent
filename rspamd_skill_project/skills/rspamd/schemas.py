from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class RspamdScanEmailInput(BaseModel):
    raw_email: str = Field(..., description="Complete raw RFC822 email content")
    mail_from: Optional[str] = Field(default=None, description="SMTP envelope sender")
    rcpt_to: List[str] = Field(default_factory=list, description="SMTP envelope recipients")
    ip: Optional[str] = Field(default=None, description="Client IP address")
    helo: Optional[str] = Field(default=None, description="SMTP HELO/EHLO string")
    hostname: Optional[str] = Field(default=None, description="Client hostname")
    log_tag: Optional[str] = Field(default=None, description="Optional request correlation tag")
    timeout_seconds: float = Field(default=15.0, ge=1.0, le=60.0)
    include_raw_result: bool = Field(default=True)

    @field_validator("raw_email")
    @classmethod
    def validate_raw_email(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("raw_email is required and must not be empty")
        return value


class SymbolEvidence(BaseModel):
    name: str
    score: float = 0.0
    description: Optional[str] = None
    options: List[str] = Field(default_factory=list)
    category: Optional[str] = None


class RspamdNormalizedResult(BaseModel):
    score: float = 0.0
    required_score: Optional[float] = None
    action: Optional[str] = None
    risk_level: str = "unknown"
    categories: List[str] = Field(default_factory=list)
    symbols: List[SymbolEvidence] = Field(default_factory=list)
    summary: str
    recommended_next_skills: List[str] = Field(default_factory=list)
    raw_result: Optional[Dict[str, Any]] = None

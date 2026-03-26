from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class EmailHeaderAuthCheckInput(BaseModel):
    raw_email: Optional[str] = Field(
        default=None,
        description="Complete raw RFC822 email content. The body is ignored; headers are extracted.",
    )
    raw_headers: Optional[str] = Field(
        default=None,
        description="Raw header block only (everything up to the first blank line).",
    )
    include_raw_headers: bool = Field(
        default=False,
        description="If true, include the extracted raw headers in the output for debugging.",
    )

    @model_validator(mode="after")
    def validate_input(self) -> "EmailHeaderAuthCheckInput":
        if (not self.raw_email or not self.raw_email.strip()) and (
            not self.raw_headers or not self.raw_headers.strip()
        ):
            raise ValueError("Either raw_email or raw_headers is required and must not be empty")
        return self

    @field_validator("raw_headers")
    @classmethod
    def validate_raw_headers(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        if not value.strip():
            raise ValueError("raw_headers must not be empty when provided")
        return value


class HeaderFinding(BaseModel):
    type: str
    severity: str = Field(..., description="low|medium|high|info")
    message: str
    evidence: Dict[str, Any] = Field(default_factory=dict)


class EmailHeaderAuthCheckResult(BaseModel):
    risk_level: str = "unknown"
    summary: str

    from_address: Optional[str] = None
    from_domain: Optional[str] = None
    reply_to: Optional[str] = None
    reply_to_domain: Optional[str] = None
    return_path: Optional[str] = None
    return_path_domain: Optional[str] = None
    message_id: Optional[str] = None
    message_id_domain: Optional[str] = None

    auth_results: Dict[str, Optional[str]] = Field(
        default_factory=dict,
        description="Best-effort parsed outcomes from Authentication-Results (e.g. spf/dkim/dmarc/arc).",
    )
    dkim_signature_count: int = 0
    dkim_domains: List[str] = Field(default_factory=list)
    authentication_results_headers: List[str] = Field(default_factory=list)

    received_count: int = 0

    findings: List[HeaderFinding] = Field(default_factory=list)
    recommended_next_skills: List[str] = Field(default_factory=list)

    raw_headers: Optional[str] = None


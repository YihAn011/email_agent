from __future__ import annotations
from typing import List
from pydantic import BaseModel


class UrlReputationInput(BaseModel):
    email_text: str
    subject: str = ""
    # Pre-computed features (optional — extracted from email_text if absent)
    num_urls: int = 0
    has_ip_url: int = 0
    email_length: int = 0
    num_exclamation_marks: int = 0
    num_links_in_body: int = 0
    is_html_email: int = 0
    url_length_max: float = 0.0
    url_length_avg: float = 0.0
    url_subdom_max: float = 0.0
    url_subdom_avg: float = 0.0
    attachment_count: int = 0
    has_attachments: int = 0


class UrlReputationResult(BaseModel):
    phishing_score: float       # P(phishing) in [0, 1]
    is_suspicious: bool         # True if score >= threshold
    risk_level: str             # "low" | "medium" | "high"
    extracted_urls: List[str]
    features_used: dict
    summary: str

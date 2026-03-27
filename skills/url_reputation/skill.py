from __future__ import annotations

import pickle
import re
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from urllib.parse import urlparse

from skills.base_skill import BaseSkill, SkillError, SkillMeta, SkillResult
from .schemas import UrlReputationInput, UrlReputationResult

MODEL_DIR = Path(__file__).parent / "model"
_cache: dict = {}

URL_RE = re.compile(r'https?://[^\s<>"\']+')
IP_RE = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')


def _load() -> tuple:
    if _cache:
        return _cache["clf"], _cache["meta"]
    clf = pickle.load(open(MODEL_DIR / "model.pkl", "rb"))
    meta = pickle.load(open(MODEL_DIR / "meta.pkl", "rb"))
    _cache.update({"clf": clf, "meta": meta})
    return clf, meta


def _extract_features(payload: UrlReputationInput) -> tuple[dict, list[str]]:
    text = payload.email_text or ""
    urls = URL_RE.findall(text)

    lengths = [len(u) for u in urls]
    subdoms = [urlparse(u).netloc.count(".") for u in urls]

    features = {
        "num_urls": payload.num_urls or len(urls),
        "has_ip_url": payload.has_ip_url or int(any(IP_RE.search(u) for u in urls)),
        "email_length": payload.email_length or len(text),
        "num_exclamation_marks": payload.num_exclamation_marks or text.count("!"),
        "num_links_in_body": payload.num_links_in_body or len(urls),
        "is_html_email": payload.is_html_email or int(bool(re.search(r'<html|<body|<a ', text, re.I))),
        "url_length_max": payload.url_length_max or (max(lengths) if lengths else 0),
        "url_length_avg": payload.url_length_avg or (sum(lengths) / len(lengths) if lengths else 0),
        "url_subdom_max": payload.url_subdom_max or (max(subdoms) if subdoms else 0),
        "url_subdom_avg": payload.url_subdom_avg or (sum(subdoms) / len(subdoms) if subdoms else 0),
        "attachment_count": payload.attachment_count,
        "has_attachments": payload.has_attachments,
    }
    return features, urls


class UrlReputationSkill(BaseSkill[UrlReputationInput, UrlReputationResult]):
    name = "url_reputation_check"
    description = (
        "Score the URL/content risk of an email using a trained GradientBoosting classifier. "
        "Returns phishing_score (0-1), is_suspicious flag, and risk_level."
    )
    version = "0.1.0"

    def run(self, payload: UrlReputationInput) -> SkillResult[UrlReputationResult]:
        start = perf_counter()
        timestamp_utc = datetime.now(timezone.utc).isoformat()

        try:
            clf, meta = _load()
            threshold = meta["phishing_threshold"]
            feature_names = meta["features"]

            features, urls = _extract_features(payload)
            X = [[features[f] for f in feature_names]]
            score = float(clf.predict_proba(X)[0][1])
            is_suspicious = score >= threshold

            if score >= 0.7:
                risk_level = "high"
            elif score >= threshold:
                risk_level = "medium"
            else:
                risk_level = "low"

            summary = (
                f"Phishing score={score:.2f} (threshold={threshold:.2f}). "
                f"Extracted {len(urls)} URL(s). "
                f"Risk level: {risk_level}."
            )

            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=True,
                data=UrlReputationResult(
                    phishing_score=round(score, 4),
                    is_suspicious=is_suspicious,
                    risk_level=risk_level,
                    extracted_urls=urls[:20],
                    features_used=features,
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
                error=SkillError(type="url_rep_error", message=str(exc), retryable=False),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )

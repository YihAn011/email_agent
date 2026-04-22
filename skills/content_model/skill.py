from __future__ import annotations

import pickle
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

from scipy import sparse

from skills.base_skill import BaseSkill, SkillError, SkillMeta, SkillResult

from .schemas import ContentModelCheckInput, ContentModelCheckResult

MODEL_DIR = Path(__file__).parent / "model"
_cache: dict[str, object] = {}


def _load() -> tuple[object | None, object | None, object | None, dict | None]:
    if _cache:
        return (
            _cache.get("word_vectorizer"),
            _cache.get("char_vectorizer"),
            _cache.get("classifier"),
            _cache.get("meta"),
        )
    paths = {
        "word_vectorizer": MODEL_DIR / "word_vectorizer.pkl",
        "char_vectorizer": MODEL_DIR / "char_vectorizer.pkl",
        "classifier": MODEL_DIR / "classifier.pkl",
        "meta": MODEL_DIR / "meta.pkl",
    }
    if not all(path.exists() for path in paths.values()):
        return None, None, None, None
    for key, path in paths.items():
        with path.open("rb") as handle:
            _cache[key] = pickle.load(handle)
    return (
        _cache["word_vectorizer"],
        _cache["char_vectorizer"],
        _cache["classifier"],
        _cache["meta"],
    )


def _compose_text(payload: ContentModelCheckInput) -> str:
    parts = [
        f"subject={payload.subject or ''}",
        f"sender={payload.from_address or ''}",
        f"sender_domain={payload.sender_domain or ''}",
        f"content_type={payload.content_types or ''}",
        f"body={(payload.email_text or '')[:4000]}",
    ]
    return " ".join(parts)


def _heuristic_score(payload: ContentModelCheckInput) -> float:
    text = _compose_text(payload).lower()
    score = 0.0
    spam_terms = (
        "viagra",
        "cialis",
        "replica",
        "rolex",
        "broker",
        "stock",
        "target price",
        "gift card",
        "bitcoin",
        "casino",
        "bonus deposit",
        "pills",
        "pharmacy",
        "unsubscribe",
        "free",
        "guarantee",
        "limited time",
        "opportunity",
    )
    hit_count = sum(1 for term in spam_terms if term in text)
    score += min(0.75, hit_count * 0.08)
    score += min(0.2, text.count("http") * 0.04)
    score += min(0.1, text.count("!") * 0.01)
    if "escapenumber" in text or "escapelong" in text:
        score += 0.25
    return min(0.99, score)


class ContentModelCheckSkill(BaseSkill[ContentModelCheckInput, ContentModelCheckResult]):
    name = "content_model_check"
    description = (
        "Score the body and sender text of an email using a calibrated text classifier tuned for "
        "low false-positive spam/phishing detection."
    )
    version = "0.1.0"

    def run(self, payload: ContentModelCheckInput) -> SkillResult[ContentModelCheckResult]:
        start = perf_counter()
        timestamp_utc = datetime.now(timezone.utc).isoformat()

        try:
            word_vectorizer, char_vectorizer, classifier, meta = _load()
            if not payload.email_text and not payload.subject and not payload.from_address:
                raise ValueError("At least one of email_text, subject, or from_address must be provided.")

            text = _compose_text(payload)
            if not all((word_vectorizer, char_vectorizer, classifier, meta)):
                threshold = 0.55
                score = _heuristic_score(payload)
                summary = (
                    "Fallback heuristic content scoring was used because the trained model files were not found. "
                    f"Malicious score={score:.2f} (threshold={threshold:.2f})."
                )
            else:
                word_features = word_vectorizer.transform([text])
                char_features = char_vectorizer.transform([text])
                features = sparse.hstack([word_features, char_features], format="csr")
                score = float(classifier.predict_proba(features)[0][1])
                threshold = float(meta["threshold"])
                summary = (
                    f"Content-model malicious score={score:.2f} (threshold={threshold:.2f}). "
                    f"Training sources={','.join(meta.get('sources', [])) or 'all'}."
                )

            is_malicious = score >= threshold
            if score >= max(0.85, threshold + 0.2):
                risk_level = "high"
            elif is_malicious:
                risk_level = "medium"
            else:
                risk_level = "low"

            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=True,
                data=ContentModelCheckResult(
                    malicious_score=round(score, 4),
                    is_malicious=is_malicious,
                    risk_level=risk_level,
                    suggested_verdict="spam" if is_malicious else None,
                    threshold=round(threshold, 4),
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
                error=SkillError(type="content_model_error", message=str(exc), retryable=False),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )


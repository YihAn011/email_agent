from __future__ import annotations

import pickle
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

from skills.base_skill import BaseSkill, SkillError, SkillMeta, SkillResult
from .schemas import UrgencyCheckInput, UrgencyCheckResult

MODEL_DIR = Path(__file__).parent / "model"
_cache: dict = {}
URGENT_KEYWORDS = [
    "urgent",
    "immediately",
    "asap",
    "action required",
    "verify",
    "suspend",
    "suspended",
    "click now",
    "last chance",
    "important",
    "attention",
    "password expires",
    "confirm",
    "update now",
    "limited time",
    "security alert",
    "unusual activity",
    "act now",
    "final notice",
]


def _load() -> tuple:
    if _cache:
        return _cache["vec"], _cache["clf"], _cache["meta"]
    if not (MODEL_DIR / "vectorizer.pkl").exists() or not (MODEL_DIR / "model.pkl").exists() or not (MODEL_DIR / "meta.pkl").exists():
        return None, None, None
    vec = pickle.load(open(MODEL_DIR / "vectorizer.pkl", "rb"))
    clf = pickle.load(open(MODEL_DIR / "model.pkl", "rb"))
    meta = pickle.load(open(MODEL_DIR / "meta.pkl", "rb"))
    _cache.update({"vec": vec, "clf": clf, "meta": meta})
    return vec, clf, meta


def _heuristic_result(subject: str, email_text: str) -> UrgencyCheckResult:
    combined = f"{subject} {email_text}".lower()
    keyword_count = sum(1 for item in URGENT_KEYWORDS if item in combined)
    exclam_count = combined.count("!")
    score = min(1.0, keyword_count * 0.12 + exclam_count * 0.03)
    if score >= 0.7:
        label = "very urgent"
        risk = "high"
    elif score >= 0.35:
        label = "somewhat urgent"
        risk = "medium"
    else:
        label = "not urgent"
        risk = "low"
    return UrgencyCheckResult(
        urgency_label=label,
        urgency_score=round(score, 4),
        is_urgent=score >= 0.35,
        risk_contribution=risk,
        summary=(
            "Fallback heuristic urgency scoring was used because the trained model files were not found. "
            f"Keyword_count={keyword_count}, exclamations={exclam_count}, score={score:.2f}."
        ),
    )


class UrgencyCheckSkill(BaseSkill[UrgencyCheckInput, UrgencyCheckResult]):
    name = "urgency_check"
    description = (
        "Classify the urgency/pressure level of an email using a trained logistic regression. "
        "Returns urgency_label, urgency_score (0-1), and a risk contribution."
    )
    version = "0.1.0"

    def run(self, payload: UrgencyCheckInput) -> SkillResult[UrgencyCheckResult]:
        start = perf_counter()
        timestamp_utc = datetime.now(timezone.utc).isoformat()

        try:
            vec, clf, meta = _load()
            if vec is None or clf is None or meta is None:
                data = _heuristic_result(payload.subject, payload.email_text)
                latency_ms = int((perf_counter() - start) * 1000)
                return SkillResult(
                    ok=True,
                    data=data,
                    meta=SkillMeta(
                        skill_name=self.name,
                        skill_version=self.version,
                        latency_ms=latency_ms,
                        timestamp_utc=timestamp_utc,
                    ),
                )
            threshold = meta["urgent_threshold"]
            label_map_inv = {v: k for k, v in meta["label_map"].items()}

            text = (payload.subject + " " + payload.email_text)[:2000]
            X = vec.transform([text])
            probs = clf.predict_proba(X)[0]

            # P(urgent) = P(somewhat urgent) + P(very urgent)
            urgent_score = float(probs[1] + probs[2])
            predicted_class = int(clf.predict(X)[0])
            urgency_label = label_map_inv[predicted_class]
            is_urgent = urgent_score >= threshold

            if urgent_score >= 0.7:
                risk_contribution = "high"
            elif urgent_score >= threshold:
                risk_contribution = "medium"
            else:
                risk_contribution = "low"

            summary = (
                f"Urgency score={urgent_score:.2f} (threshold={threshold:.2f}). "
                f"Classified as '{urgency_label}'. "
                f"Risk contribution: {risk_contribution}."
            )

            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=True,
                data=UrgencyCheckResult(
                    urgency_label=urgency_label,
                    urgency_score=round(urgent_score, 4),
                    is_urgent=is_urgent,
                    risk_contribution=risk_contribution,
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
                error=SkillError(type="urgency_error", message=str(exc), retryable=False),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )

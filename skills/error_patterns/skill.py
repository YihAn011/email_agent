from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

from skills.base_skill import BaseSkill, SkillError, SkillMeta, SkillResult

from .schemas import (
    ErrorPatternEntry,
    ErrorPatternMatch,
    ErrorPatternMemoryCheckInput,
    ErrorPatternMemoryCheckResult,
    ListErrorPatternsInput,
    ListErrorPatternsResult,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_DIR = PROJECT_ROOT / "runtime" / "error_patterns"
PATTERNS_PATH = RUNTIME_DIR / "patterns.json"

STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "your",
    "this",
    "that",
    "from",
    "have",
    "has",
    "are",
    "was",
    "will",
    "alert",
    "email",
    "message",
    "notification",
    "update",
}


def normalize_subject(subject: str) -> str:
    text = re.sub(r"\s+", " ", (subject or "").strip().lower())
    text = re.sub(r"^(re|fw|fwd)\s*:\s*", "", text)
    return text


def extract_subject_keywords(subject: str, *, limit: int = 6) -> list[str]:
    tokens = re.findall(r"[a-z0-9]{3,}", normalize_subject(subject))
    keywords: list[str] = []
    for token in tokens:
        if token in STOPWORDS:
            continue
        if token not in keywords:
            keywords.append(token)
        if len(keywords) >= limit:
            break
    return keywords


def extract_sender_domain(from_address: str) -> str:
    text = (from_address or "").strip().lower()
    if "@" not in text:
        return ""
    domain = text.split("@")[-1]
    return domain.replace("<", "").replace(">", "").strip()


def load_error_patterns() -> list[ErrorPatternEntry]:
    if not PATTERNS_PATH.exists():
        return []
    raw = json.loads(PATTERNS_PATH.read_text(encoding="utf-8"))
    return [ErrorPatternEntry.model_validate(item) for item in raw]


def score_pattern_match(pattern: ErrorPatternEntry, payload: ErrorPatternMemoryCheckInput) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    strong_match = False

    sender_domain = extract_sender_domain(payload.from_address)
    if pattern.sender_domain and sender_domain == pattern.sender_domain:
        score += 4
        reasons.append("same sender domain")
        strong_match = True

    subject_normalized = normalize_subject(payload.subject)
    if pattern.subject_normalized and subject_normalized == pattern.subject_normalized:
        score += 4
        reasons.append("same normalized subject")
        strong_match = True

    incoming_keywords = set(extract_subject_keywords(payload.subject))
    overlap = sorted(incoming_keywords & set(pattern.subject_keywords))
    if overlap:
        score += min(3, len(overlap))
        reasons.append(f"shared subject keywords={','.join(overlap)}")
        if len(overlap) >= 2:
            strong_match = True

    required_overlap = sorted(incoming_keywords & set(pattern.required_keywords))
    if pattern.required_keywords:
        if len(required_overlap) == len(set(pattern.required_keywords)):
            score += 4
            reasons.append(f"matched required keywords={','.join(required_overlap)}")
            strong_match = True
        else:
            return 0, []

    if pattern.current_verdict == payload.current_verdict:
        score += 2
        reasons.append("same current verdict")

    if pattern.rspamd_risk_level and payload.rspamd_risk_level == pattern.rspamd_risk_level:
        score += 1
        reasons.append("same rspamd risk")
    if pattern.header_risk_level and payload.header_risk_level == pattern.header_risk_level:
        score += 1
        reasons.append("same header risk")
    if pattern.urgency_label and payload.urgency_label == pattern.urgency_label:
        score += 1
        reasons.append("same urgency label")
    if pattern.url_risk_level and payload.url_risk_level == pattern.url_risk_level:
        score += 1
        reasons.append("same URL risk")

    if not strong_match:
        return 0, []
    return score, reasons


def find_error_pattern_matches(
    payload: ErrorPatternMemoryCheckInput, *, limit: int = 5
) -> list[ErrorPatternMatch]:
    matches: list[ErrorPatternMatch] = []
    for pattern in load_error_patterns():
        score, reasons = score_pattern_match(pattern, payload)
        min_score = 8 if pattern.template_kind == "exact" else 7
        if score < min_score:
            continue
        matches.append(
            ErrorPatternMatch(
                pattern=pattern,
                score=score,
                reason="; ".join(reasons),
            )
        )
    matches.sort(key=lambda item: (-item.score, -item.pattern.occurrences, item.pattern.id))
    return matches[:limit]


class ErrorPatternMemoryCheckSkill(
    BaseSkill[ErrorPatternMemoryCheckInput, ErrorPatternMemoryCheckResult]
):
    name = "error_pattern_memory_check"
    description = "Check known dataset-derived misclassification patterns before returning the final email verdict."
    version = "0.1.0"

    def run(
        self, payload: ErrorPatternMemoryCheckInput
    ) -> SkillResult[ErrorPatternMemoryCheckResult]:
        start = perf_counter()
        timestamp_utc = datetime.now(timezone.utc).isoformat()
        try:
            matches = find_error_pattern_matches(payload)
            if not matches:
                result = ErrorPatternMemoryCheckResult(
                    matched=False,
                    summary="No stored error pattern matched the current email signals.",
                    matches=[],
                )
            else:
                top = matches[0]
                result = ErrorPatternMemoryCheckResult(
                    matched=True,
                    suggested_verdict=top.pattern.suggested_verdict,
                    summary=(
                        f"Matched {len(matches)} stored error pattern(s). "
                        f"Top match suggests `{top.pattern.suggested_verdict}` because {top.reason}."
                    ),
                    matches=matches,
                )
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=True,
                data=result,
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
                error=SkillError(type="error_pattern_check_error", message=str(exc), retryable=False),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )


class ListErrorPatternsSkill(BaseSkill[ListErrorPatternsInput, ListErrorPatternsResult]):
    name = "list_error_patterns"
    description = "List dataset-derived misclassification patterns used by the error-pattern memory layer."
    version = "0.1.0"

    def run(self, payload: ListErrorPatternsInput) -> SkillResult[ListErrorPatternsResult]:
        start = perf_counter()
        timestamp_utc = datetime.now(timezone.utc).isoformat()
        try:
            entries = load_error_patterns()
            if payload.pattern_type:
                entries = [entry for entry in entries if entry.pattern_type == payload.pattern_type]
            result = ListErrorPatternsResult(entries=entries[: payload.limit])
            latency_ms = int((perf_counter() - start) * 1000)
            return SkillResult(
                ok=True,
                data=result,
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
                error=SkillError(type="list_error_patterns_error", message=str(exc), retryable=False),
                meta=SkillMeta(
                    skill_name=self.name,
                    skill_version=self.version,
                    latency_ms=latency_ms,
                    timestamp_utc=timestamp_utc,
                ),
            )

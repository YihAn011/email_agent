from __future__ import annotations

import re
from dataclasses import dataclass

from .storage import list_decision_memory, mark_memory_referenced


STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "your",
    "from",
    "this",
    "that",
    "have",
    "has",
    "you",
    "are",
    "was",
    "will",
    "our",
    "but",
    "not",
    "new",
    "alert",
    "security",
    "update",
    "email",
}


def normalize_subject(subject: str) -> str:
    cleaned = re.sub(r"\s+", " ", (subject or "").strip().lower())
    cleaned = re.sub(r"^(re|fw|fwd)\s*:\s*", "", cleaned)
    return cleaned


def extract_keywords(subject: str, *, limit: int = 6) -> list[str]:
    tokens = re.findall(r"[a-z0-9]{3,}", normalize_subject(subject))
    seen: list[str] = []
    for token in tokens:
        if token in STOPWORDS:
            continue
        if token not in seen:
            seen.append(token)
        if len(seen) >= limit:
            break
    return seen


def extract_domain(from_address: str) -> str:
    text = (from_address or "").strip().lower()
    if "@" not in text:
        return ""
    domain = text.split("@")[-1]
    return domain.replace(">", "").replace("<", "").strip()


@dataclass
class MemoryMatch:
    memory_id: int
    corrected_verdict: str
    prior_verdict: str
    notes: str
    sender_domain: str
    subject_normalized: str
    score: int
    reason: str


def find_memory_match(
    *,
    subject: str,
    from_address: str,
    current_verdict: str,
) -> MemoryMatch | None:
    sender_domain = extract_domain(from_address)
    subject_normalized = normalize_subject(subject)
    subject_keywords = set(extract_keywords(subject))

    best: MemoryMatch | None = None
    for entry in list_decision_memory(limit=200):
        score = 0
        reasons: list[str] = []

        if sender_domain and entry["sender_domain"] == sender_domain:
            score += 4
            reasons.append("same sender domain")
        if subject_normalized and entry["subject_normalized"] == subject_normalized:
            score += 4
            reasons.append("same normalized subject")

        entry_keywords = {token for token in str(entry["subject_keywords"]).split("|") if token}
        overlap = sorted(subject_keywords & entry_keywords)
        if overlap:
            score += min(3, len(overlap))
            reasons.append(f"shared keywords={','.join(overlap)}")

        if entry["prior_verdict"] == current_verdict:
            score += 1
            reasons.append("same prior verdict")

        if score < 5:
            continue

        candidate = MemoryMatch(
            memory_id=int(entry["id"]),
            corrected_verdict=str(entry["corrected_verdict"]),
            prior_verdict=str(entry["prior_verdict"]),
            notes=str(entry.get("notes") or ""),
            sender_domain=str(entry["sender_domain"]),
            subject_normalized=str(entry["subject_normalized"]),
            score=score,
            reason="; ".join(reasons),
        )
        if best is None or candidate.score > best.score:
            best = candidate

    if best is not None:
        mark_memory_referenced(best.memory_id)
    return best

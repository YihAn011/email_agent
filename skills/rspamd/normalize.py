from __future__ import annotations

from typing import Any, Dict, List, Tuple

from .schemas import RspamdNormalizedResult, SymbolEvidence


CATEGORY_RULES: list[tuple[str, str]] = [
    ("PHISH", "phishing"),
    ("SPOOF", "spoofing"),
    ("DMARC", "authentication_issue"),
    ("DKIM", "authentication_issue"),
    ("SPF", "authentication_issue"),
    ("URL", "suspicious_links"),
    ("RBL", "reputation_issue"),
    ("REPUTATION", "reputation_issue"),
    ("BAYES", "spam"),
    ("FREEMAIL", "sender_profile"),
    ("MIME", "content_anomaly"),
    ("ATTACH", "attachment_risk"),
    ("ARC", "authentication_issue"),
]


def infer_category(symbol_name: str) -> str | None:
    upper_name = symbol_name.upper()
    for token, category in CATEGORY_RULES:
        if token in upper_name:
            return category
    return None


def infer_risk_level(score: float, required_score: float | None, categories: List[str]) -> str:
    if "phishing" in categories and score >= 6:
        return "high"
    if required_score is not None:
        if score >= required_score:
            return "high"
        if score >= required_score * 0.5:
            return "medium"
        return "low"
    if score >= 8:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _score_band(score: float, action: str | None) -> str:
    action_lc = (action or "").lower()
    if score >= 12 or action_lc in {"soft reject", "reject"}:
        return "high"
    if score >= 7 or action_lc in {"add header", "rewrite subject"}:
        return "elevated"
    if score >= 4:
        return "gray"
    return "low"


def recommend_next_skills(categories: List[str], score: float, action: str | None = None) -> List[str]:
    recommendations: List[str] = []
    category_set = set(categories)
    band = _score_band(score, action)
    has_phish_signal = bool(category_set & {"phishing", "spoofing", "suspicious_links"})
    has_spam_signal = bool(category_set & {"spam", "reputation_issue"})
    has_auth_signal = "authentication_issue" in category_set

    if has_phish_signal:
        recommendations.append("url_reputation_check")
        recommendations.append("email_header_auth_check")
        recommendations.append("scam_indicator_check")
        if band in {"gray", "elevated", "high"}:
            recommendations.append("urgency_check")

    if has_spam_signal:
        recommendations.append("spam_campaign_check")
        if "suspicious_links" in category_set or band in {"elevated", "high"}:
            recommendations.append("url_reputation_check")

    if has_auth_signal:
        recommendations.append("email_header_auth_check")
        if band in {"elevated", "high"}:
            recommendations.append("scam_indicator_check")

    if "attachment_risk" in category_set and "url_reputation_check" not in recommendations:
        recommendations.append("url_reputation_check")

    if band in {"elevated", "high"}:
        recommendations.append("list_error_patterns")
    if band == "high" or (band == "elevated" and has_phish_signal):
        recommendations.append("error_pattern_memory_check")

    seen = set()
    deduped: List[str] = []
    for item in recommendations:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def extract_symbols(raw_result: Dict[str, Any]) -> List[SymbolEvidence]:
    raw_symbols = raw_result.get("symbols") or {}
    parsed_symbols: List[SymbolEvidence] = []

    if isinstance(raw_symbols, dict):
        for name, info in raw_symbols.items():
            if isinstance(info, dict):
                score = float(info.get("score") or 0.0)
                description = info.get("description")
                options = info.get("options") or []
            else:
                score = 0.0
                description = None
                options = []
            parsed_symbols.append(
                SymbolEvidence(
                    name=name,
                    score=score,
                    description=description,
                    options=options if isinstance(options, list) else [str(options)],
                    category=infer_category(name),
                )
            )

    parsed_symbols.sort(key=lambda item: abs(item.score), reverse=True)
    return parsed_symbols


def summarize(action: str | None, score: float, categories: List[str], symbol_count: int) -> str:
    if not categories:
        return f"Rspamd returned action={action or 'unknown'} with score={score:.2f} and {symbol_count} matched symbols."

    category_text = ", ".join(categories)
    return (
        f"Rspamd returned action={action or 'unknown'} with score={score:.2f}. "
        f"Detected categories: {category_text}. Matched symbols: {symbol_count}."
    )


def normalize_rspamd_result(raw_result: Dict[str, Any], include_raw_result: bool = True) -> RspamdNormalizedResult:
    score = float(raw_result.get("score") or 0.0)
    required_score_value = raw_result.get("required_score")
    required_score = float(required_score_value) if required_score_value is not None else None
    action = raw_result.get("action")

    symbols = extract_symbols(raw_result)
    categories = sorted({sym.category for sym in symbols if sym.category})
    risk_level = infer_risk_level(score, required_score, categories)
    next_skills = recommend_next_skills(categories, score, action)
    summary = summarize(action, score, categories, len(symbols))

    return RspamdNormalizedResult(
        score=score,
        required_score=required_score,
        action=action,
        risk_level=risk_level,
        categories=categories,
        symbols=symbols,
        summary=summary,
        recommended_next_skills=next_skills,
        raw_result=raw_result if include_raw_result else None,
    )

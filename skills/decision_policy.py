from __future__ import annotations

from typing import Any


def classify_email_type(subject: str, from_address: str) -> str:
    subject_lc = (subject or "").lower()
    from_lc = (from_address or "").lower()
    text = f"{subject_lc} {from_lc}"

    if any(token in text for token in ("columbia", ".edu", "university", "school", "course", "canvas", "professor")):
        return "School email"
    if any(token in text for token in ("invoice", "receipt", "bill", "payment", "statement", "charged", "subscription")):
        return "Billing email"
    if any(token in text for token in ("security alert", "verify", "password", "sign-in", "login", "account alert", "suspended")):
        return "Security / account alert"
    if any(token in text for token in ("sale", "offer", "deal", "save", "coupon", "newsletter", "weekly ad", "promotion", "promo", "discount", "%", "subway")):
        return "Promotional / advertising email"
    if any(token in text for token in ("order", "shipment", "delivered", "shipping", "package", "tracking", "return")):
        return "Shopping / delivery email"
    if any(token in text for token in ("interview", "recruiting", "job", "career", "application")):
        return "Work / recruiting email"
    if any(token in text for token in ("bank", "credit card", "transaction", "zelle", "paypal", "venmo")):
        return "Financial email"
    return "General email"


def required_decision_label(
    rspamd_data: dict[str, Any],
    content_data: dict[str, Any] | None = None,
    header_data: dict[str, Any] | None = None,
    url_data: dict[str, Any] | None = None,
    urgency_data: dict[str, Any] | None = None,
    scam_data: dict[str, Any] | None = None,
    spam_data: dict[str, Any] | None = None,
    subject: str = "",
    from_address: str = "",
) -> str:
    categories = {str(item).lower() for item in (rspamd_data.get("categories") or [])}
    symbols = {
        str(item.get("name") or "").lower()
        for item in (rspamd_data.get("symbols") or [])
        if isinstance(item, dict)
    }
    scam_indicators = {
        str(item).lower()
        for item in ((scam_data or {}).get("indicators") or [])
        if str(item).strip()
    }
    risk = str(rspamd_data.get("risk_level") or "").lower()
    content_risk = str((content_data or {}).get("risk_level") or "").lower()
    content_score = float((content_data or {}).get("malicious_score") or 0.0)
    content_malicious = bool((content_data or {}).get("is_malicious"))
    header_risk = str((header_data or {}).get("risk_level") or "").lower()
    action = str(rspamd_data.get("action") or "").lower()
    score = float(rspamd_data.get("score") or 0.0)
    url_risk = str((url_data or {}).get("risk_level") or "").lower()
    url_suspicious = bool((url_data or {}).get("is_suspicious"))
    urgency_risk = str((urgency_data or {}).get("risk_contribution") or "").lower()
    urgent = bool((urgency_data or {}).get("is_urgent"))
    scam_matched = bool((scam_data or {}).get("matched"))
    spam_matched = bool((spam_data or {}).get("matched"))
    spam_risk = str((spam_data or {}).get("risk_level") or "").lower()
    email_type = classify_email_type(subject, from_address)
    sender_text = f"{subject} {from_address}".lower()
    branded_marketing = (
        email_type == "Promotional / advertising email"
        and any(token in sender_text for token in ("subway", "subs.subway.com", "news@subs.subway.com"))
    )
    account_or_security_context = any(
        token in sender_text
        for token in (
            "account",
            "verify",
            "verification",
            "password",
            "login",
            "sign-in",
            "security",
            "mailbox",
            "help desk",
            "bank",
            "statement",
            "invoice",
            "payment",
        )
    )
    header_format_noise = bool(
        symbols
        and symbols
        <= {
            "short_part_bad_headers",
            "missing_essential_headers",
            "hfilter_hostname_unknown",
            "missing_mid",
            "missing_to",
            "r_bad_cte_7bit",
        }
    )
    corroborating_checks_low = (
        url_risk in {"", "low", "unknown"}
        and not url_suspicious
        and urgency_risk in {"", "low", "unknown"}
        and not urgent
        and header_risk in {"", "low", "unknown", "n/a"}
        and not scam_matched
        and not spam_matched
    )
    has_phish_signal = bool({"phishing", "spoofing", "suspicious_links"} & categories)
    has_spam_signal = bool("spam" in categories or any("bayes" in item for item in symbols) or "reputation_issue" in categories)
    high_rspamd = score >= 12 or action in {"soft reject", "reject"}
    elevated_rspamd = score >= 7 or action in {"add header", "rewrite subject", "soft reject", "reject"}
    content_high = content_score >= 0.85
    content_elevated = content_malicious or content_risk in {"medium", "high"}
    strong_scam_signal = bool(
        scam_indicators
        & {
            "brand_impersonation_paypal",
            "brand_lookalike_paypal",
            "suspicious_payment_or_recovery_url",
            "gift_card_or_crypto_payment",
            "extortion_threat",
            "microsoft_lookalike_domain",
            "account_takeover_lure",
            "usaa_account_lure",
            "amex_account_lure",
        }
    )
    weak_scam_signal = scam_matched and not strong_scam_signal
    non_scam_phish_corroboration = sum(
        1
        for condition in (
            header_risk in {"medium", "high"},
            url_risk in {"medium", "high"} or url_suspicious,
            urgency_risk in {"medium", "high"} or urgent,
            has_phish_signal,
        )
        if condition
    )
    phish_corroboration = sum(
        1
        for condition in (
            header_risk in {"medium", "high"},
            url_risk in {"medium", "high"} or url_suspicious,
            scam_matched,
            urgency_risk in {"medium", "high"} or urgent,
            has_phish_signal,
        )
        if condition
    )

    if header_risk == "high" and (url_suspicious or scam_matched):
        return "Phishing"
    if content_high and account_or_security_context and phish_corroboration >= 1:
        return "Phishing"
    if content_elevated and account_or_security_context and phish_corroboration >= 2:
        return "Phishing"
    if has_phish_signal and (
        url_risk in {"medium", "high"} or url_suspicious or strong_scam_signal or header_risk in {"medium", "high"}
    ):
        return "Phishing"
    if url_risk == "high" and (has_phish_signal or strong_scam_signal):
        return "Phishing"
    if url_risk == "high" and header_risk == "high" and account_or_security_context:
        return "Phishing"
    if account_or_security_context and sum(
        1
        for condition in (
            header_risk in {"medium", "high"},
            url_risk in {"medium", "high"} or url_suspicious,
            scam_matched,
            urgency_risk in {"medium", "high"} or urgent,
            elevated_rspamd,
        )
        if condition
    ) >= 2:
        return "Phishing"
    if weak_scam_signal and not account_or_security_context and non_scam_phish_corroboration <= 1:
        return "Spam"
    if content_data is not None and not content_malicious and not spam_matched:
        return "Normal"

    if branded_marketing and corroborating_checks_low:
        return "Normal"
    if action == "reject" and header_format_noise and corroborating_checks_low:
        return "Normal"
    if content_high and not account_or_security_context:
        return "Spam"
    if content_elevated and (has_spam_signal or spam_matched or spam_risk in {"medium", "high"}):
        return "Spam"
    if spam_matched and (
        has_spam_signal
        or spam_risk == "high"
        or (url_risk in {"medium", "high"} and header_risk not in {"medium", "high"})
    ):
        return "Spam"
    if has_spam_signal and not has_phish_signal:
        return "Spam"
    if high_rspamd and not has_phish_signal and header_risk not in {"medium", "high"}:
        return "Spam"
    if risk == "high" and (urgent or url_risk == "medium") and not account_or_security_context:
        return "Spam"
    if content_malicious and not account_or_security_context and corroborating_checks_low:
        return "Spam"
    return "Normal"

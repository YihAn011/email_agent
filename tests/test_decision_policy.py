from skills.decision_policy import required_decision_label


def test_weak_reply_to_mismatch_becomes_spam_not_phishing():
    verdict = required_decision_label(
        rspamd_data={"score": 3.2, "risk_level": "low", "categories": [], "symbols": [], "action": "no action"},
        content_data={"is_malicious": False, "risk_level": "low", "malicious_score": 0.12},
        header_data={"risk_level": "low"},
        url_data={"risk_level": "low", "is_suspicious": False},
        urgency_data={"risk_contribution": "high", "is_urgent": True},
        scam_data={
            "matched": True,
            "indicators": ["official_claim_with_freemail_reply_to"],
        },
        spam_data={"matched": False, "risk_level": "low"},
        subject="USPS Expected Delivery on Friday",
        from_address="tracking@updates.example",
    )
    assert verdict == "Spam"


def test_strong_scam_and_suspicious_links_still_phishing():
    verdict = required_decision_label(
        rspamd_data={
            "score": 4.5,
            "risk_level": "medium",
            "categories": ["suspicious_links"],
            "symbols": [],
            "action": "add header",
        },
        content_data={"is_malicious": False, "risk_level": "low", "malicious_score": 0.21},
        header_data={"risk_level": "low"},
        url_data={"risk_level": "high", "is_suspicious": True},
        urgency_data={"risk_contribution": "medium", "is_urgent": True},
        scam_data={
            "matched": True,
            "indicators": ["account_takeover_lure"],
        },
        spam_data={"matched": False, "risk_level": "low"},
        subject="Verify your account now",
        from_address="support@example.com",
    )
    assert verdict == "Phishing"


def test_high_url_and_medium_header_without_phish_signals_is_not_phishing():
    verdict = required_decision_label(
        rspamd_data={
            "score": 1.39,
            "risk_level": "low",
            "categories": [],
            "symbols": [],
            "action": "no action",
        },
        content_data={"is_malicious": False, "risk_level": "low", "malicious_score": 0.14},
        header_data={"risk_level": "medium"},
        url_data={"risk_level": "high", "is_suspicious": True},
        urgency_data={"risk_contribution": "high", "is_urgent": True},
        scam_data={"matched": False, "indicators": []},
        spam_data={"matched": False, "risk_level": "low"},
        subject="See your April One Key overview",
        from_address="mail@eg.expedia.com",
    )
    assert verdict == "Normal"

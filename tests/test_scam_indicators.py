from skills.scam_indicators.schemas import ScamIndicatorCheckInput
from skills.scam_indicators.skill import ScamIndicatorCheckSkill


def test_reply_to_freemail_uses_real_header_not_body_noise():
    raw_email = (
        "From: AMD <news@updates.amd.com>\n"
        "Reply-To: team@gmail.com\n"
        "Subject: The Future of Performance is Here\n"
        "Content-Type: text/html; charset=utf-8\n"
        "\n"
        "<html><body><p>Launch news only.</p>"
        "<!-- bitcoin wallet: camera call police -->"
        "</body></html>\n"
    )

    result = ScamIndicatorCheckSkill().run(
        ScamIndicatorCheckInput(
            raw_email=raw_email,
            subject="The Future of Performance is Here",
            from_address="news@updates.amd.com",
        )
    )

    assert result.ok
    indicators = set(result.data.indicators)
    assert "gift_card_or_crypto_payment" not in indicators
    assert "extortion_threat" not in indicators


def test_crypto_phrase_in_visible_text_still_matches():
    raw_email = (
        "From: fake@example.com\n"
        "Subject: Action required\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "Buy a gift card or send bitcoin to this wallet: 123 now.\n"
    )

    result = ScamIndicatorCheckSkill().run(
        ScamIndicatorCheckInput(
            raw_email=raw_email,
            subject="Action required",
            from_address="fake@example.com",
        )
    )

    assert result.ok
    assert "gift_card_or_crypto_payment" in set(result.data.indicators)


def test_marketing_gift_card_offer_does_not_match_scam_payment():
    raw_email = (
        "From: store@example.com\n"
        "Subject: The Future of Performance is Here\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "Buy a new device today and get a $50 gift card. New camera system included.\n"
    )

    result = ScamIndicatorCheckSkill().run(
        ScamIndicatorCheckInput(
            raw_email=raw_email,
            subject="The Future of Performance is Here",
            from_address="store@example.com",
        )
    )

    assert result.ok
    indicators = set(result.data.indicators)
    assert "gift_card_or_crypto_payment" not in indicators
    assert "extortion_threat" not in indicators

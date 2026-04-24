from skills.content_model.schemas import ContentModelCheckInput
from skills.content_model.skill import _heuristic_score


def test_marketing_template_is_not_scored_as_malicious_by_heuristic():
    payload = ContentModelCheckInput(
        email_text=(
            "See your April One Key overview. "
            "Book now with this offer. "
            "Privacy. View online. Unsubscribe. Download the app. "
            "https://click.eg.expedia.com/u/?qs=abc123"
        ),
        subject="See your April One Key overview",
        from_address="mail@eg.expedia.com",
        sender_domain="eg.expedia.com",
        content_types="text/html",
    )

    assert _heuristic_score(payload) <= 0.3

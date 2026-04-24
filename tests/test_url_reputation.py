from skills.url_reputation.schemas import UrlReputationInput
from skills.url_reputation.skill import UrlReputationSkill


def test_legit_marketing_template_urls_are_dampened():
    email_text = """
    From: Expedia.com <mail@eg.expedia.com>
    Subject: See your April One Key overview
    List-Unsubscribe: <https://click.eg.expedia.com/subscription_center.aspx>

    Check out your latest One Key overview.
    Book now with this offer.
    Privacy
    View online
    Download the Expedia app

    https://click.eg.expedia.com/u/?qs=abc123
    https://image.eg.expedia.com/lib/banner.png
    https://a.travel-assets.com/travel-assets-manager/example.jpg
    """

    result = UrlReputationSkill().run(UrlReputationInput(email_text=email_text, subject="See your April One Key overview"))

    assert result.ok
    assert result.data is not None
    assert result.data.is_suspicious is False
    assert result.data.risk_level == "low"
    assert "dampened" in result.data.summary.lower()

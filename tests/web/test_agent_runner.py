from web.agent_runner import _extract_verdict, _skill_summary_from_tool_message
from unittest.mock import MagicMock

def test_phishing_verdict():
    assert _extract_verdict("This email is a phishing attempt.") == "phishing_or_spoofing"

def test_suspicious_verdict():
    assert _extract_verdict("The email looks suspicious due to urgency.") == "suspicious"

def test_benign_verdict():
    assert _extract_verdict("This is a legitimate email from Columbia IT.") == "benign"

def test_spoofing_verdict():
    assert _extract_verdict("Domain spoofing detected.") == "phishing_or_spoofing"

def test_default_conservative():
    assert _extract_verdict("Unable to determine conclusively.") == "suspicious"

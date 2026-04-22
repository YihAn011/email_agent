import pytest
from fastapi.testclient import TestClient
from web.server import app
import web.server as server

client = TestClient(app)

def test_status_returns_200():
    resp = client.get("/api/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "monitor_running" in data
    assert "result_count" in data
    assert "bound_mailboxes" in data

def test_emails_returns_list():
    resp = client.get("/api/emails")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_email_source_returns_raw_email(tmp_path, monkeypatch):
    mailbox_dir = tmp_path / "user_example_com"
    mailbox_dir.mkdir()
    eml_path = mailbox_dir / "42.eml"
    eml_path.write_text(
        "From: sender@example.com\nSubject: Test message\n\nHello world.\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(server, "MESSAGES_DIR", tmp_path)
    monkeypatch.setattr(
        server,
        "list_mailboxes",
        lambda: [{"email_address": "user@example.com"}],
    )
    monkeypatch.setattr(server, "sanitize_mailbox_dir", lambda _value: "user_example_com")

    resp = client.get("/api/email/42/source")
    assert resp.status_code == 200
    data = resp.json()
    assert data["uid"] == 42
    assert data["email_address"] == "user@example.com"
    assert data["subject"] == "Test message"
    assert "Hello world." in data["raw_email"]

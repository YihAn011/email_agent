import pytest
from fastapi.testclient import TestClient
from web.server import app

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

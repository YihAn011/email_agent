"""Lightweight mock Rspamd /checkv2 endpoint for local testing."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

MOCK_RESPONSE = {
    "is_skipped": False,
    "score": 14.7,
    "required_score": 15.0,
    "action": "add header",
    "thresholds": {
        "reject": 15.0,
        "add header": 6.0,
        "greylist": 4.0,
    },
    "symbols": {
        "PHISHING": {
            "name": "PHISHING",
            "score": 5.0,
            "description": "Phishing indicators detected",
            "options": ["example-payments-login-security.com"],
        },
        "DMARC_POLICY_ALLOW": {
            "name": "DMARC_POLICY_ALLOW",
            "score": -0.5,
            "description": "DMARC permit",
        },
        "SPF_FAIL": {
            "name": "SPF_FAIL",
            "score": 3.0,
            "description": "SPF check failed",
        },
        "BAYES_SPAM": {
            "name": "BAYES_SPAM",
            "score": 4.5,
            "description": "Bayesian classifier: spam",
        },
        "URL_SUSPICIOUS": {
            "name": "URL_SUSPICIOUS",
            "score": 2.5,
            "description": "Suspicious URL pattern",
            "options": ["http://example-payments-login-security.com/verify"],
        },
        "FREEMAIL_FROM": {
            "name": "FREEMAIL_FROM",
            "score": 0.2,
            "description": "Sender uses freemail service",
        },
    },
    "message-id": "12345@example-payments.com",
    "time_real": 0.042,
}


class MockRspamdHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/checkv2":
            body = json.dumps(MOCK_RESPONSE).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def log_message(self, fmt, *args):
        print(f"[mock-rspamd] {fmt % args}")


def main():
    server = HTTPServer(("127.0.0.1", 11333), MockRspamdHandler)
    print("[mock-rspamd] Listening on http://127.0.0.1:11333")
    server.serve_forever()


if __name__ == "__main__":
    main()

"""Automated tests for evidence redactor."""
import sys
from pathlib import Path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.services.evidence_redactor import (
    redact_headers,
    redact_body,
    redact_evidence,
    redact_value,
)


def test_redact_value_preserves_short_prefix():
    res = redact_value("secretpassword123", keep_prefix=4)
    assert res.startswith("secr")
    assert "[REDACTED]" in res
    assert "password123" not in res


def test_redact_headers_scrubs_authorization_and_cookies():
    headers = {
        "Authorization": "Bearer demo-token-alice-secret-12345",
        "Cookie": "session_id=abcdef123456",
        "Content-Type": "application/json",
        "Custom-Token": "Bearer token-value-here",
    }
    cleaned = redact_headers(headers)
    assert "[REDACTED]" in cleaned["Authorization"]
    assert "alice-secret-12345" not in cleaned["Authorization"]
    assert "[REDACTED]" in cleaned["Cookie"]
    assert "abcdef123456" not in cleaned["Cookie"]
    assert cleaned["Content-Type"] == "application/json"
    assert "token-value-here" not in cleaned["Custom-Token"]


def test_redact_body_recursive():
    body = {
        "id": "user-001",
        "username": "alice",
        "password_hash": "sha256$real_secret_hash_value",
        "api_key": "api-key-99999",
        "profile": {
            "email": "alice@demo.local",
            "internal_notes": "Highly confidential developer notes",
            "access_token": "token-12345",
        },
        "orders": [
            {"order_id": "1", "secret": "internal_order_secret"},
            {"order_id": "2", "product": "Standard License"}
        ]
    }
    redacted = redact_body(body)

    assert redacted["id"] == "user-001"
    assert redacted["username"] == "alice"
    assert "[REDACTED]" in redacted["password_hash"]
    assert "real_secret_hash_value" not in redacted["password_hash"]
    assert "[REDACTED]" in redacted["api_key"]
    assert "[REDACTED]" in redacted["profile"]["internal_notes"]
    assert "[REDACTED]" in redacted["profile"]["access_token"]
    assert "[REDACTED]" in redacted["orders"][0]["secret"]
    assert redacted["orders"][1]["product"] == "Standard License"


def test_redact_evidence_full():
    evidence = {
        "status_code": 200,
        "request_headers": {"Authorization": "Bearer super_secret_token"},
        "response_headers": {"Set-Cookie": "auth_cookie=12345"},
        "response_body": {
            "user": "alice",
            "password_hash": "$2b$12$e749823749823",
        },
        "token_used": "super_secret_token",
    }
    cleaned = redact_evidence(evidence)
    assert "super_secret_token" not in str(cleaned)
    assert "$2b$12$e749823749823" not in str(cleaned)
    assert cleaned["status_code"] == 200


def test_redacts_sensitive_pairs_inside_text_previews():
    """Regression: a raw JSON response stored as a text preview must not leak secrets
    (found while collecting test evidence: password_hash survived in response_preview)."""
    from app.services.evidence_redactor import redact_evidence
    preview = ('{"id":"user-alice-001","password_hash":"FAKE_HASH_NOT_REAL_a1b2c3d4",'
               '"api_key":"FAKE_API_KEY_alice_xyz789","internal_notes":"VIP","email":"a@demo.local"}')
    cleaned = redact_evidence({"status_code": 200, "response_preview": preview,
                               "repr": "{'password': 'pass1', 'username': 'name1'}"})
    text = str(cleaned)
    for secret in ("FAKE_HASH_NOT_REAL_a1b2c3d4", "FAKE_API_KEY_alice_xyz789", "pass1"):
        assert secret not in text
    assert "a@demo.local" in text and "user-alice-001" in text and "name1" in text  # non-sensitive data kept
    assert "[REDACTED]" in cleaned["response_preview"]

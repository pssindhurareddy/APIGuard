"""Evidence redaction engine.

Removes bearer tokens, API secrets, password hashes, and sensitive
headers before evidence is saved to SQLite or exported in reports.
"""
import re
from typing import Any

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
}

SENSITIVE_FIELD_NAMES = {
    "password",
    "password_hash",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "api_key",
    "private_key",
    "internal_notes",
    "ssn",
    "credit_card",
    "card_number",
    "db_connection_string",
}

TOKEN_PATTERN = re.compile(r'(Bearer\s+)[A-Za-z0-9\-._~+/]+=*', re.IGNORECASE)

# Sensitive "key": "value" pairs inside serialized text (e.g. a stored
# response_preview holding raw JSON, or a Python dict repr). Without this, a
# password hash inside a text preview would survive the object-level redaction.
_SENSITIVE_KEY_ALT = "|".join(sorted((re.escape(n) for n in SENSITIVE_FIELD_NAMES), key=len, reverse=True))
TEXT_PAIR_PATTERN = re.compile(
    r'(?P<key>(?P<q>["\'])[^"\']*(?:' + _SENSITIVE_KEY_ALT + r')[^"\']*(?P=q)\s*:\s*)'
    r'(?P<vq>["\'])(?P<val>[^"\']*)(?P=vq)',
    re.IGNORECASE,
)


def redact_text(text: str) -> str:
    """Redact bearer tokens and sensitive key/value pairs inside free text."""
    text = TOKEN_PATTERN.sub(r'\1[REDACTED]', text)
    return TEXT_PAIR_PATTERN.sub(
        lambda m: f"{m.group('key')}{m.group('vq')}{redact_value(m.group('val'))}{m.group('vq')}", text
    )


def redact_value(value: str, keep_prefix: int = 4) -> str:
    """Mask sensitive string value while retaining limited prefix for context."""
    if not isinstance(value, str):
        return "[REDACTED]"
    if len(value) <= keep_prefix:
        return "[REDACTED]"
    return value[:keep_prefix] + "...[REDACTED]"


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Scrub sensitive header keys and auth tokens."""
    redacted = {}
    for key, value in headers.items():
        k_lower = key.lower()
        if k_lower in SENSITIVE_HEADER_NAMES:
            redacted[key] = redact_value(str(value))
        else:
            redacted[key] = TOKEN_PATTERN.sub(r'\1[REDACTED]', str(value))
    return redacted


def redact_body(body: Any, depth: int = 0, max_depth: int = 10) -> Any:
    """Recursively redact sensitive attributes in JSON object hierarchies."""
    if depth > max_depth:
        return "[RECURSION_DEPTH_EXCEEDED]"

    if isinstance(body, dict):
        redacted = {}
        for key, value in body.items():
            k_lower = str(key).lower()
            if any(s in k_lower for s in SENSITIVE_FIELD_NAMES):
                redacted[key] = redact_value(str(value))
            else:
                redacted[key] = redact_body(value, depth + 1, max_depth)
        return redacted
    elif isinstance(body, list):
        return [redact_body(item, depth + 1, max_depth) for item in body[:50]]
    elif isinstance(body, str):
        return redact_text(body)
    else:
        return body


def redact_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Produce sanitized evidence dictionary safe for persistence and export."""
    if not isinstance(evidence, dict):
        return {}
    clean: dict[str, Any] = {}
    for key, value in evidence.items():
        if key in ("request_headers", "response_headers") and isinstance(value, dict):
            clean[key] = redact_headers(value)
        elif key in ("request_body", "response_body", "response_body_preview"):
            clean[key] = redact_body(value)
        elif isinstance(value, str) and any(s in key.lower() for s in ("token", "auth", "secret", "key", "password")):
            clean[key] = redact_value(value)
        else:
            # Everything else (e.g. response_preview text, nested lists) is still
            # scrubbed recursively: tokens and sensitive key/value pairs inside it.
            clean[key] = redact_body(value)
    return clean


"""Risk and confidence classification engine for APIGuard."""
from typing import Optional
from ..schemas.scan import Severity, Confidence

SEVERITY_TABLE = {
    # Authentication Checks
    "AUTH-001": Severity.HIGH,       # Unauthenticated access to protected endpoint
    "AUTH-002": Severity.HIGH,       # Forged/invalid bearer token accepted
    "AUTH-003": Severity.MEDIUM,     # Identity mismatch between token and resource
    "AUTH-004": Severity.MEDIUM,     # Auth policy mismatch

    # Authorization Checks
    "AUTHZ-001": Severity.CRITICAL,  # Cross-user object access / BOLA
    "AUTHZ-002": Severity.HIGH,      # Privilege escalation to admin endpoint
    "AUTHZ-003": Severity.CRITICAL,  # Missing object-level authorization
    "AUTHZ-004": Severity.MEDIUM,    # Role authorization inconsistency

    # Input Validation Checks
    "INPUT-001": Severity.MEDIUM,    # Missing required field accepted
    "INPUT-002": Severity.MEDIUM,    # Invalid data type accepted
    "INPUT-003": Severity.MEDIUM,    # Boundary / numeric range violation accepted
    "INPUT-004": Severity.LOW,       # Malformed JSON parsing error / 500
    "INPUT-005": Severity.LOW,       # Unexpected field handling

    # Data Exposure Checks
    "DATA-001": Severity.HIGH,       # Forbidden sensitive field leaked (e.g. hash, secret)
    "DATA-002": Severity.MEDIUM,     # Response fields exceed declared allowlist
    "DATA-003": Severity.HIGH,       # Nested sensitive data leakage
    "DATA-004": Severity.MEDIUM,     # Minimal response principle violation
}


def classify_severity(test_id: str, default: Severity = Severity.MEDIUM) -> Severity:
    """Determine finding severity from test specification."""
    return SEVERITY_TABLE.get(test_id, default)


def classify_confidence(
    expected_status: Optional[int],
    actual_status: Optional[int],
    has_policy: bool,
    has_body_evidence: bool,
) -> Confidence:
    """Determine confidence score based on objective test evidence vs heuristics."""
    if has_policy and has_body_evidence and expected_status is not None and actual_status is not None:
        return Confidence.HIGH
    if has_body_evidence and (has_policy or actual_status is not None):
        return Confidence.MEDIUM
    return Confidence.LOW


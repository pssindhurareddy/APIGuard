"""Base class and common data models for security check implementations."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional
import hashlib
import uuid


@dataclass
class CheckResult:
    """Standardized result schema produced by any security check execution."""
    test_id: str
    test_name: str
    category: str
    endpoint: str
    http_method: str
    status: str  # PASS, CONFIRMED, SUSPECTED, ERROR, SKIPPED
    severity: str
    confidence: str
    expected_result: str = ""
    actual_result: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    explanation: str = ""
    remediation: str = ""
    impact: str = ""
    preconditions: str = ""
    limitations: str = ""
    duration_ms: float = 0.0
    fingerprint: str = ""

    def __post_init__(self):
        if not self.fingerprint:
            raw = f"{self.test_id}:{self.endpoint}:{self.http_method}"
            self.fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class BaseCheck(ABC):
    """Abstract base class for modular security checks."""

    def __init__(self, request_engine: Any, target_config: dict[str, Any]):
        self.engine = request_engine
        self.target = target_config
        self.base_url = target_config.get("base_url", "").rstrip("/")

    @property
    @abstractmethod
    def category(self) -> str:
        """Category string identifier."""
        ...

    @abstractmethod
    async def run(self) -> list[CheckResult]:
        """Execute test suite and return granular results."""
        ...

    def _url(self, path: str) -> str:
        """Construct full target URL from endpoint path."""
        p = path if path.startswith("/") else f"/{path}"
        return f"{self.base_url}{p}"

    @staticmethod
    def _fill_path(path: str, resources: dict[str, Any]) -> str:
        """Replace every {placeholder} in a path template with the matching value."""
        for key, value in (resources or {}).items():
            path = path.replace("{" + key + "}", str(value))
        return path

    def _resolve_path(self, path: str, profile_name: str = "alice") -> str:
        """Substitute templated path parameters (e.g. {order_id}) with the
        synthetic resource IDs declared in target test_resources, so probes hit
        a real object instead of the literal template (which yields 404/422 noise)."""
        resources = self.target.get("test_resources", {}).get(profile_name, {})
        return self._fill_path(path, resources)

    @staticmethod
    def _materialize(value: Any) -> Any:
        """Replace the "{unique}" token in example bodies with a fresh random value,
        so repeated probes (e.g. user registration) never collide."""
        if isinstance(value, str) and "{unique}" in value:
            return value.replace("{unique}", uuid.uuid4().hex[:10])
        if isinstance(value, dict):
            return {k: BaseCheck._materialize(v) for k, v in value.items()}
        if isinstance(value, list):
            return [BaseCheck._materialize(v) for v in value]
        return value

    def _example_body(self, schema: dict[str, Any]) -> dict[str, Any]:
        """Fresh copy of a policy's example_body with placeholders materialized."""
        return self._materialize(dict(schema.get("example_body", {}) or {}))

    def _probe_body(self, endpoint_policy: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Return a schema-valid example body for write endpoints so that
        authentication probes are not rejected by input validation first."""
        if endpoint_policy.get("method", "GET").upper() in ("POST", "PUT", "PATCH"):
            return self._example_body(endpoint_policy.get("request_schema", {}))
        return None

    def _get_auth_header(self, profile_name: str) -> dict[str, str]:
        """Retrieve Bearer authorization header for a named test profile."""
        profiles = self.target.get("auth_profiles", {})
        profile = profiles.get(profile_name, {})
        token = profile.get("token", "")
        if token:
            return {"Authorization": f"Bearer {token}"}
        return {}

    @staticmethod
    def _get_field(body: Any, dotted: str) -> Any:
        """Read a possibly nested field, e.g. "data.username"."""
        cur = body
        for part in dotted.split("."):
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        return cur

    def _get_profile_username(self, profile_name: str) -> str:
        """Retrieve username for named profile."""
        profiles = self.target.get("auth_profiles", {})
        profile = profiles.get(profile_name, {})
        return profile.get("username", profile_name)

    def _make_result(
        self,
        test_id: str,
        test_name: str,
        endpoint: str,
        method: str,
        status: str,
        severity: str,
        confidence: str,
        expected: str = "",
        actual: str = "",
        evidence: Optional[dict[str, Any]] = None,
        explanation: str = "",
        remediation: str = "",
        impact: str = "",
        preconditions: str = "",
        limitations: str = "",
        duration_ms: float = 0.0,
    ) -> CheckResult:
        return CheckResult(
            test_id=test_id,
            test_name=test_name,
            category=self.category,
            endpoint=endpoint,
            http_method=method,
            status=status,
            severity=severity,
            confidence=confidence,
            expected_result=expected,
            actual_result=actual,
            evidence=evidence or {},
            explanation=explanation,
            remediation=remediation,
            impact=impact,
            preconditions=preconditions,
            limitations=limitations,
            duration_ms=duration_ms,
        )


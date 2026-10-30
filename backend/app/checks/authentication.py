"""Authentication Security Checks (AUTH-001 through AUTH-004)."""
import time
from typing import Any
from .base import BaseCheck, CheckResult


class AuthenticationCheck(BaseCheck):
    """Evaluates token requirement, validation rigor, and identity accuracy."""

    @property
    def category(self) -> str:
        return "authentication"

    async def run(self) -> list[CheckResult]:
        results: list[CheckResult] = []
        results.extend(await self._check_missing_token())
        results.extend(await self._check_invalid_token())
        results.extend(await self._check_identity_validation())
        results.extend(await self._check_inconsistent_policy())
        return results

    async def _check_missing_token(self) -> list[CheckResult]:
        """AUTH-001: Request configured protected endpoint without authentication."""
        results: list[CheckResult] = []
        policies = self.target.get("endpoint_policies", [])
        protected_eps = [ep for ep in policies if ep.get("authentication_required", False)]

        if not protected_eps:
            results.append(self._make_result(
                test_id="AUTH-001",
                test_name="Missing Authentication Token",
                endpoint="N/A",
                method="GET",
                status="SKIPPED",
                severity="INFO",
                confidence="LOW",
                expected="Declared protected endpoints in target policy",
                actual="No endpoints have authentication_required=true",
                preconditions="Requires target policy containing endpoints with authentication_required=true",
            ))
            return results

        for ep in protected_eps:
            path = ep.get("path", "")
            method = ep.get("method", "GET")
            url = self._url(self._resolve_path(path))
            body = self._probe_body(ep)
            start = time.monotonic()

            result = await self.engine.request(method, url, json_body=body)
            duration = (time.monotonic() - start) * 1000

            if not result.success:
                results.append(self._make_result(
                    test_id="AUTH-001",
                    test_name="Missing Authentication Token",
                    endpoint=path,
                    method=method,
                    status="ERROR",
                    severity="INFO",
                    confidence="LOW",
                    expected="Server responds to unauthenticated probe",
                    actual=f"Network error: {result.error}",
                    evidence={"error": result.error},
                    duration_ms=duration,
                ))
                continue

            if result.status_code in (401, 403):
                results.append(self._make_result(
                    test_id="AUTH-001",
                    test_name="Missing Authentication Token",
                    endpoint=path,
                    method=method,
                    status="PASS",
                    severity="INFO",
                    confidence="HIGH",
                    expected="HTTP 401 Unauthorized or 403 Forbidden without credentials",
                    actual=f"HTTP {result.status_code} received with access denied",
                    evidence={
                        "status_code": result.status_code,
                        "response_preview": str(result.body_text)[:200],
                    },
                    explanation="Endpoint enforces mandatory authentication; unauthenticated request was rejected.",
                    duration_ms=duration,
                ))
            elif result.status_code == 200:
                results.append(self._make_result(
                    test_id="AUTH-001",
                    test_name="Missing Authentication Token",
                    endpoint=path,
                    method=method,
                    status="CONFIRMED",
                    severity="HIGH",
                    confidence="HIGH",
                    expected="HTTP 401/403 for missing credentials on protected endpoint",
                    actual="HTTP 200 OK returned with protected response data",
                    evidence={
                        "status_code": result.status_code,
                        "response_body_keys": list(result.body.keys()) if isinstance(result.body, dict) else None,
                        "response_preview": str(result.body_text)[:300],
                    },
                    explanation=(
                        f"The endpoint {path} is declared as requiring authentication, "
                        "but returned HTTP 200 with data when called without an Authorization header."
                    ),
                    remediation=(
                        "Implement authentication middleware or dependency injection on the route. "
                        "Verify Bearer token presence and reject missing tokens with HTTP 401."
                    ),
                    impact="Anonymous clients can access protected endpoints and read private information.",
                    duration_ms=duration,
                ))
            else:
                results.append(self._make_result(
                    test_id="AUTH-001",
                    test_name="Missing Authentication Token",
                    endpoint=path,
                    method=method,
                    status="SUSPECTED",
                    severity="MEDIUM",
                    confidence="LOW",
                    expected="HTTP 401/403",
                    actual=f"Unexpected HTTP status {result.status_code}",
                    evidence={"status_code": result.status_code},
                    explanation=f"Received unexpected status {result.status_code}. Further manual review recommended.",
                    duration_ms=duration,
                ))

        return results

    async def _check_invalid_token(self) -> list[CheckResult]:
        """AUTH-002: Request protected endpoint with invalid bearer token."""
        results: list[CheckResult] = []
        policies = self.target.get("endpoint_policies", [])
        protected_eps = [ep for ep in policies if ep.get("authentication_required", False)]

        if not protected_eps:
            results.append(self._make_result(
                test_id="AUTH-002",
                test_name="Invalid Authentication Token",
                endpoint="N/A",
                method="GET",
                status="SKIPPED",
                severity="INFO",
                confidence="LOW",
                preconditions="Requires declared protected endpoints",
            ))
            return results

        for ep in protected_eps:
            path = ep.get("path", "")
            method = ep.get("method", "GET")
            url = self._url(self._resolve_path(path))
            body = self._probe_body(ep)
            start = time.monotonic()

            headers = {"Authorization": "Bearer forged-synthetic-token-invalid-999"}
            result = await self.engine.request(method, url, headers=headers, json_body=body)
            duration = (time.monotonic() - start) * 1000

            if not result.success:
                results.append(self._make_result(
                    test_id="AUTH-002",
                    test_name="Invalid Authentication Token",
                    endpoint=path,
                    method=method,
                    status="ERROR",
                    severity="INFO",
                    confidence="LOW",
                    actual=f"Request failed: {result.error}",
                    duration_ms=duration,
                ))
                continue

            if result.status_code in (401, 403):
                results.append(self._make_result(
                    test_id="AUTH-002",
                    test_name="Invalid Authentication Token",
                    endpoint=path,
                    method=method,
                    status="PASS",
                    severity="INFO",
                    confidence="HIGH",
                    expected="HTTP 401/403 for invalid token",
                    actual=f"HTTP {result.status_code} returned (token rejected)",
                    evidence={"status_code": result.status_code},
                    explanation="Endpoint validates token signature/store and rejected the fake token.",
                    duration_ms=duration,
                ))
            elif result.status_code == 200:
                results.append(self._make_result(
                    test_id="AUTH-002",
                    test_name="Invalid Authentication Token",
                    endpoint=path,
                    method=method,
                    status="CONFIRMED",
                    severity="HIGH",
                    confidence="HIGH",
                    expected="HTTP 401/403 rejecting invalid token",
                    actual="HTTP 200 OK returned with data despite invalid bearer token",
                    evidence={
                        "status_code": result.status_code,
                        "token_format": "Synthetic invalid token",
                    },
                    explanation=(
                        f"The endpoint {path} accepted an invalid, forged bearer token "
                        "and returned HTTP 200. Token cryptographic signature or lookup validation is absent."
                    ),
                    remediation=(
                        "Validate all incoming Bearer tokens against the token authority or session store. "
                        "Return HTTP 401 when token is invalid, expired, or malformed."
                    ),
                    impact="Attackers can bypass authentication using arbitrary token values.",
                    duration_ms=duration,
                ))
            else:
                results.append(self._make_result(
                    test_id="AUTH-002",
                    test_name="Invalid Authentication Token",
                    endpoint=path,
                    method=method,
                    status="SUSPECTED",
                    severity="MEDIUM",
                    confidence="LOW",
                    expected="HTTP 401/403",
                    actual=f"HTTP {result.status_code}",
                    evidence={"status_code": result.status_code},
                    explanation=f"Received unexpected status {result.status_code}. Further manual review recommended.",
                    duration_ms=duration,
                ))

        return results

    async def _check_identity_validation(self) -> list[CheckResult]:
        """AUTH-003: Check if returned profile identity matches authenticated user."""
        results: list[CheckResult] = []
        policies = self.target.get("endpoint_policies", [])
        identity_eps = [
            ep for ep in policies
            if ep.get("returns_identity", False) and ep.get("authentication_required", False)
        ]

        if not identity_eps:
            results.append(self._make_result(
                test_id="AUTH-003",
                test_name="Identity Validation",
                endpoint="N/A",
                method="GET",
                status="SKIPPED",
                severity="INFO",
                confidence="LOW",
                preconditions="Requires endpoint with returns_identity=true",
            ))
            return results

        # Select Alice profile
        alice_header = self._get_auth_header("alice")
        if not alice_header:
            results.append(self._make_result(
                test_id="AUTH-003",
                test_name="Identity Validation",
                endpoint="N/A",
                method="GET",
                status="SKIPPED",
                severity="INFO",
                confidence="LOW",
                preconditions="Alice auth profile required for identity validation test",
            ))
            return results

        for ep in identity_eps:
            path = ep.get("path", "")
            method = ep.get("method", "GET")
            field_name = ep.get("identity_field", "username")
            url = self._url(path)
            start = time.monotonic()

            result = await self.engine.request(method, url, headers=alice_header)
            duration = (time.monotonic() - start) * 1000

            if not result.success:
                results.append(self._make_result(
                    test_id="AUTH-003",
                    test_name="Identity Validation",
                    endpoint=path,
                    method=method,
                    status="ERROR",
                    severity="INFO",
                    confidence="LOW",
                    actual=f"Request failed: {result.error}",
                    duration_ms=duration,
                ))
                continue

            if result.status_code == 200 and isinstance(result.body, dict):
                actual_user = self._get_field(result.body, field_name)
                expected_user = self._get_profile_username("alice")
                if actual_user == expected_user:
                    results.append(self._make_result(
                        test_id="AUTH-003",
                        test_name="Identity Validation",
                        endpoint=path,
                        method=method,
                        status="PASS",
                        severity="INFO",
                        confidence="HIGH",
                        expected=f"Response field '{field_name}' equals 'alice'",
                        actual=f"Response field '{field_name}' matches authenticated identity ('alice')",
                        evidence={"identity_field": field_name, "value": actual_user},
                        explanation="Identity returned by the endpoint accurately reflects authenticated user.",
                        duration_ms=duration,
                    ))
                else:
                    results.append(self._make_result(
                        test_id="AUTH-003",
                        test_name="Identity Validation",
                        endpoint=path,
                        method=method,
                        status="CONFIRMED",
                        severity="MEDIUM",
                        confidence="HIGH",
                        expected=f"Response field '{field_name}' equals 'alice'",
                        actual=f"Response field '{field_name}' returned '{actual_user}'",
                        evidence={"expected": expected_user, "actual": actual_user},
                        explanation="Endpoint returned an identity disparate from the authenticated caller.",
                        remediation="Bind identity extraction strictly to token claims.",
                        impact="Session leakage or incorrect user data binding.",
                        duration_ms=duration,
                    ))
            else:
                results.append(self._make_result(
                    test_id="AUTH-003",
                    test_name="Identity Validation",
                    endpoint=path,
                    method=method,
                    status="SUSPECTED",
                    severity="MEDIUM",
                    confidence="LOW",
                    actual=f"Status {result.status_code}, unexpected response structure",
                    duration_ms=duration,
                ))

        return results

    async def _check_inconsistent_policy(self) -> list[CheckResult]:
        """AUTH-004: Compare observed auth behavior vs declared endpoint policy."""
        results: list[CheckResult] = []
        policies = self.target.get("endpoint_policies", [])

        for ep in policies:
            auth_required = ep.get("authentication_required")
            if auth_required is None:
                continue

            path = ep.get("path", "")
            method = ep.get("method", "GET")
            url = self._url(self._resolve_path(path))
            body = self._probe_body(ep)
            start = time.monotonic()

            result = await self.engine.request(method, url, json_body=body)
            duration = (time.monotonic() - start) * 1000

            if not result.success:
                continue

            permits_unauthenticated = (result.status_code == 200)

            if auth_required and permits_unauthenticated:
                results.append(self._make_result(
                    test_id="AUTH-004",
                    test_name="Authentication Policy Consistency",
                    endpoint=path,
                    method=method,
                    status="CONFIRMED",
                    severity="MEDIUM",
                    confidence="HIGH",
                    expected="Policy declares authentication_required=true -> expected 401/403",
                    actual=f"Endpoint returned HTTP {result.status_code} without authentication",
                    evidence={"declared_auth_required": True, "observed_status": result.status_code},
                    explanation=f"Specification states {path} requires authentication, but server allowed unauthenticated access.",
                    remediation="Align implementation with documented security policy.",
                    impact="Configuration drift leaving intended protections disabled.",
                    duration_ms=duration,
                ))
            elif not auth_required and not permits_unauthenticated:
                results.append(self._make_result(
                    test_id="AUTH-004",
                    test_name="Authentication Policy Consistency",
                    endpoint=path,
                    method=method,
                    status="SUSPECTED",
                    severity="LOW",
                    confidence="MEDIUM",
                    expected="Policy declares public access -> expected 200",
                    actual=f"Endpoint returned HTTP {result.status_code}",
                    explanation="Endpoint blocked access despite policy declaring public availability.",
                    duration_ms=duration,
                ))
            else:
                results.append(self._make_result(
                    test_id="AUTH-004",
                    test_name="Authentication Policy Consistency",
                    endpoint=path,
                    method=method,
                    status="PASS",
                    severity="INFO",
                    confidence="HIGH",
                    expected="Observed behavior conforms to policy specification",
                    actual=f"Observed access control matches policy (auth_required={auth_required})",
                    duration_ms=duration,
                ))

        return results


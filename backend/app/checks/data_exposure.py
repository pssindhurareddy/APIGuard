"""Excessive Data Exposure Security Checks (DATA-001 through DATA-004)."""
import time
from typing import Any
from .base import BaseCheck, CheckResult

DEFAULT_SENSITIVE_PATTERNS = {
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
    "internal_config",
}


class DataExposureCheck(BaseCheck):
    """Evaluates API response serialization for sensitive fields and schema leakage."""

    @property
    def category(self) -> str:
        return "data_exposure"

    async def run(self) -> list[CheckResult]:
        results: list[CheckResult] = []
        results.extend(await self._check_sensitive_fields())
        results.extend(await self._check_response_allowlist())
        results.extend(await self._check_nested_exposure())
        results.extend(await self._check_minimal_response())
        return results

    def _get_patterns(self) -> set[str]:
        custom = self.target.get("sensitive_field_patterns", [])
        return DEFAULT_SENSITIVE_PATTERNS | set(custom)

    def _find_sensitive_fields(
        self, obj: Any, current_path: str = "", depth: int = 0, max_depth: int = 10
    ) -> list[dict[str, Any]]:
        """Recursively scan dictionaries and arrays for sensitive key names."""
        if depth > max_depth:
            return []

        hits: list[dict[str, Any]] = []
        patterns = self._get_patterns()

        if isinstance(obj, dict):
            for key, val in obj.items():
                p = f"{current_path}.{key}" if current_path else str(key)
                if str(key).lower() in patterns:
                    hits.append({
                        "field": str(key),
                        "path": p,
                        "value_type": type(val).__name__,
                        "present": val is not None,
                    })
                hits.extend(self._find_sensitive_fields(val, p, depth + 1, max_depth))
        elif isinstance(obj, list):
            for idx, item in enumerate(obj[:20]):
                p = f"{current_path}[{idx}]"
                hits.extend(self._find_sensitive_fields(item, p, depth + 1, max_depth))

        return hits

    async def _check_sensitive_fields(self) -> list[CheckResult]:
        """DATA-001: Detect sensitive attributes (passwords, tokens, internal notes) in responses."""
        results: list[CheckResult] = []
        policies = self.target.get("endpoint_policies", [])
        data_eps = [
            ep for ep in policies
            if ep.get("check_data_exposure", True) and ep.get("method", "GET") == "GET"
        ]

        if not data_eps:
            results.append(self._make_result(
                test_id="DATA-001",
                test_name="Sensitive Field Detection",
                endpoint="N/A",
                method="GET",
                status="SKIPPED",
                severity="INFO",
                confidence="LOW",
                preconditions="Requires GET endpoints with check_data_exposure=true",
            ))
            return results

        auth_header = self._get_auth_header("alice")

        for ep in data_eps:
            path = ep.get("path", "")
            # Fill placeholder if path requires order_id or user_id
            test_res = self.target.get("test_resources", {}).get("alice", {})
            concrete_path = (
                self._fill_path(path, {"order_id": "order-1001", "user_id": "user-alice-001", **test_res})
            )

            url = self._url(concrete_path)
            method = ep.get("method", "GET")
            forbidden_declared = set(ep.get("forbidden_response_fields", []))

            start = time.monotonic()
            result = await self.engine.request(method, url, headers=auth_header)
            duration = (time.monotonic() - start) * 1000

            if not result.success:
                continue

            if result.status_code != 200 or not isinstance(result.body, (dict, list)):
                continue

            hits = self._find_sensitive_fields(result.body)

            # Filter against forbidden policy if declared, or default sensitive names
            matched_findings = []
            for h in hits:
                if forbidden_declared:
                    if h["field"].lower() in forbidden_declared or h["field"] in forbidden_declared:
                        matched_findings.append(h)
                else:
                    matched_findings.append(h)

            if not matched_findings:
                results.append(self._make_result(
                    test_id="DATA-001",
                    test_name="Sensitive Field Detection",
                    endpoint=path,
                    method=method,
                    status="PASS",
                    severity="INFO",
                    confidence="HIGH",
                    expected="Response contains zero forbidden or sensitive credential fields",
                    actual="No sensitive field patterns detected in response payload",
                    duration_ms=duration,
                ))
            else:
                field_names = [f["path"] for f in matched_findings]
                results.append(self._make_result(
                    test_id="DATA-001",
                    test_name="Sensitive Field Detection",
                    endpoint=path,
                    method=method,
                    status="CONFIRMED",
                    severity="HIGH",
                    confidence="HIGH",
                    expected="Response must omit sensitive/forbidden credential fields",
                    actual=f"Response leaked {len(matched_findings)} sensitive attribute(s): {', '.join(field_names)}",
                    evidence={
                        "leaked_fields": matched_findings,
                        "endpoint": concrete_path,
                    },
                    explanation=(
                        f"Excessive Data Exposure: Endpoint {concrete_path} returned sensitive fields "
                        f"({', '.join(field_names)}) in the JSON response body. "
                        "The declared policy prohibits these attributes from external disclosure."
                    ),
                    remediation=(
                        "Implement response DTOs (Data Transfer Objects) or Pydantic output models "
                        "that explicitly select only safe, consumer-facing fields. Exclude database entity internal fields."
                    ),
                    impact="Credential theft, password hash exposure for offline cracking, or API key compromise.",
                    duration_ms=duration,
                ))

        return results

    async def _check_response_allowlist(self) -> list[CheckResult]:
        """DATA-002: Compare response fields against explicit target allowlist."""
        results: list[CheckResult] = []
        policies = self.target.get("endpoint_policies", [])
        allowlist_eps = [
            ep for ep in policies
            if ep.get("allowed_response_fields") and ep.get("method", "GET") == "GET"
        ]

        if not allowlist_eps:
            return results

        auth_header = self._get_auth_header("alice")

        for ep in allowlist_eps:
            path = ep.get("path", "")
            test_res = self.target.get("test_resources", {}).get("alice", {})
            concrete_path = (
                self._fill_path(path, {"order_id": "order-1001", "user_id": "user-alice-001", **test_res})
            )
            allowed = set(ep.get("allowed_response_fields", []))
            url = self._url(concrete_path)
            method = ep.get("method", "GET")

            start = time.monotonic()
            result = await self.engine.request(method, url, headers=auth_header)
            duration = (time.monotonic() - start) * 1000

            if not result.success or result.status_code != 200 or not isinstance(result.body, dict):
                continue

            actual_fields = set(result.body.keys())
            unexpected = actual_fields - allowed

            if not unexpected:
                results.append(self._make_result(
                    test_id="DATA-002",
                    test_name="Response Field Allowlist",
                    endpoint=path,
                    method=method,
                    status="PASS",
                    severity="INFO",
                    confidence="HIGH",
                    expected=f"Response properties strictly match allowlist: {sorted(allowed)}",
                    actual=f"All {len(actual_fields)} returned fields are within permitted allowlist",
                    duration_ms=duration,
                ))
            else:
                results.append(self._make_result(
                    test_id="DATA-002",
                    test_name="Response Field Allowlist",
                    endpoint=path,
                    method=method,
                    status="CONFIRMED",
                    severity="MEDIUM",
                    confidence="HIGH",
                    expected=f"Response properties strictly limited to: {sorted(allowed)}",
                    actual=f"Found {len(unexpected)} unapproved attribute(s): {sorted(unexpected)}",
                    evidence={
                        "allowed_fields": sorted(allowed),
                        "actual_fields": sorted(actual_fields),
                        "extra_fields": sorted(unexpected),
                    },
                    explanation=f"Endpoint {path} exposed unapproved fields not present in the API contract allowlist.",
                    remediation="Configure serialization filters to exclude unwhitelisted attributes.",
                    impact="Information disclosure of internal system state and schema structure.",
                    duration_ms=duration,
                ))

        return results

    async def _check_nested_exposure(self) -> list[CheckResult]:
        """DATA-003: Deeply inspect nested dictionaries for sensitive keys."""
        results: list[CheckResult] = []
        policies = self.target.get("endpoint_policies", [])
        data_eps = [ep for ep in policies if ep.get("method", "GET") == "GET"]
        auth_header = self._get_auth_header("alice")

        nested_hits = []
        for ep in data_eps:
            path = ep.get("path", "")
            test_res = self.target.get("test_resources", {}).get("alice", {})
            concrete_path = (
                self._fill_path(path, {"order_id": "order-1001", "user_id": "user-alice-001", **test_res})
            )
            url = self._url(concrete_path)

            start = time.monotonic()
            result = await self.engine.request("GET", url, headers=auth_header)
            duration = (time.monotonic() - start) * 1000

            if not result.success or result.status_code != 200 or not isinstance(result.body, (dict, list)):
                continue

            hits = self._find_sensitive_fields(result.body)
            # Retain only nested attributes (path contains a dot or bracket)
            nested_only = [h for h in hits if "." in h["path"] or "[" in h["path"]]
            if nested_only:
                nested_hits.extend(nested_only)
                results.append(self._make_result(
                    test_id="DATA-003",
                    test_name="Nested Object Inspection",
                    endpoint=path,
                    method="GET",
                    status="CONFIRMED",
                    severity="HIGH",
                    confidence="HIGH",
                    expected="Nested structures contain no sensitive keys",
                    actual=f"Found {len(nested_only)} sensitive field(s) in nested object graph",
                    evidence={"nested_findings": nested_only},
                    explanation=f"Sensitive keys leaked in nested sub-objects on {concrete_path}.",
                    remediation="Apply recursive filtering on serialized models before response dispatch.",
                    impact="Hidden leakage of internal configuration or credentials.",
                    duration_ms=duration,
                ))

        if not results:
            results.append(self._make_result(
                test_id="DATA-003",
                test_name="Nested Object Inspection",
                endpoint="all_get_routes",
                method="GET",
                status="PASS",
                severity="INFO",
                confidence="MEDIUM",
                expected="Nested response hierarchies clean of sensitive keys",
                actual="Zero nested sensitive attributes found across tested endpoints",
            ))

        return results

    async def _check_minimal_response(self) -> list[CheckResult]:
        """DATA-004: Validate response conforms to minimal data exposure principle."""
        results: list[CheckResult] = []
        policies = self.target.get("endpoint_policies", [])
        minimal_eps = [
            ep for ep in policies
            if ep.get("allowed_response_fields") and ep.get("method", "GET") == "GET"
        ]

        if not minimal_eps:
            return results

        auth_header = self._get_auth_header("alice")

        for ep in minimal_eps:
            path = ep.get("path", "")
            test_res = self.target.get("test_resources", {}).get("alice", {})
            concrete_path = (
                self._fill_path(path, {"order_id": "order-1001", "user_id": "user-alice-001", **test_res})
            )
            allowed = set(ep.get("allowed_response_fields", []))
            url = self._url(concrete_path)

            start = time.monotonic()
            result = await self.engine.request("GET", url, headers=auth_header)
            duration = (time.monotonic() - start) * 1000

            if not result.success or result.status_code != 200 or not isinstance(result.body, dict):
                continue

            actual_fields = set(result.body.keys())
            extra = actual_fields - allowed

            if not extra:
                results.append(self._make_result(
                    test_id="DATA-004",
                    test_name="Minimal Response Validation",
                    endpoint=path,
                    method="GET",
                    status="PASS",
                    severity="INFO",
                    confidence="HIGH",
                    expected="Response adheres to minimal attribute exposure principle",
                    actual="Returned attributes are minimal and within specification",
                    duration_ms=duration,
                ))
            else:
                results.append(self._make_result(
                    test_id="DATA-004",
                    test_name="Minimal Response Validation",
                    endpoint=path,
                    method="GET",
                    status="CONFIRMED",
                    severity="MEDIUM",
                    confidence="HIGH",
                    expected=f"Attributes bounded strictly to: {sorted(allowed)}",
                    actual=f"Excessive attributes returned: {sorted(extra)}",
                    evidence={"extra_attributes": sorted(extra)},
                    explanation=f"Endpoint {concrete_path} exposes more object data than required by the client use-case.",
                    remediation="Apply principle of least privilege to API payload schemas.",
                    duration_ms=duration,
                ))

        return results


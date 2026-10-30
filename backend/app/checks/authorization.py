"""Authorization Security Checks (AUTHZ-001 through AUTHZ-004)."""
import time
from typing import Any
from .base import BaseCheck, CheckResult


class AuthorizationCheck(BaseCheck):
    """Evaluates Broken Object Level Authorization (BOLA), RBAC, and object tenancy."""

    @property
    def category(self) -> str:
        return "authorization"

    async def run(self) -> list[CheckResult]:
        results: list[CheckResult] = []
        results.extend(await self._check_cross_user_access())
        results.extend(await self._check_privileged_function())
        results.extend(await self._check_reverse_object_access())
        results.extend(await self._check_policy_consistency())
        return results

    async def _check_cross_user_access(self) -> list[CheckResult]:
        """AUTHZ-001: Cross-user object access (Alice accesses Bob's resource)."""
        results: list[CheckResult] = []
        policies = self.target.get("endpoint_policies", [])
        owner_eps = [ep for ep in policies if ep.get("ownership_required", False)]

        if not owner_eps:
            results.append(self._make_result(
                test_id="AUTHZ-001",
                test_name="Cross-User Object Access (BOLA)",
                endpoint="N/A",
                method="GET",
                status="SKIPPED",
                severity="INFO",
                confidence="LOW",
                preconditions="Requires endpoints with ownership_required=true",
            ))
            return results

        test_resources = self.target.get("test_resources", {})
        alice_header = self._get_auth_header("alice")
        bob_resources = test_resources.get("bob", {})

        if not alice_header or not bob_resources:
            results.append(self._make_result(
                test_id="AUTHZ-001",
                test_name="Cross-User Object Access (BOLA)",
                endpoint="N/A",
                method="GET",
                status="SKIPPED",
                severity="INFO",
                confidence="LOW",
                preconditions="Both Alice profile and Bob test resources must be configured",
            ))
            return results

        for ep in owner_eps:
            path_tmpl = ep.get("path", "")
            method = ep.get("method", "GET")
            res_key = ep.get("resource_key", "order_id")
            bob_res_id = bob_resources.get(res_key)

            if not bob_res_id:
                continue

            # Concrete path: Alice requesting Bob's resource ID
            path = self._fill_path(path_tmpl, {**bob_resources, res_key: bob_res_id})
            url = self._url(path)
            start = time.monotonic()

            result = await self.engine.request(method, url, headers=alice_header)
            duration = (time.monotonic() - start) * 1000

            if not result.success:
                results.append(self._make_result(
                    test_id="AUTHZ-001",
                    test_name="Cross-User Object Access (BOLA)",
                    endpoint=path_tmpl,
                    method=method,
                    status="ERROR",
                    severity="INFO",
                    confidence="LOW",
                    actual=f"Request failed: {result.error}",
                    duration_ms=duration,
                ))
                continue

            if result.status_code in (403, 404):
                results.append(self._make_result(
                    test_id="AUTHZ-001",
                    test_name="Cross-User Object Access (BOLA)",
                    endpoint=path_tmpl,
                    method=method,
                    status="PASS",
                    severity="INFO",
                    confidence="HIGH",
                    expected="HTTP 403 Forbidden or 404 Not Found when User A requests User B's resource",
                    actual=f"HTTP {result.status_code} received; cross-user object access safely denied",
                    evidence={
                        "status_code": result.status_code,
                        "requester": "alice",
                        "target_resource_owner": "bob",
                        "resource_id": bob_res_id,
                    },
                    explanation="Server enforces strict object-level authorization: Alice cannot inspect Bob's data.",
                    duration_ms=duration,
                ))
            elif result.status_code == 200:
                results.append(self._make_result(
                    test_id="AUTHZ-001",
                    test_name="Cross-User Object Access (BOLA)",
                    endpoint=path_tmpl,
                    method=method,
                    status="CONFIRMED",
                    severity="CRITICAL",
                    confidence="HIGH",
                    expected="HTTP 403 or 404 preventing unauthorized object access",
                    actual="HTTP 200 OK returned; Alice received Bob's private resource data",
                    evidence={
                        "status_code": result.status_code,
                        "requester": "alice",
                        "target_resource_owner": "bob",
                        "resource_id": bob_res_id,
                        "returned_owner_field": result.body.get("owner") if isinstance(result.body, dict) else None,
                        "response_preview": str(result.body_text)[:300],
                    },
                    explanation=(
                        f"CRITICAL BOLA (Broken Object Level Authorization): Authenticated user 'alice' "
                        f"requested resource '{bob_res_id}' owned by 'bob' at {path_tmpl} and received HTTP 200 with the full object."
                    ),
                    remediation=(
                        "Implement object ownership validation in the data access layer: "
                        "verify that the authenticated identity owns the requested object ID before returning data. "
                        "Return HTTP 403 or 404 for tenant isolation violations."
                    ),
                    impact="Complete bypass of data isolation allowing arbitrary tenant/user data exfiltration.",
                    duration_ms=duration,
                ))
            else:
                results.append(self._make_result(
                    test_id="AUTHZ-001",
                    test_name="Cross-User Object Access (BOLA)",
                    endpoint=path_tmpl,
                    method=method,
                    status="SUSPECTED",
                    severity="HIGH",
                    confidence="LOW",
                    expected="HTTP 403/404",
                    actual=f"HTTP {result.status_code}",
                    duration_ms=duration,
                ))

        return results

    async def _check_privileged_function(self) -> list[CheckResult]:
        """AUTHZ-002: Regular user requests administrative function."""
        results: list[CheckResult] = []
        policies = self.target.get("endpoint_policies", [])
        admin_eps = [ep for ep in policies if ep.get("required_role") == "admin"]

        if not admin_eps:
            results.append(self._make_result(
                test_id="AUTHZ-002",
                test_name="Privileged Function Access",
                endpoint="N/A",
                method="GET",
                status="SKIPPED",
                severity="INFO",
                confidence="LOW",
                preconditions="Requires endpoints with required_role=admin",
            ))
            return results

        user_header = self._get_auth_header("alice")
        if not user_header:
            results.append(self._make_result(
                test_id="AUTHZ-002",
                test_name="Privileged Function Access",
                endpoint="N/A",
                method="GET",
                status="SKIPPED",
                severity="INFO",
                confidence="LOW",
                preconditions="Requires standard user auth profile",
            ))
            return results

        for ep in admin_eps:
            path = ep.get("path", "")
            method = ep.get("method", "GET")
            url = self._url(path)
            start = time.monotonic()

            result = await self.engine.request(method, url, headers=user_header)
            duration = (time.monotonic() - start) * 1000

            if not result.success:
                results.append(self._make_result(
                    test_id="AUTHZ-002",
                    test_name="Privileged Function Access",
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
                    test_id="AUTHZ-002",
                    test_name="Privileged Function Access",
                    endpoint=path,
                    method=method,
                    status="PASS",
                    severity="INFO",
                    confidence="HIGH",
                    expected="HTTP 403 Forbidden for non-admin user role",
                    actual=f"HTTP {result.status_code} received; privilege boundary preserved",
                    evidence={"status_code": result.status_code, "caller_role": "user"},
                    explanation="Role-based access control properly rejected an unprivileged user from admin route.",
                    duration_ms=duration,
                ))
            elif result.status_code == 200:
                results.append(self._make_result(
                    test_id="AUTHZ-002",
                    test_name="Privileged Function Access",
                    endpoint=path,
                    method=method,
                    status="CONFIRMED",
                    severity="HIGH",
                    confidence="HIGH",
                    expected="HTTP 403 Forbidden for non-admin user",
                    actual="HTTP 200 OK returned; standard user executed administrative function",
                    evidence={
                        "status_code": result.status_code,
                        "caller_role": "user",
                        "admin_endpoint": path,
                        "response_preview": str(result.body_text)[:300],
                    },
                    explanation=(
                        f"Vertical Privilege Escalation: A standard user (role 'user') called admin endpoint "
                        f"{path} and received HTTP 200 with administrative data. Server-side role check is absent."
                    ),
                    remediation=(
                        "Implement role-based authorization check: inspect authenticated token claims for 'role: admin'. "
                        "Return HTTP 403 Forbidden if the caller lacks administrative privileges."
                    ),
                    impact="Unprivileged users can execute administrative operations or inspect system analytics.",
                    duration_ms=duration,
                ))
            else:
                results.append(self._make_result(
                    test_id="AUTHZ-002",
                    test_name="Privileged Function Access",
                    endpoint=path,
                    method=method,
                    status="SUSPECTED",
                    severity="MEDIUM",
                    confidence="LOW",
                    expected="HTTP 403",
                    actual=f"HTTP {result.status_code}",
                    duration_ms=duration,
                ))

        return results

    async def _check_reverse_object_access(self) -> list[CheckResult]:
        """AUTHZ-003: Reverse object authorization test (Bob accesses Alice's resource)."""
        results: list[CheckResult] = []
        policies = self.target.get("endpoint_policies", [])
        owner_eps = [ep for ep in policies if ep.get("ownership_required", False)]

        if not owner_eps:
            return results

        test_resources = self.target.get("test_resources", {})
        bob_header = self._get_auth_header("bob")
        alice_resources = test_resources.get("alice", {})

        if not bob_header or not alice_resources:
            return results

        for ep in owner_eps:
            path_tmpl = ep.get("path", "")
            method = ep.get("method", "GET")
            res_key = ep.get("resource_key", "order_id")
            alice_res_id = alice_resources.get(res_key)

            if not alice_res_id:
                continue

            path = self._fill_path(path_tmpl, {**alice_resources, res_key: alice_res_id})
            url = self._url(path)
            start = time.monotonic()

            result = await self.engine.request(method, url, headers=bob_header)
            duration = (time.monotonic() - start) * 1000

            if not result.success:
                continue

            if result.status_code in (403, 404):
                results.append(self._make_result(
                    test_id="AUTHZ-003",
                    test_name="Missing Object-Level Restrictions",
                    endpoint=path_tmpl,
                    method=method,
                    status="PASS",
                    severity="INFO",
                    confidence="HIGH",
                    expected="HTTP 403 or 404 denying Bob access to Alice's object",
                    actual=f"HTTP {result.status_code} received; access denied",
                    duration_ms=duration,
                ))
            elif result.status_code == 200:
                results.append(self._make_result(
                    test_id="AUTHZ-003",
                    test_name="Missing Object-Level Restrictions",
                    endpoint=path_tmpl,
                    method=method,
                    status="CONFIRMED",
                    severity="CRITICAL",
                    confidence="HIGH",
                    expected="HTTP 403/404",
                    actual="HTTP 200 OK returned; Bob accessed Alice's resource",
                    evidence={
                        "requester": "bob",
                        "target_owner": "alice",
                        "resource_id": alice_res_id,
                    },
                    explanation="Bidirectional BOLA confirmed: Bob can access Alice's records.",
                    remediation="Apply object-level authorization consistently across all entity queries.",
                    impact="Cross-user data compromise across tenant accounts.",
                    duration_ms=duration,
                ))

        return results

    async def _check_policy_consistency(self) -> list[CheckResult]:
        """AUTHZ-004: Validate authorized admin user is granted access."""
        results: list[CheckResult] = []
        policies = self.target.get("endpoint_policies", [])
        admin_eps = [ep for ep in policies if ep.get("required_role") == "admin"]
        admin_header = self._get_auth_header("admin")

        if not admin_eps or not admin_header:
            return results

        for ep in admin_eps:
            path = ep.get("path", "")
            method = ep.get("method", "GET")
            url = self._url(path)
            start = time.monotonic()

            result = await self.engine.request(method, url, headers=admin_header)
            duration = (time.monotonic() - start) * 1000

            if not result.success:
                continue

            if result.status_code == 200:
                results.append(self._make_result(
                    test_id="AUTHZ-004",
                    test_name="Authorization Policy Consistency",
                    endpoint=path,
                    method=method,
                    status="PASS",
                    severity="INFO",
                    confidence="HIGH",
                    expected="HTTP 200 OK for user possessing required 'admin' role",
                    actual="HTTP 200 OK received; authorized access succeeded",
                    duration_ms=duration,
                ))
            elif result.status_code in (401, 403):
                results.append(self._make_result(
                    test_id="AUTHZ-004",
                    test_name="Authorization Policy Consistency",
                    endpoint=path,
                    method=method,
                    status="SUSPECTED",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    expected="HTTP 200 for administrator",
                    actual=f"HTTP {result.status_code} denied access to administrator",
                    explanation="The authorized admin role was denied access. Check role configuration.",
                    duration_ms=duration,
                ))

        return results


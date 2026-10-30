"""Input Validation Security Checks (INPUT-001 through INPUT-005)."""
import time
from typing import Any
from .base import BaseCheck, CheckResult


class InputValidationCheck(BaseCheck):
    """Evaluates payload schema conformance, type coercion, and numeric boundaries."""

    @property
    def category(self) -> str:
        return "input_validation"

    async def run(self) -> list[CheckResult]:
        results: list[CheckResult] = []
        results.extend(await self._check_missing_required_field())
        results.extend(await self._check_invalid_data_type())
        results.extend(await self._check_boundary_violations())
        results.extend(await self._check_malformed_json())
        results.extend(await self._check_unexpected_fields())
        return results

    def _get_validation_endpoints(self) -> list[dict[str, Any]]:
        policies = self.target.get("endpoint_policies", [])
        return [ep for ep in policies if ep.get("request_schema") is not None]

    async def _check_missing_required_field(self) -> list[CheckResult]:
        """INPUT-001: Submit request missing a declared mandatory field."""
        results: list[CheckResult] = []
        endpoints = self._get_validation_endpoints()

        if not endpoints:
            results.append(self._make_result(
                test_id="INPUT-001",
                test_name="Missing Required Field",
                endpoint="N/A",
                method="POST",
                status="SKIPPED",
                severity="INFO",
                confidence="LOW",
                preconditions="Requires endpoints with request_schema.required_fields",
            ))
            return results

        auth_header = self._get_auth_header("alice")

        for ep in endpoints:
            path = ep.get("path", "")
            method = ep.get("method", "POST")
            schema = ep.get("request_schema", {})
            required_fields = schema.get("required_fields", [])
            example_body = self._example_body(schema)

            if not required_fields or not example_body:
                continue

            for field_name in required_fields:
                test_payload = {k: v for k, v in self._example_body(schema).items() if k != field_name}
                url = self._url(path)
                start = time.monotonic()

                result = await self.engine.request(
                    method, url, headers=auth_header, json_body=test_payload
                )
                duration = (time.monotonic() - start) * 1000

                if not result.success:
                    results.append(self._make_result(
                        test_id="INPUT-001",
                        test_name="Missing Required Field",
                        endpoint=path,
                        method=method,
                        status="ERROR",
                        severity="INFO",
                        confidence="LOW",
                        actual=f"Request failed: {result.error}",
                        duration_ms=duration,
                    ))
                    continue

                if result.status_code in (400, 422):
                    results.append(self._make_result(
                        test_id="INPUT-001",
                        test_name="Missing Required Field",
                        endpoint=path,
                        method=method,
                        status="PASS",
                        severity="INFO",
                        confidence="HIGH",
                        expected=f"HTTP 422/400 rejecting body missing mandatory field '{field_name}'",
                        actual=f"HTTP {result.status_code} received; validation correctly rejected missing field",
                        evidence={"omitted_field": field_name, "status_code": result.status_code},
                        explanation=f"Server properly validated schema constraints and rejected omission of '{field_name}'.",
                        duration_ms=duration,
                    ))
                elif result.status_code in (200, 201):
                    results.append(self._make_result(
                        test_id="INPUT-001",
                        test_name="Missing Required Field",
                        endpoint=path,
                        method=method,
                        status="CONFIRMED",
                        severity="MEDIUM",
                        confidence="HIGH",
                        expected=f"HTTP 422/400 rejecting request missing '{field_name}'",
                        actual=f"HTTP {result.status_code} OK returned; server processed incomplete payload",
                        evidence={
                            "missing_field": field_name,
                            "status_code": result.status_code,
                            "sent_keys": list(test_payload.keys()),
                        },
                        explanation=(
                            f"The endpoint {path} accepted a request missing mandatory field '{field_name}' "
                            f"and processed it with HTTP {result.status_code}. Missing required field validation."
                        ),
                        remediation=(
                            "Enforce strict request body schema validation using Pydantic or JSON Schema. "
                            "Ensure all required parameters are non-null and present before business execution."
                        ),
                        impact="Incomplete records, database integrity violations, or logic flaws.",
                        duration_ms=duration,
                    ))
                else:
                    results.append(self._make_result(
                        test_id="INPUT-001",
                        test_name="Missing Required Field",
                        endpoint=path,
                        method=method,
                        status="SUSPECTED",
                        severity="LOW",
                        confidence="LOW",
                        expected="HTTP 422",
                        actual=f"HTTP {result.status_code}",
                        duration_ms=duration,
                    ))

        return results

    async def _check_invalid_data_type(self) -> list[CheckResult]:
        """INPUT-002: Submit payload with incompatible data types."""
        results: list[CheckResult] = []
        endpoints = self._get_validation_endpoints()

        if not endpoints:
            return results

        auth_header = self._get_auth_header("alice")

        for ep in endpoints:
            path = ep.get("path", "")
            method = ep.get("method", "POST")
            schema = ep.get("request_schema", {})
            field_types = schema.get("field_types", {})
            example_body = self._example_body(schema)

            for field_name, expected_type in field_types.items():
                test_payload = self._example_body(schema)
                if expected_type == "integer":
                    test_payload[field_name] = "invalid_string_not_int"
                elif expected_type == "float":
                    test_payload[field_name] = "invalid_string_not_float"
                elif expected_type == "string":
                    test_payload[field_name] = {"nested_obj": "wrong_type"}
                else:
                    continue

                url = self._url(path)
                start = time.monotonic()
                result = await self.engine.request(
                    method, url, headers=auth_header, json_body=test_payload
                )
                duration = (time.monotonic() - start) * 1000

                if not result.success:
                    continue

                if result.status_code in (400, 422):
                    results.append(self._make_result(
                        test_id="INPUT-002",
                        test_name="Invalid Data Type",
                        endpoint=path,
                        method=method,
                        status="PASS",
                        severity="INFO",
                        confidence="HIGH",
                        expected=f"HTTP 422/400 rejecting type mismatch for '{field_name}'",
                        actual=f"HTTP {result.status_code} received; type validation successfully triggered",
                        evidence={"field": field_name, "expected_type": expected_type},
                        explanation=f"Server correctly validated data types on '{field_name}'.",
                        duration_ms=duration,
                    ))
                elif result.status_code in (200, 201):
                    results.append(self._make_result(
                        test_id="INPUT-002",
                        test_name="Invalid Data Type",
                        endpoint=path,
                        method=method,
                        status="CONFIRMED",
                        severity="MEDIUM",
                        confidence="HIGH",
                        expected=f"HTTP 422 rejecting type mismatch on '{field_name}'",
                        actual=f"HTTP {result.status_code} OK returned; invalid data type accepted",
                        evidence={
                            "field": field_name,
                            "expected_type": expected_type,
                            "sent_type": type(test_payload[field_name]).__name__,
                            "status_code": result.status_code,
                        },
                        explanation=(
                            f"The endpoint {path} accepted an invalid data type for '{field_name}' "
                            f"(expected {expected_type}). Weak or absent type checking."
                        ),
                        remediation="Apply typed request body deserializers to reject invalid primitive types.",
                        impact="Potential type confusion, SQL or injection side effects, or application crashes.",
                        duration_ms=duration,
                    ))

        return results

    async def _check_boundary_violations(self) -> list[CheckResult]:
        """INPUT-003: Submit numeric boundary and range violations (e.g. negative quantity)."""
        results: list[CheckResult] = []
        endpoints = self._get_validation_endpoints()

        if not endpoints:
            return results

        auth_header = self._get_auth_header("alice")

        for ep in endpoints:
            path = ep.get("path", "")
            method = ep.get("method", "POST")
            schema = ep.get("request_schema", {})
            constraints = schema.get("constraints", {})
            example_body = self._example_body(schema)

            for field_name, rule in constraints.items():
                test_values: list[tuple[str, Any]] = []
                if rule.get("positive", False):
                    test_values.append(("negative_value", -5))
                if "min" in rule:
                    test_values.append(("below_min", rule["min"] - 1))
                if "max" in rule:
                    test_values.append(("above_max", rule["max"] + 1000))

                for violation_label, test_val in test_values:
                    test_payload = self._example_body(schema)
                    test_payload[field_name] = test_val

                    url = self._url(path)
                    start = time.monotonic()
                    result = await self.engine.request(
                        method, url, headers=auth_header, json_body=test_payload
                    )
                    duration = (time.monotonic() - start) * 1000

                    if not result.success:
                        continue

                    if result.status_code in (400, 422):
                        results.append(self._make_result(
                            test_id="INPUT-003",
                            test_name="Boundary Violations",
                            endpoint=path,
                            method=method,
                            status="PASS",
                            severity="INFO",
                            confidence="HIGH",
                            expected=f"HTTP 422 rejecting out-of-range '{field_name}'={test_val}",
                            actual=f"HTTP {result.status_code} received; boundary violation rejected",
                            evidence={"field": field_name, "value": test_val, "violation": violation_label},
                            duration_ms=duration,
                        ))
                    elif result.status_code in (200, 201):
                        results.append(self._make_result(
                            test_id="INPUT-003",
                            test_name="Boundary Violations",
                            endpoint=path,
                            method=method,
                            status="CONFIRMED",
                            severity="MEDIUM",
                            confidence="HIGH",
                            expected=f"HTTP 422 rejecting '{field_name}'={test_val} ({violation_label})",
                            actual=f"HTTP {result.status_code} OK; server accepted invalid boundary value",
                            evidence={
                                "field": field_name,
                                "violating_value": test_val,
                                "constraint": rule,
                                "status_code": result.status_code,
                            },
                            explanation=(
                                f"Endpoint {path} accepted value '{test_val}' for '{field_name}', "
                                f"violating configured constraint {rule}."
                            ),
                            remediation="Implement boundary constraints (gt=0, le=max) in request validation.",
                            impact="Financial calculation tampering, negative quantity inventory flaws.",
                            duration_ms=duration,
                        ))

        return results

    async def _check_malformed_json(self) -> list[CheckResult]:
        """INPUT-004: Submit syntactically broken JSON body."""
        results: list[CheckResult] = []
        endpoints = self._get_validation_endpoints()

        if not endpoints:
            return results

        auth_header = dict(self._get_auth_header("alice"))
        auth_header["Content-Type"] = "application/json"

        for ep in endpoints:
            path = ep.get("path", "")
            method = ep.get("method", "POST")
            url = self._url(path)
            start = time.monotonic()

            broken_payload = '{"product": "Test", "quantity": '  # Truncated syntax
            result = await self.engine.request(
                method, url, headers=auth_header, body=broken_payload, content_type="application/json"
            )
            duration = (time.monotonic() - start) * 1000

            if not result.success:
                continue

            if result.status_code in (400, 422):
                results.append(self._make_result(
                    test_id="INPUT-004",
                    test_name="Malformed JSON Handling",
                    endpoint=path,
                    method=method,
                    status="PASS",
                    severity="INFO",
                    confidence="HIGH",
                    expected="HTTP 400 or 422 gracefully rejecting invalid JSON syntax",
                    actual=f"HTTP {result.status_code} received with safe client error",
                    duration_ms=duration,
                ))
            elif result.status_code == 500:
                results.append(self._make_result(
                    test_id="INPUT-004",
                    test_name="Malformed JSON Handling",
                    endpoint=path,
                    method=method,
                    status="SUSPECTED",
                    severity="LOW",
                    confidence="MEDIUM",
                    expected="HTTP 400 Bad Request",
                    actual="HTTP 500 Internal Server Error returned on malformed JSON",
                    evidence={"status_code": 500, "response_preview": str(result.body_text)[:200]},
                    explanation="Unhandled parser exception generated a 500 internal server error.",
                    remediation="Wrap body deserialization in exception handlers and return HTTP 400.",
                    impact="Exception details leakage and denial-of-service vulnerability.",
                    duration_ms=duration,
                ))

        return results

    async def _check_unexpected_fields(self) -> list[CheckResult]:
        """INPUT-005: Submit unexpected extra parameters (Mass Assignment test)."""
        results: list[CheckResult] = []
        endpoints = self._get_validation_endpoints()

        if not endpoints:
            return results

        auth_header = self._get_auth_header("alice")

        for ep in endpoints:
            path = ep.get("path", "")
            method = ep.get("method", "POST")
            schema = ep.get("request_schema", {})
            example_body = self._example_body(schema)
            strict = schema.get("strict", False)

            mass_cfg = schema.get("mass_assignment")
            if mass_cfg:
                results.append(await self._verify_mass_assignment(ep, schema, mass_cfg, auth_header))
                continue

            test_payload = self._example_body(schema)
            test_payload["_extra_test_attribute"] = "untrusted_value"
            test_payload["is_admin"] = True

            url = self._url(path)
            start = time.monotonic()
            result = await self.engine.request(
                method, url, headers=auth_header, json_body=test_payload
            )
            duration = (time.monotonic() - start) * 1000

            if not result.success:
                continue

            if result.status_code in (400, 422):
                results.append(self._make_result(
                    test_id="INPUT-005",
                    test_name="Unexpected Fields",
                    endpoint=path,
                    method=method,
                    status="PASS",
                    severity="INFO",
                    confidence="HIGH",
                    expected="Server strictly rejects unknown payload parameters",
                    actual=f"HTTP {result.status_code} received; extra parameters rejected",
                    duration_ms=duration,
                ))
            elif result.status_code in (200, 201):
                status = "CONFIRMED" if strict else "PASS"
                sev = "LOW" if strict else "INFO"
                explanation = (
                    "Endpoint accepted unexpected parameters despite declared strict schema."
                    if strict
                    else "Endpoint safely accepted or ignored extraneous payload parameters (non-strict mode)."
                )
                results.append(self._make_result(
                    test_id="INPUT-005",
                    test_name="Unexpected Fields",
                    endpoint=path,
                    method=method,
                    status=status,
                    severity=sev,
                    confidence="MEDIUM",
                    expected="Policy dependent strict filtering",
                    actual=f"HTTP {result.status_code} returned",
                    evidence={"strict_mode": strict, "extra_fields": ["_extra_test_attribute", "is_admin"]},
                    explanation=explanation,
                    limitations="Accepting extraneous fields is only a vulnerability if mass assignment binds them.",
                    duration_ms=duration,
                ))

        return results

    async def _verify_mass_assignment(self, ep, schema, cfg, auth_header) -> CheckResult:
        """INPUT-005 (verified): inject a privileged attribute, then prove whether it
        was actually bound by logging in as the new account and reading it back.

        Policy format (request_schema.mass_assignment):
          inject: {admin: true}
          verify:
            login: {path, method, credential_fields: [username, password], token_field}
            request: {method: GET, path: /me}
            field: data.admin
            privileged_value: true
        """
        path = ep.get("path", "")
        method = ep.get("method", "POST")
        inject = cfg.get("inject", {})
        verify = cfg.get("verify", {})
        payload = {**self._example_body(schema), **inject}
        start = time.monotonic()

        def result(status, severity, confidence, actual, explanation, evidence, remediation="", impact=""):
            return self._make_result(
                test_id="INPUT-005", test_name="Mass Assignment (verified)", endpoint=path, method=method,
                status=status, severity=severity, confidence=confidence,
                expected="Injected privileged attribute is rejected or ignored",
                actual=actual, evidence=evidence, explanation=explanation,
                remediation=remediation, impact=impact,
                duration_ms=(time.monotonic() - start) * 1000,
            )

        created = await self.engine.request(method, self._url(path), headers=auth_header, json_body=payload)
        evidence = {"injected_fields": inject, "create_status": created.status_code if created.success else None}
        if not created.success:
            return result("ERROR", "INFO", "LOW", f"Request failed: {created.error}", "", evidence)
        if created.status_code in (400, 422):
            return result("PASS", "INFO", "HIGH", f"HTTP {created.status_code}: payload with injected fields rejected",
                          "The endpoint rejected the privileged attribute outright.", evidence)
        if not 200 <= created.status_code < 300:
            return result("SUSPECTED", "LOW", "LOW", f"Unexpected HTTP {created.status_code}",
                          "Unexpected status; manual review recommended.", evidence)

        # Log in as the account we just created and read the attribute back.
        login = verify.get("login", {})
        creds = {f: payload.get(f) for f in login.get("credential_fields", ["username", "password"])}
        logged_in = await self.engine.request(login.get("method", "POST"), self._url(login.get("path", "")), json_body=creds)
        token = self._get_field(logged_in.body, login.get("token_field", "token")) if logged_in.success else None
        if not token:
            return result("SUSPECTED", "LOW", "LOW", "Request accepted, but the new account could not log in to verify",
                          "Accepted the injected attribute; binding could not be verified.", evidence)

        req = verify.get("request", {})
        check = await self.engine.request(req.get("method", "GET"), self._url(req.get("path", "")),
                                          headers={"Authorization": f"Bearer {token}"})
        observed = self._get_field(check.body, verify.get("field", "")) if check.success else None
        evidence.update({"verified_via": req.get("path"), "observed_value": observed})

        if observed == verify.get("privileged_value", True):
            return result(
                "CONFIRMED", "HIGH", "HIGH",
                f"New account has {verify.get('field')} = {observed!r} after self-registration",
                f"Mass assignment confirmed: the client-supplied attribute(s) {list(inject)} were bound to the "
                f"stored account, so any anonymous user can register with elevated privileges.",
                evidence,
                remediation="Bind request bodies to an explicit allowlist DTO (e.g. Pydantic extra='forbid') and "
                            "set privileged attributes such as roles only server-side.",
                impact="Vertical privilege escalation to administrator by any unauthenticated client.",
            )
        return result("PASS", "INFO", "HIGH",
                      f"Request accepted but {verify.get('field')} = {observed!r} (attribute not bound)",
                      "The extra attribute was ignored by the server; no privilege was granted.", evidence)

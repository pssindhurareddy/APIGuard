"""End-to-End detection and remediation validation tests.

Validates that:
1. Vulnerable mode triggers CONFIRMED findings across all 4 categories.
2. Secure mode PASSES the corresponding checks with verified remediation.
"""
import sys
from pathlib import Path

# Add project root, backend, and demo_api to sys.path immediately
root = Path(__file__).resolve().parent.parent.parent
backend_dir = root / "backend"
demo_dir = root / "demo_api"

for p in (str(backend_dir), str(demo_dir), str(root)):
    if p not in sys.path:
        sys.path.insert(0, p)

import pytest
import httpx
from demo_api.app.main import create_app
from app.services.scope_guard import ScopeGuard
from app.services.request_engine import RequestEngine, RequestResult
from app.checks.authentication import AuthenticationCheck
from app.checks.authorization import AuthorizationCheck
from app.checks.input_validation import InputValidationCheck
from app.checks.data_exposure import DataExposureCheck


class MockASGIRequestEngine:
    """Adapts RequestEngine to execute directly in-memory against FastAPI ASGI apps."""

    def __init__(self, asgi_app, base_url: str):
        self.app = asgi_app
        self.base_url = base_url.rstrip("/")

    async def request(
        self,
        method: str,
        url: str,
        headers=None,
        json_body=None,
        body=None,
        content_type=None,
    ) -> RequestResult:
        path = url.replace(self.base_url, "")
        if not path.startswith("/"):
            path = "/" + path

        req_headers = dict(headers or {})
        if content_type:
            req_headers["Content-Type"] = content_type

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://testserver") as client:
            kwargs = {"method": method, "url": path, "headers": req_headers}
            if json_body is not None:
                kwargs["json"] = json_body
            elif body is not None:
                kwargs["content"] = body

            resp = await client.request(**kwargs)

            parsed_body = None
            if "application/json" in resp.headers.get("content-type", ""):
                try:
                    parsed_body = resp.json()
                except Exception:
                    parsed_body = None

            return RequestResult(
                success=True,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=parsed_body,
                body_text=resp.text,
                content_type=resp.headers.get("content-type", ""),
                duration_ms=5.0,
                url=url,
                method=method,
            )


TARGET_CONFIG_VULN = {
    "base_url": "http://127.0.0.1:8001",
    "auth_profiles": {
        "alice": {"username": "alice", "role": "user", "token": "demo-token-alice-12345"},
        "bob": {"username": "bob", "role": "user", "token": "demo-token-bob-67890"},
        "admin": {"username": "admin", "role": "admin", "token": "demo-token-admin-99999"},
    },
    "test_resources": {
        "alice": {"user_id": "user-alice-001", "order_id": "order-1001"},
        "bob": {"user_id": "user-bob-002", "order_id": "order-1002"},
    },
    "endpoint_policies": [
        {
            "path": "/api/profile",
            "method": "GET",
            "authentication_required": True,
            "returns_identity": True,
            "identity_field": "username",
            "check_data_exposure": True,
            "forbidden_response_fields": ["password_hash", "internal_notes", "api_key"],
            "allowed_response_fields": ["id", "username", "display_name", "email", "role", "created_at"],
        },
        {
            "path": "/api/orders/{order_id}",
            "method": "GET",
            "authentication_required": True,
            "ownership_required": True,
            "resource_key": "order_id",
            "check_data_exposure": True,
        },
        {
            "path": "/api/admin/stats",
            "method": "GET",
            "authentication_required": True,
            "required_role": "admin",
            "check_data_exposure": True,
            "forbidden_response_fields": ["internal_config"],
        },
        {
            "path": "/api/orders",
            "method": "POST",
            "authentication_required": True,
            "request_schema": {
                "required_fields": ["product", "quantity", "price"],
                "field_types": {"product": "string", "quantity": "integer", "price": "float"},
                "constraints": {"quantity": {"min": 1, "max": 1000, "positive": True}},
                "example_body": {"product": "Test", "quantity": 1, "price": 10.0},
                "strict": True,
            },
        },
    ],
}

TARGET_CONFIG_SECURE = dict(TARGET_CONFIG_VULN)
TARGET_CONFIG_SECURE["base_url"] = "http://127.0.0.1:8002"


@pytest.mark.asyncio
async def test_vulnerable_auth_detection():
    vuln_app = create_app("vulnerable")
    engine = MockASGIRequestEngine(vuln_app, TARGET_CONFIG_VULN["base_url"])
    check = AuthenticationCheck(engine, TARGET_CONFIG_VULN)
    results = await check.run()

    auth_001 = next(r for r in results if r.test_id == "AUTH-001" and r.endpoint == "/api/profile")
    assert auth_001.status == "CONFIRMED"
    assert auth_001.severity == "HIGH"


@pytest.mark.asyncio
async def test_secure_auth_passes():
    sec_app = create_app("secure")
    engine = MockASGIRequestEngine(sec_app, TARGET_CONFIG_SECURE["base_url"])
    check = AuthenticationCheck(engine, TARGET_CONFIG_SECURE)
    results = await check.run()

    auth_001 = next(r for r in results if r.test_id == "AUTH-001" and r.endpoint == "/api/profile")
    assert auth_001.status == "PASS"


@pytest.mark.asyncio
async def test_vulnerable_bola_detection():
    vuln_app = create_app("vulnerable")
    engine = MockASGIRequestEngine(vuln_app, TARGET_CONFIG_VULN["base_url"])
    check = AuthorizationCheck(engine, TARGET_CONFIG_VULN)
    results = await check.run()

    bola = next(r for r in results if r.test_id == "AUTHZ-001")
    assert bola.status == "CONFIRMED"
    assert bola.severity == "CRITICAL"


@pytest.mark.asyncio
async def test_secure_bola_prevented():
    sec_app = create_app("secure")
    engine = MockASGIRequestEngine(sec_app, TARGET_CONFIG_SECURE["base_url"])
    check = AuthorizationCheck(engine, TARGET_CONFIG_SECURE)
    results = await check.run()

    bola = next(r for r in results if r.test_id == "AUTHZ-001")
    assert bola.status == "PASS"


@pytest.mark.asyncio
async def test_vulnerable_privilege_escalation():
    vuln_app = create_app("vulnerable")
    engine = MockASGIRequestEngine(vuln_app, TARGET_CONFIG_VULN["base_url"])
    check = AuthorizationCheck(engine, TARGET_CONFIG_VULN)
    results = await check.run()

    priv_esc = next(r for r in results if r.test_id == "AUTHZ-002")
    assert priv_esc.status == "CONFIRMED"
    assert priv_esc.severity == "HIGH"


@pytest.mark.asyncio
async def test_secure_privilege_escalation_blocked():
    sec_app = create_app("secure")
    engine = MockASGIRequestEngine(sec_app, TARGET_CONFIG_SECURE["base_url"])
    check = AuthorizationCheck(engine, TARGET_CONFIG_SECURE)
    results = await check.run()

    priv_esc = next(r for r in results if r.test_id == "AUTHZ-002")
    assert priv_esc.status == "PASS"


@pytest.mark.asyncio
async def test_vulnerable_input_validation():
    vuln_app = create_app("vulnerable")
    engine = MockASGIRequestEngine(vuln_app, TARGET_CONFIG_VULN["base_url"])
    check = InputValidationCheck(engine, TARGET_CONFIG_VULN)
    results = await check.run()

    inp_001 = next(r for r in results if r.test_id == "INPUT-001")
    assert inp_001.status == "CONFIRMED"


@pytest.mark.asyncio
async def test_secure_input_validation_passes():
    sec_app = create_app("secure")
    engine = MockASGIRequestEngine(sec_app, TARGET_CONFIG_SECURE["base_url"])
    check = InputValidationCheck(engine, TARGET_CONFIG_SECURE)
    results = await check.run()

    inp_001 = next(r for r in results if r.test_id == "INPUT-001")
    assert inp_001.status == "PASS"


@pytest.mark.asyncio
async def test_vulnerable_data_exposure():
    vuln_app = create_app("vulnerable")
    engine = MockASGIRequestEngine(vuln_app, TARGET_CONFIG_VULN["base_url"])
    check = DataExposureCheck(engine, TARGET_CONFIG_VULN)
    results = await check.run()

    data_001 = next(r for r in results if r.test_id == "DATA-001" and r.endpoint == "/api/profile")
    assert data_001.status == "CONFIRMED"
    assert data_001.severity == "HIGH"


@pytest.mark.asyncio
async def test_secure_data_exposure_clean():
    sec_app = create_app("secure")
    engine = MockASGIRequestEngine(sec_app, TARGET_CONFIG_SECURE["base_url"])
    check = DataExposureCheck(engine, TARGET_CONFIG_SECURE)
    results = await check.run()

    data_001 = next(r for r in results if r.test_id == "DATA-001" and r.endpoint == "/api/profile")
    assert data_001.status == "PASS"

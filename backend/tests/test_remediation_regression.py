"""Regression tests for the remediation-validation fixes.

1. AUTH-001/002 resolve templated paths ({order_id}) to real synthetic IDs, so
   they produce a definitive PASS/CONFIRMED instead of SUSPECTED 404/422 noise.
2. The secure demo API rejects mass-assignment fields (INPUT-005).
3. The secure demo API authenticates before resolving object IDs (no 404 oracle).
4. A full scan of the secure API yields zero CONFIRMED and zero SUSPECTED findings.
"""
import httpx
import pytest

from demo_api.app.main import create_app
from app.checks.authentication import AuthenticationCheck
from app.checks.authorization import AuthorizationCheck
from app.checks.input_validation import InputValidationCheck
from app.checks.data_exposure import DataExposureCheck
from backend.tests.test_detection_engine import (
    MockASGIRequestEngine,
    TARGET_CONFIG_VULN,
    TARGET_CONFIG_SECURE,
)

ALL_CHECKS = (AuthenticationCheck, AuthorizationCheck, InputValidationCheck, DataExposureCheck)


async def _full_scan(mode: str, config: dict):
    engine = MockASGIRequestEngine(create_app(mode), config["base_url"])
    results = []
    for cls in ALL_CHECKS:
        results.extend(await cls(engine, config).run())
    return results


@pytest.mark.asyncio
async def test_auth_checks_resolve_path_parameters_no_suspected_noise():
    for mode, cfg in (("vulnerable", TARGET_CONFIG_VULN), ("secure", TARGET_CONFIG_SECURE)):
        engine = MockASGIRequestEngine(create_app(mode), cfg["base_url"])
        results = await AuthenticationCheck(engine, cfg).run()
        suspected = [(r.test_id, r.endpoint) for r in results if r.status == "SUSPECTED"]
        assert suspected == [], f"{mode}: unexpected SUSPECTED results {suspected}"


@pytest.mark.asyncio
async def test_vulnerable_order_endpoint_readable_without_token():
    engine = MockASGIRequestEngine(create_app("vulnerable"), TARGET_CONFIG_VULN["base_url"])
    results = await AuthenticationCheck(engine, TARGET_CONFIG_VULN).run()
    hit = [r for r in results if r.test_id == "AUTH-001" and r.endpoint == "/api/orders/{order_id}"]
    assert hit and hit[0].status == "CONFIRMED"


@pytest.mark.asyncio
async def test_secure_api_rejects_mass_assignment():
    engine = MockASGIRequestEngine(create_app("secure"), TARGET_CONFIG_SECURE["base_url"])
    results = await InputValidationCheck(engine, TARGET_CONFIG_SECURE).run()
    ma = [r for r in results if r.test_id == "INPUT-005"]
    assert ma and all(r.status == "PASS" for r in ma)


@pytest.mark.asyncio
async def test_secure_api_authenticates_before_object_lookup():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app("secure")),
                                 base_url="http://testserver") as c:
        existing = await c.get("/api/orders/order-1001")
        missing = await c.get("/api/orders/order-does-not-exist")
    assert existing.status_code == 401 and missing.status_code == 401


@pytest.mark.asyncio
async def test_full_secure_scan_has_no_open_findings():
    results = await _full_scan("secure", TARGET_CONFIG_SECURE)
    open_ = [(r.test_id, r.endpoint, r.status) for r in results if r.status in ("CONFIRMED", "SUSPECTED")]
    assert open_ == [], f"secure API still has open findings: {open_}"


@pytest.mark.asyncio
async def test_backend_serves_dashboard_on_root():
    """The pre-built dashboard is served at / so no separate frontend server is needed."""
    from app.main import app as backend_app
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=backend_app),
                                 base_url="http://testserver") as c:
        r = await c.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "APIGuard" in r.text

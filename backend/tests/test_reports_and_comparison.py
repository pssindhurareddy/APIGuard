"""Automated tests for Report Generator, Database persistence, and Scan Comparison."""
import sys
from pathlib import Path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import pytest
import uuid
from datetime import datetime, timezone

from app.services.report_generator import ReportGenerator
from app.models.database import init_db, insert_row, fetch_one, fetch_all


@pytest.mark.asyncio
async def test_database_persistence_and_query():
    await init_db()
    target_id = "target-test-" + str(uuid.uuid4())[:8]
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    # Insert target first to satisfy foreign key constraint
    await insert_row("targets", {
        "id": target_id,
        "name": "Test Target",
        "base_url": "http://127.0.0.1:8001",
        "environment": "demo",
        "allowed_hosts": '["127.0.0.1"]',
        "allowed_ports": "[8001]",
        "allowed_paths": '["/api/"]',
        "allowed_methods": '["GET"]',
        "is_authorized": 1,
        "auth_profiles": "{}",
        "created_at": now,
        "updated_at": now,
    })

    # Now insert scan referencing target_id
    await insert_row("scans", {
        "id": scan_id,
        "target_id": target_id,
        "target_name": "Test Target",
        "target_url": "http://127.0.0.1:8001",
        "status": "COMPLETED",
        "categories": '["authentication"]',
        "total_tests": 4,
        "passed": 3,
        "confirmed": 1,
        "created_at": now,
    })

    retrieved = await fetch_one("scans", scan_id)
    assert retrieved is not None
    assert retrieved["id"] == scan_id
    assert retrieved["total_tests"] == 4
    assert retrieved["confirmed"] == 1


def test_report_generator_json_and_html():
    gen = ReportGenerator()
    scan_data = {
        "id": "scan-demo-12345",
        "target_name": "Demo Target API",
        "target_url": "http://127.0.0.1:8001",
        "status": "COMPLETED",
        "categories": ["authentication", "authorization"],
        "started_at": "2024-01-01T10:00:00Z",
        "completed_at": "2024-01-01T10:00:05Z",
        "total_tests": 2,
        "passed": 1,
        "confirmed": 1,
        "duration_ms": 5000,
        "summary": "1 passed, 1 confirmed",
    }
    findings = [
        {
            "id": "find-1",
            "scan_id": "scan-demo-12345",
            "test_id": "AUTHZ-001",
            "test_name": "Cross-User Object Access (BOLA)",
            "category": "authorization",
            "endpoint": "/api/orders/order-1002",
            "http_method": "GET",
            "status": "CONFIRMED",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "expected_result": "HTTP 403 Forbidden",
            "actual_result": "HTTP 200 OK returned",
            "evidence": {"sensitive_token": "Bearer demo-token-alice-12345"},
            "explanation": "Alice accessed Bob's order.",
            "remediation": "Add ownership check.",
            "impact": "Tenant data breach.",
            "finding_status": "OPEN",
            "created_at": "2024-01-01T10:00:02Z",
        },
        {
            "id": "find-2",
            "scan_id": "scan-demo-12345",
            "test_id": "AUTH-001",
            "test_name": "Missing Authentication Token",
            "category": "authentication",
            "endpoint": "/api/profile",
            "http_method": "GET",
            "status": "PASS",
            "severity": "INFO",
            "confidence": "HIGH",
            "expected_result": "HTTP 401",
            "actual_result": "HTTP 401 received",
            "evidence": {},
            "finding_status": "PASS",
            "created_at": "2024-01-01T10:00:01Z",
        }
    ]

    # Verify JSON report
    json_report = gen.generate_json_report(scan_data, findings)
    assert json_report["report_title"] == "APIGuard Security Assessment Report"
    assert json_report["statistics"]["total_tests"] == 2
    assert json_report["severity_breakdown"]["CRITICAL"] == 1
    # Check that secrets are redacted from report
    assert "demo-token-alice-12345" not in str(json_report)

    # Verify HTML report
    html_report = gen.generate_html_report(scan_data, findings)
    assert "<!DOCTYPE html>" in html_report
    assert "APIGuard Security Assessment Report" in html_report
    assert "Cross-User Object Access (BOLA)" in html_report
    assert "CRITICAL" in html_report
    assert "demo-token-alice-12345" not in html_report

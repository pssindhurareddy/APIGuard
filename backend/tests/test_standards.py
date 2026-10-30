"""Every check must map to an OWASP API Top 10 (2023) / ASVS category and a CWE."""
import re

from app.api.test_cases import TEST_LIBRARY
from app.services.report_generator import ReportGenerator
from app.services.standards import CHECK_STANDARDS, standards_for


def test_every_check_in_library_is_mapped():
    for tc in TEST_LIBRARY:
        s = standards_for(tc["id"])
        assert s["owasp"] is not None, tc["id"]
        assert s["cwe"], tc["id"]
        assert all(re.fullmatch(r"CWE-\d+", c["id"]) for c in s["cwe"])


def test_key_mappings_are_correct():
    assert standards_for("AUTHZ-001")["owasp"]["id"] == "API1:2023"
    assert "CWE-639" in [c["id"] for c in standards_for("AUTHZ-001")["cwe"]]
    assert standards_for("INPUT-005")["owasp"]["id"] == "API3:2023"
    assert "CWE-915" in [c["id"] for c in standards_for("INPUT-005")["cwe"]]
    assert standards_for("UNKNOWN-1") == {"owasp": None, "cwe": []}
    assert len(CHECK_STANDARDS) == 17


def test_reports_include_standards():
    scan = {"id": "s1", "target_name": "t", "target_url": "http://127.0.0.1:8001", "categories": "[]"}
    finding = {"test_id": "AUTHZ-001", "test_name": "BOLA", "category": "authorization", "endpoint": "/x",
               "http_method": "GET", "status": "CONFIRMED", "severity": "CRITICAL", "evidence": "{}"}
    gen = ReportGenerator()
    report = gen.generate_json_report(scan, [finding])
    assert report["findings"][0]["standards"]["owasp"]["id"] == "API1:2023"
    assert "API1:2023" in gen.generate_html_report(scan, [finding])

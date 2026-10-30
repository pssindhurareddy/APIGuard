"""Report generation service producing HTML and JSON artifacts."""
import json
import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from ..config import TEMPLATES_DIR, REPORTS_DIR
from .evidence_redactor import redact_evidence
from .standards import enrich


class ReportGenerator:
    """Generates structured JSON and styled HTML reports."""

    def __init__(self):
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def generate_json_report(
        self,
        scan: dict[str, Any],
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Produce machine-readable JSON security report."""
        processed_findings = []
        for f in findings:
            item = dict(f)
            if isinstance(item.get("evidence"), str):
                try:
                    item["evidence"] = json.loads(item["evidence"])
                except Exception:
                    item["evidence"] = {}
            if item.get("evidence"):
                item["evidence"] = redact_evidence(item["evidence"])
            enrich(item)
            processed_findings.append(item)

        categories = scan.get("categories", "[]")
        if isinstance(categories, str):
            try:
                categories = json.loads(categories)
            except Exception:
                categories = []

        return {
            "report_title": "APIGuard Security Assessment Report",
            "framework_version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_metadata": {
                "scan_id": scan.get("id"),
                "target_name": scan.get("target_name"),
                "target_url": scan.get("target_url"),
                "status": scan.get("status"),
                "categories": categories,
                "started_at": scan.get("started_at"),
                "completed_at": scan.get("completed_at"),
                "duration_ms": scan.get("duration_ms"),
                "summary": scan.get("summary"),
            },
            "statistics": {
                "total_tests": scan.get("total_tests", 0),
                "passed": scan.get("passed", 0),
                "confirmed": scan.get("confirmed", 0),
                "suspected": scan.get("suspected", 0),
                "errors": scan.get("errors", 0),
                "skipped": scan.get("skipped", 0),
            },
            "severity_breakdown": self._calculate_severity_breakdown(processed_findings),
            "findings": processed_findings,
            "remediation_summary": self._extract_remediation_summary(processed_findings),
            "coverage_limitations": [
                "Automated scanning covers four explicit vulnerability categories: Auth, AuthZ (BOLA), Input, Data Exposure.",
                "Assessments depend on declared endpoint specifications and synthetic identities.",
                "Business logic vulnerabilities outside defined policies require dedicated manual penetration testing.",
                "Rate-limiting and denial-of-service tests are explicitly omitted for safety.",
            ],
            "ethical_testing_statement": (
                "APIGuard is built strictly for authorized testing and academic research. "
                "Testing third-party systems without prior explicit written permission is strictly prohibited."
            ),
        }

    def generate_html_report(
        self,
        scan: dict[str, Any],
        findings: list[dict[str, Any]],
    ) -> str:
        """Render complete HTML report using Jinja2."""
        report_data = self.generate_json_report(scan, findings)
        try:
            template = self.jinja_env.get_template("report.html")
            return template.render(report=report_data)
        except Exception:
            return self._generate_fallback_html(report_data)

    def _calculate_severity_breakdown(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            if f.get("status") in ("CONFIRMED", "SUSPECTED"):
                sev = f.get("severity", "INFO")
                breakdown[sev] = breakdown.get(sev, 0) + 1
        return breakdown

    def _extract_remediation_summary(self, findings: list[dict[str, Any]]) -> list[dict[str, str]]:
        rems = []
        for f in findings:
            if f.get("status") in ("CONFIRMED", "SUSPECTED") and f.get("remediation"):
                rems.append({
                    "test_id": f.get("test_id", ""),
                    "endpoint": f.get("endpoint", ""),
                    "action": f.get("remediation", ""),
                })
        return rems

    def _generate_fallback_html(self, report: dict[str, Any]) -> str:
        scan = report.get("scan_metadata", {})
        stats = report.get("statistics", {})
        findings = report.get("findings", [])

        rows = ""
        for f in findings:
            color = "#ef4444" if f.get("status") == "CONFIRMED" else "#10b981"
            rows += f"""
            <tr style="border-bottom: 1px solid #334155;">
                <td style="padding: 10px;">{html.escape(str(f.get('test_id')))}</td>
                <td style="padding: 10px;">{html.escape(str(f.get('test_name')))}</td>
                <td style="padding: 10px;">{html.escape(str(f.get('http_method')))} {html.escape(str(f.get('endpoint')))}</td>
                <td style="padding: 10px; color: {color}; font-weight: bold;">{html.escape(str(f.get('status')))}</td>
                <td style="padding: 10px;">{html.escape(str(f.get('severity')))}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>APIGuard Report - {html.escape(str(scan.get('scan_id')))}</title></head>
<body style="background:#0f172a;color:#f8fafc;font-family:sans-serif;padding:30px;max-width:1000px;margin:auto;">
    <h1 style="color:#38bdf8;">🛡️ APIGuard Security Assessment Report</h1>
    <p>Target: <strong>{html.escape(str(scan.get('target_name')))}</strong> ({html.escape(str(scan.get('target_url')))})</p>
    <p>Generated: {html.escape(str(report.get('generated_at')))}</p>
    <h3>Statistics: Total: {stats.get('total_tests')} | Passed: {stats.get('passed')} | Confirmed: {stats.get('confirmed')}</h3>
    <table style="width:100%;border-collapse:collapse;margin-top:20px;">
        <thead>
            <tr style="background:#1e293b;text-align:left;">
                <th style="padding:10px;">Test ID</th>
                <th style="padding:10px;">Name</th>
                <th style="padding:10px;">Endpoint</th>
                <th style="padding:10px;">Status</th>
                <th style="padding:10px;">Severity</th>
            </tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>
</body></html>"""


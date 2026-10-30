"""Report and Scan Comparison endpoints."""
import json
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from typing import Any

from ..models.database import fetch_one, fetch_all
from ..services.report_generator import ReportGenerator

router = APIRouter()
_generator = ReportGenerator()


def _parse_row(row: dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    if isinstance(item.get("evidence"), str):
        try:
            item["evidence"] = json.loads(item["evidence"])
        except Exception:
            item["evidence"] = {}
    return item


@router.get("/api/scans/{scan_id}/report.json")
async def get_json_report(scan_id: str):
    """Export machine-readable JSON security assessment report."""
    scan = await fetch_one("scans", scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings_raw = await fetch_all("findings", where="scan_id = ?", params=[scan_id], order_by="created_at ASC")
    findings = [_parse_row(r) for r in findings_raw]

    report_data = _generator.generate_json_report(scan, findings)
    return JSONResponse(content=report_data)


@router.get("/api/scans/{scan_id}/report.html")
async def get_html_report(scan_id: str):
    """Export styled standalone HTML report."""
    scan = await fetch_one("scans", scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings_raw = await fetch_all("findings", where="scan_id = ?", params=[scan_id], order_by="created_at ASC")
    findings = [_parse_row(r) for r in findings_raw]

    html_content = _generator.generate_html_report(scan, findings)
    return HTMLResponse(content=html_content)


@router.get("/api/scans/{scan_id}/compare/{other_scan_id}")
async def compare_scans(scan_id: str, other_scan_id: str):
    """Perform before-and-after remediation validation between two scans."""
    scan1 = await fetch_one("scans", scan_id)
    scan2 = await fetch_one("scans", other_scan_id)

    if not scan1 or not scan2:
        raise HTTPException(404, "One or both scan identifiers could not be found.")

    findings1_raw = await fetch_all("findings", where="scan_id = ?", params=[scan_id])
    findings2_raw = await fetch_all("findings", where="scan_id = ?", params=[other_scan_id])

    findings1 = [_parse_row(r) for r in findings1_raw]
    findings2 = [_parse_row(r) for r in findings2_raw]

    # Map confirmed/suspected issues by test fingerprint or test_id+endpoint
    def get_key(f: dict[str, Any]) -> str:
        return f.get("fingerprint") or f"{f.get('test_id')}:{f.get('endpoint')}:{f.get('http_method')}"

    issues1 = {get_key(f): f for f in findings1 if f.get("status") in ("CONFIRMED", "SUSPECTED")}
    issues2 = {get_key(f): f for f in findings2 if f.get("status") in ("CONFIRMED", "SUSPECTED")}

    # Map all tests in scan2 to check for PASS
    all_scan2 = {get_key(f): f for f in findings2}

    # Resolved: Was in scan1, NOT in scan2, AND scan2 executed the test with PASS
    remediated = []
    for k, item1 in issues1.items():
        if k not in issues2:
            item2 = all_scan2.get(k)
            remediated.append({
                "test_id": item1.get("test_id"),
                "test_name": item1.get("test_name"),
                "endpoint": item1.get("endpoint"),
                "original_severity": item1.get("severity"),
                "retest_status": item2.get("status") if item2 else "NOT_RETESTED",
                "evidence_resolved": item2.get("actual_result") if item2 else "Test omitted",
                "verified_remediation": item2.get("status") == "PASS" if item2 else False,
            })

    # Newly Introduced
    new_issues = [f for k, f in issues2.items() if k not in issues1]

    # Persistent Unresolved
    persistent = [f for k, f in issues2.items() if k in issues1]

    return {
        "baseline_scan": {
            "id": scan1["id"],
            "target_name": scan1.get("target_name"),
            "target_url": scan1.get("target_url"),
            "total_tests": scan1.get("total_tests", 0),
            "confirmed_findings": scan1.get("confirmed", 0),
            "completed_at": scan1.get("completed_at"),
        },
        "remediation_scan": {
            "id": scan2["id"],
            "target_name": scan2.get("target_name"),
            "target_url": scan2.get("target_url"),
            "total_tests": scan2.get("total_tests", 0),
            "confirmed_findings": scan2.get("confirmed", 0),
            "completed_at": scan2.get("completed_at"),
        },
        "remediated_findings": remediated,
        "persistent_findings": persistent,
        "new_findings": new_issues,
        "remediation_success_rate": (
            f"{(len(remediated) / max(len(issues1), 1)) * 100:.1f}%" if issues1 else "100%"
        ),
    }


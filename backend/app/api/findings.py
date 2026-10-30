"""Findings API endpoints providing search, inspection, and status management."""
import json
from fastapi import APIRouter, HTTPException
from typing import Optional
from ..models.database import fetch_all, fetch_one, update_row
from ..schemas.scan import UpdateFindingRequest
from ..services.standards import enrich

router = APIRouter()


def _format_finding(row: dict) -> dict:
    item = dict(row)
    if isinstance(item.get("evidence"), str):
        try:
            item["evidence"] = json.loads(item["evidence"])
        except Exception:
            item["evidence"] = {}
    return enrich(item)


@router.get("/api/findings")
async def list_findings(
    scan_id: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    finding_status: Optional[str] = None,
):
    """Filter and query findings across all or specific scans."""
    clauses = []
    params = []
    if scan_id:
        clauses.append("scan_id = ?")
        params.append(scan_id)
    if category:
        clauses.append("category = ?")
        params.append(category)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if finding_status:
        clauses.append("finding_status = ?")
        params.append(finding_status)

    where = " AND ".join(clauses) if clauses else ""
    rows = await fetch_all("findings", where=where, params=params, order_by="created_at DESC")
    return [_format_finding(r) for r in rows]


@router.get("/api/scans/{scan_id}/findings")
async def get_scan_findings(scan_id: str):
    """Retrieve all findings belonging to a specific scan run."""
    scan = await fetch_one("scans", scan_id)
    if not scan:
        raise HTTPException(404, "Scan run not found")
    rows = await fetch_all("findings", where="scan_id = ?", params=[scan_id], order_by="created_at ASC")
    return [_format_finding(r) for r in rows]


@router.get("/api/findings/{finding_id}")
async def get_finding(finding_id: str):
    """Retrieve in-depth details for a single finding."""
    f = await fetch_one("findings", finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    return _format_finding(f)


@router.patch("/api/findings/{finding_id}")
async def update_finding_status(finding_id: str, req: UpdateFindingRequest):
    """Update workflow status of finding (OPEN, ACKNOWLEDGED, FIXED, ACCEPTED_RISK)."""
    f = await fetch_one("findings", finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")

    await update_row("findings", finding_id, {"finding_status": req.finding_status.value})
    updated = await fetch_one("findings", finding_id)
    return _format_finding(updated)


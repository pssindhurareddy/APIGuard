"""Scan lifecycle API endpoints."""
import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional

from ..models.database import insert_row, fetch_one, fetch_all
from ..services.scan_orchestrator import ScanOrchestrator
from ..schemas.scan import CreateScanRequest

router = APIRouter()
_orchestrator = ScanOrchestrator()


@router.get("/api/scans")
async def list_scans():
    """Retrieve full scan history."""
    rows = await fetch_all("scans", order_by="created_at DESC")
    out = []
    for r in rows:
        item = dict(r)
        if isinstance(item.get("categories"), str):
            try:
                item["categories"] = json.loads(item["categories"])
            except Exception:
                item["categories"] = []
        out.append(item)
    return out


@router.post("/api/scans", status_code=201)
async def create_scan(req: CreateScanRequest, background_tasks: BackgroundTasks):
    """Initiate a security scan run against an authorized target."""
    target = await fetch_one("targets", req.target_id)
    if not target:
        raise HTTPException(404, "Target not found")

    valid_cats = {"authentication", "authorization", "input_validation", "data_exposure"}
    for c in req.categories:
        if c not in valid_cats:
            raise HTTPException(400, f"Unknown test category: '{c}'. Valid categories: {sorted(valid_cats)}")

    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    await insert_row("scans", {
        "id": scan_id,
        "target_id": req.target_id,
        "target_name": target["name"],
        "target_url": target["base_url"],
        "status": "QUEUED",
        "categories": json.dumps(req.categories),
        "auth_profile": req.auth_profile,
        "created_at": now,
    })

    # Schedule scan execution in background
    background_tasks.add_task(
        _orchestrator.execute_scan, scan_id, target, req.categories
    )

    created = await fetch_one("scans", scan_id)
    resp = dict(created)
    if isinstance(resp.get("categories"), str):
        try:
            resp["categories"] = json.loads(resp["categories"])
        except Exception:
            resp["categories"] = []
    return resp


@router.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Retrieve status and summary of a specific scan."""
    scan = await fetch_one("scans", scan_id)
    if not scan:
        raise HTTPException(404, "Scan run not found")
    res = dict(scan)
    if isinstance(res.get("categories"), str):
        try:
            res["categories"] = json.loads(res["categories"])
        except Exception:
            res["categories"] = []
    return res


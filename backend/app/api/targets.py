"""Target management endpoints with scope validation."""
import json
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Any

from ..models.database import insert_row, update_row, fetch_one, fetch_all
from ..config import LOOPBACK_ADDRESSES, LOOPBACK_HOSTNAMES, ALLOWED_SCHEMES
from ..schemas.target import CreateTargetRequest, UpdateTargetRequest

router = APIRouter()


def _validate_target_url(url: str) -> tuple[str, int]:
    """Validate URL syntax, scheme, and default loopback boundaries."""
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise HTTPException(400, f"Scheme '{parsed.scheme}' not allowed. Must be http or https.")
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(400, "URL must contain a valid hostname.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # Restrict to loopback by default for safety
    if hostname not in LOOPBACK_ADDRESSES and hostname not in LOOPBACK_HOSTNAMES:
        raise HTTPException(
            400,
            f"Host '{hostname}' is not a loopback address. "
            "Academic prototype is restricted to loopback testing (127.0.0.1 or localhost) by default."
        )
    return hostname, port


def _serialize_target(row: dict[str, Any]) -> dict[str, Any]:
    """Serialize target record, ensuring credentials and auth tokens are NOT leaked."""
    res = dict(row)
    for field in ("allowed_hosts", "allowed_ports", "allowed_paths", "allowed_methods"):
        if isinstance(res.get(field), str):
            try:
                res[field] = json.loads(res[field])
            except Exception:
                res[field] = []

    auth_profiles = res.get("auth_profiles", "{}")
    if isinstance(auth_profiles, str):
        try:
            auth_profiles = json.loads(auth_profiles)
        except Exception:
            auth_profiles = {}

    # Expose only safe metadata (role, username) without secrets
    res["auth_profiles_public"] = [
        {"name": k, "username": v.get("username", k), "role": v.get("role", "user")}
        for k, v in auth_profiles.items()
    ]
    res.pop("auth_profiles", None)
    res["is_authorized"] = bool(res.get("is_authorized", 0))
    return res


@router.get("/api/targets")
async def list_targets():
    """List all configured API scan targets."""
    rows = await fetch_all("targets", order_by="created_at ASC, rowid ASC")
    return [_serialize_target(r) for r in rows]


@router.post("/api/targets", status_code=201)
async def create_target(req: CreateTargetRequest):
    """Register a new scan target subject to scope validation."""
    hostname, port = _validate_target_url(req.base_url)
    target_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    await insert_row("targets", {
        "id": target_id,
        "name": req.name,
        "base_url": req.base_url.rstrip("/"),
        "environment": req.environment,
        "allowed_hosts": json.dumps([hostname]),
        "allowed_ports": json.dumps([port]),
        "allowed_paths": json.dumps(req.allowed_paths),
        "allowed_methods": json.dumps(req.allowed_methods),
        "is_authorized": int(req.is_authorized),
        "auth_profiles": json.dumps(req.auth_profiles),
        "created_at": now,
        "updated_at": now,
    })

    record = await fetch_one("targets", target_id)
    return _serialize_target(record)


@router.get("/api/targets/{target_id}")
async def get_target(target_id: str):
    """Retrieve details for a single target."""
    record = await fetch_one("targets", target_id)
    if not record:
        raise HTTPException(404, "Target not found")
    return _serialize_target(record)


@router.patch("/api/targets/{target_id}")
async def update_target(target_id: str, req: UpdateTargetRequest):
    """Update target configuration parameters."""
    target = await fetch_one("targets", target_id)
    if not target:
        raise HTTPException(404, "Target not found")

    updates: dict[str, Any] = {"updated_at": datetime.now(timezone.utc).isoformat()}
    if req.base_url is not None:
        hostname, port = _validate_target_url(req.base_url)
        updates["base_url"] = req.base_url.rstrip("/")
        updates["allowed_hosts"] = json.dumps([hostname])
        updates["allowed_ports"] = json.dumps([port])
    if req.name is not None:
        updates["name"] = req.name
    if req.environment is not None:
        updates["environment"] = req.environment
    if req.allowed_paths is not None:
        updates["allowed_paths"] = json.dumps(req.allowed_paths)
    if req.allowed_methods is not None:
        updates["allowed_methods"] = json.dumps(req.allowed_methods)
    if req.is_authorized is not None:
        updates["is_authorized"] = int(req.is_authorized)
    if req.auth_profiles is not None:
        updates["auth_profiles"] = json.dumps(req.auth_profiles)

    await update_row("targets", target_id, updates)
    updated = await fetch_one("targets", target_id)
    return _serialize_target(updated)


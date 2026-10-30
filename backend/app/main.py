"""APIGuard Scanner Backend - Master Application Entrypoint."""
import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .models.database import init_db, insert_row, fetch_one, fetch_all
from .api import health, targets, scans, findings, reports, test_cases, openapi_routes


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize SQLite database and seed default demonstration targets."""
    await init_db()
    await _seed_demo_targets()
    await _seed_yaml_targets()
    yield


app = FastAPI(
    title="APIGuard — Automated REST API Security Testing Framework",
    description=(
        "Local-first cybersecurity testing framework assessing REST APIs for "
        "authentication, authorization (BOLA), input validation, and excessive data exposure."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS configuration - narrow to local frontend development server
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Global safe exception handler: prevents internal paths or raw stack traces from leaking
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred during request processing.",
            "type": type(exc).__name__,
        },
    )

# Register API Route Handlers
app.include_router(health.router, tags=["Health"])
app.include_router(targets.router, tags=["Targets"])
app.include_router(scans.router, tags=["Scans"])
app.include_router(findings.router, tags=["Findings"])
app.include_router(reports.router, tags=["Reports"])
app.include_router(test_cases.router, tags=["Test Cases"])
app.include_router(openapi_routes.router, tags=["OpenAPI"])


async def _seed_demo_targets():
    """Seed default local vulnerable and secure demonstration API targets if missing."""
    now_iso = datetime.now(timezone.utc).isoformat()

    # Synthetic demo profiles (STATIC DEMO CREDENTIALS ONLY)
    demo_profiles = {
        "alice": {
            "username": "alice",
            "role": "user",
            "token": "demo-token-alice-12345",
        },
        "bob": {
            "username": "bob",
            "role": "user",
            "token": "demo-token-bob-67890",
        },
        "admin": {
            "username": "admin",
            "role": "admin",
            "token": "demo-token-admin-99999",
        },
    }

    # 1. Vulnerable Demo Target (Port 8001)
    vuln_target = await fetch_one("targets", "target-vulnerable-demo")
    if not vuln_target:
        await insert_row("targets", {
            "id": "target-vulnerable-demo",
            "name": "Local Vulnerable Demo API",
            "base_url": "http://127.0.0.1:8001",
            "environment": "demo",
            "allowed_hosts": json.dumps(["127.0.0.1", "localhost"]),
            "allowed_ports": json.dumps([8001]),
            "allowed_paths": json.dumps(["/api/"]),
            "allowed_methods": json.dumps(["GET", "POST", "PUT", "PATCH", "DELETE"]),
            "is_authorized": 1,
            "auth_profiles": json.dumps(demo_profiles),
            "created_at": now_iso,
            "updated_at": now_iso,
        })

    # 2. Secured Demo Target (Port 8002)
    sec_target = await fetch_one("targets", "target-secure-demo")
    if not sec_target:
        await insert_row("targets", {
            "id": "target-secure-demo",
            "name": "Local Secured Demo API",
            "base_url": "http://127.0.0.1:8002",
            "environment": "demo",
            "allowed_hosts": json.dumps(["127.0.0.1", "localhost"]),
            "allowed_ports": json.dumps([8002]),
            "allowed_paths": json.dumps(["/api/"]),
            "allowed_methods": json.dumps(["GET", "POST", "PUT", "PATCH", "DELETE"]),
            "is_authorized": 1,
            "auth_profiles": json.dumps(demo_profiles),
            "created_at": now_iso,
            "updated_at": now_iso,
        })


async def _seed_yaml_targets():
    """Register every additional target declared in config/demo_targets.yaml
    (e.g. the third-party VAmPI benchmark). Login credentials are NOT copied
    into the database; the orchestrator reads them from YAML at scan time."""
    import yaml
    from .config import CONFIG_DIR

    yaml_path = CONFIG_DIR / "demo_targets.yaml"
    if not yaml_path.exists():
        return
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    now_iso = datetime.now(timezone.utc).isoformat()
    for t in data.get("targets", []):
        if not t.get("id") or await fetch_one("targets", t["id"]):
            continue
        public_profiles = {
            name: {k: v for k, v in (prof or {}).items() if k in ("username", "role")}
            for name, prof in (t.get("auth_profiles") or {}).items()
        }
        await insert_row("targets", {
            "id": t["id"],
            "name": t.get("name", t["id"]),
            "base_url": t["base_url"],
            "environment": t.get("environment", "demo"),
            "allowed_hosts": json.dumps(t.get("allowed_hosts", ["127.0.0.1"])),
            "allowed_ports": json.dumps(t.get("allowed_ports", [])),
            "allowed_paths": json.dumps(t.get("allowed_paths", ["/"])),
            "allowed_methods": json.dumps(t.get("allowed_methods", ["GET", "POST"])),
            "is_authorized": 1 if t.get("is_authorized", False) else 0,
            "auth_profiles": json.dumps(public_profiles),
            "created_at": now_iso,
            "updated_at": now_iso,
        })


# ---------------------------------------------------------------------------
# Dashboard hosting
# The pre-built React dashboard (frontend/dist) is served by this backend at
# http://127.0.0.1:8000/ so the tool runs without Node.js or a separate dev
# server. API routes above are registered first and therefore take precedence.
# ---------------------------------------------------------------------------
from pathlib import Path as _Path

from fastapi.responses import HTMLResponse as _HTMLResponse
from fastapi.staticfiles import StaticFiles as _StaticFiles

_DASHBOARD_DIR = _Path(__file__).resolve().parents[2] / "frontend" / "dist"

if (_DASHBOARD_DIR / "index.html").exists():
    app.mount("/", _StaticFiles(directory=_DASHBOARD_DIR, html=True), name="dashboard")
else:
    @app.get("/", include_in_schema=False)
    async def _dashboard_missing():
        return _HTMLResponse(
            "<h2>APIGuard backend is running.</h2>"
            "<p>The dashboard build (frontend/dist) was not found. Build it with "
            "<code>cd frontend &amp;&amp; npm install &amp;&amp; npm run build</code>, then restart the backend.</p>"
            "<p>API health: <a href='/api/health'>/api/health</a> &middot; API docs: <a href='/docs'>/docs</a></p>",
            status_code=200,
        )

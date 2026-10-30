"""Health check endpoint probing scanner engine and demo targets."""
from fastapi import APIRouter
import httpx

router = APIRouter()


@router.get("/api/health")
async def health_check():
    """Verify backend health and live probe local demonstration APIs."""
    demo_status = {}
    probes = [
        ("vulnerable_demo", 8001, "/api/health"),
        ("secure_demo", 8002, "/api/health"),
        ("vampi_vulnerable", 8003, "/"),  # third-party VAmPI benchmark
        ("vampi_secure", 8004, "/"),
    ]
    for name, port, probe_path in probes:
        try:
            async with httpx.AsyncClient(timeout=1.5) as client:
                res = await client.get(f"http://127.0.0.1:{port}{probe_path}")
                if res.status_code == 200:
                    demo_status[name] = {"status": "online", "port": port, "details": res.json()}
                else:
                    demo_status[name] = {"status": "error", "port": port, "code": res.status_code}
        except Exception:
            demo_status[name] = {"status": "offline", "port": port}

    return {
        "status": "healthy",
        "service": "APIGuard Security Scanner Backend",
        "version": "1.0.0",
        "demo_apis": demo_status,
    }


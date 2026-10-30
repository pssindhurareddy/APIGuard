"""Health check endpoint."""
from fastapi import APIRouter, Request

router = APIRouter()

@router.get("/api/health")
async def health_check(request: Request):
    mode = getattr(request.app.state, "mode", "unknown")
    return {
        "status": "healthy",
        "mode": mode,
        "service": "APIGuard Demo API",
        "version": "1.0.0",
    }


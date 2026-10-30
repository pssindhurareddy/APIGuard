"""Admin endpoints - demonstrate privilege escalation vulnerability."""
from fastapi import APIRouter, Request, Header, HTTPException
from typing import Optional
from ..security import (
    get_current_user_required,
    get_current_user_optional,
    require_admin,
    get_mode,
)
from ..fixtures import ADMIN_STATS

router = APIRouter()


@router.get("/api/admin/stats")
async def get_admin_stats(
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """Get administrative statistics.
    
    VULNERABLE MODE:
    - Any authenticated user can access (no role check)
    
    SECURE MODE:
    - Only admin role can access
    """
    mode = get_mode(request)
    
    if mode == "vulnerable":
        # VULNERABILITY: No role check - any user can access admin endpoint
        username = get_current_user_optional(authorization)
        # Accept even without auth in vulnerable mode
        return ADMIN_STATS
    else:
        # SECURE: Require authentication AND admin role
        username = get_current_user_required(authorization)
        require_admin(username)
        return ADMIN_STATS


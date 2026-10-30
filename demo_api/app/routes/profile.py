"""Profile endpoints - demonstrate auth and data exposure vulnerabilities."""
from fastapi import APIRouter, Request, Header, HTTPException
from typing import Optional
from ..security import (
    get_current_user_optional,
    get_current_user_required,
    get_mode,
    extract_token,
    DEMO_TOKENS,
)
from ..fixtures import get_user_safe, get_user_full, USERS

router = APIRouter()


@router.get("/api/profile")
async def get_profile(request: Request, authorization: Optional[str] = Header(None)):
    """Get current user's profile.
    
    VULNERABLE MODE:
    - Returns data even without auth token
    - Exposes sensitive fields (password_hash, internal_notes, api_key)
    
    SECURE MODE:
    - Requires valid authentication
    - Returns only safe fields
    """
    mode = get_mode(request)
    
    if mode == "vulnerable":
        # VULNERABILITY: No authentication required
        # VULNERABILITY: Returns sensitive fields
        username = get_current_user_optional(authorization)
        if username is None:
            # In vulnerable mode, default to alice's profile when no auth
            username = "alice"
        return get_user_full(username)
    else:
        # SECURE: Require authentication
        username = get_current_user_required(authorization)
        # SECURE: Return only safe fields
        return get_user_safe(username)


@router.get("/api/users/{user_id}/profile")
async def get_user_profile(
    user_id: str,
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """Get a specific user's profile by user ID.
    
    VULNERABLE MODE:
    - Any authenticated user can view any other user's profile
    - Exposes sensitive fields
    
    SECURE MODE:
    - Users can only view their own profile (ownership enforced)
    - Admin can view any profile
    - Returns only safe fields
    """
    mode = get_mode(request)

    # SECURE: authenticate before resolving the user ID (no existence oracle).
    if mode != "vulnerable":
        get_current_user_required(authorization)

    # Find user by ID
    target_user = None
    for uname, udata in USERS.items():
        if udata["id"] == user_id:
            target_user = uname
            break
    
    if target_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    if mode == "vulnerable":
        # VULNERABILITY: No ownership check - any user can see any profile
        # VULNERABILITY: Returns sensitive fields
        token = extract_token(authorization)
        if token and token not in DEMO_TOKENS:
            raise HTTPException(status_code=401, detail="Invalid token")
        return get_user_full(target_user)
    else:
        # SECURE: Require auth
        username = get_current_user_required(authorization)
        # SECURE: Ownership check (admin can view any)
        user_data = USERS.get(username, {})
        if username != target_user and user_data.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Access denied: you can only view your own profile")
        # SECURE: Return only safe fields
        return get_user_safe(target_user)


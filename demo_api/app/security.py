"""Security utilities for the demo API.

Handles token validation and user extraction for both
vulnerable and secure modes.
"""

from fastapi import Header, HTTPException, Request
from typing import Optional
from .fixtures import DEMO_TOKENS, USERS


def get_mode(request: Request) -> str:
    """Get the current API mode from app state."""
    return getattr(request.app.state, "mode", "vulnerable")


def extract_token(authorization: Optional[str] = Header(None)) -> Optional[str]:
    """Extract bearer token from Authorization header."""
    if authorization is None:
        return None
    if not authorization.startswith("Bearer "):
        return None
    return authorization[7:]


def get_current_user_optional(authorization: Optional[str] = Header(None)) -> Optional[str]:
    """Extract username from token, return None if not authenticated.
    Does NOT raise - used for endpoints that may or may not require auth.
    """
    token = extract_token(authorization)
    if token is None:
        return None
    return DEMO_TOKENS.get(token)


def get_current_user_required(authorization: Optional[str] = Header(None)) -> str:
    """Extract username from token, raise 401 if not authenticated."""
    token = extract_token(authorization)
    if token is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    username = DEMO_TOKENS.get(token)
    if username is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return username


def require_admin(username: str) -> None:
    """Check if user has admin role, raise 403 if not."""
    user = USERS.get(username)
    if user is None or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required")


def check_resource_ownership(username: str, resource_owner: str) -> bool:
    """Check if user owns the resource."""
    return username == resource_owner


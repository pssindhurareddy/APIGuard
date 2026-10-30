"""Synthetic demonstration data for APIGuard demo API.

All data is fake and for testing purposes only.
DEMO TOKENS ARE NOT REAL CREDENTIALS - they are static test values.
"""

from datetime import datetime
from typing import Any

# ============================================================
# DEMONSTRATION-ONLY TOKENS - NOT REAL CREDENTIALS
# These are static fake tokens used only for local testing.
# ============================================================
DEMO_TOKENS: dict[str, str] = {
    "demo-token-alice-12345": "alice",
    "demo-token-bob-67890": "bob",
    "demo-token-admin-99999": "admin",
}

USERS: dict[str, dict[str, Any]] = {
    "alice": {
        "id": "user-alice-001",
        "username": "alice",
        "display_name": "Alice Demo",
        "email": "alice@demo.local",
        "role": "user",
        "password_hash": "FAKE_HASH_NOT_REAL_a1b2c3d4",
        "internal_notes": "Test account for vulnerability demonstration",
        "api_key": "FAKE_API_KEY_alice_xyz789",
        "created_at": "2024-01-15T10:00:00Z",
    },
    "bob": {
        "id": "user-bob-002",
        "username": "bob",
        "display_name": "Bob Demo",
        "email": "bob@demo.local",
        "role": "user",
        "password_hash": "FAKE_HASH_NOT_REAL_e5f6g7h8",
        "internal_notes": "Test account for authorization testing",
        "api_key": "FAKE_API_KEY_bob_abc123",
        "created_at": "2024-01-16T11:00:00Z",
    },
    "admin": {
        "id": "user-admin-003",
        "username": "admin",
        "display_name": "Admin Demo",
        "email": "admin@demo.local",
        "role": "admin",
        "password_hash": "FAKE_HASH_NOT_REAL_i9j0k1l2",
        "internal_notes": "Administrator test account",
        "api_key": "FAKE_API_KEY_admin_def456",
        "created_at": "2024-01-10T09:00:00Z",
    },
}

# Safe user fields that should be in API responses
SAFE_USER_FIELDS = {"id", "username", "display_name", "email", "role", "created_at"}

# Fields that should NEVER appear in API responses
FORBIDDEN_USER_FIELDS = {"password_hash", "internal_notes", "api_key"}

ORDERS: dict[str, dict[str, Any]] = {
    "order-1001": {
        "id": "order-1001",
        "owner": "alice",
        "product": "Security Scanner License",
        "quantity": 1,
        "price": 99.99,
        "status": "completed",
        "created_at": "2024-06-01T14:30:00Z",
    },
    "order-1002": {
        "id": "order-1002",
        "owner": "bob",
        "product": "Penetration Testing Toolkit",
        "quantity": 2,
        "price": 149.99,
        "status": "pending",
        "created_at": "2024-06-15T09:00:00Z",
    },
    "order-1003": {
        "id": "order-1003",
        "owner": "alice",
        "product": "API Gateway Subscription",
        "quantity": 1,
        "price": 29.99,
        "status": "completed",
        "created_at": "2024-07-01T16:45:00Z",
    },
}

ADMIN_STATS: dict[str, Any] = {
    "total_users": 3,
    "total_orders": 3,
    "revenue": 329.97,
    "active_sessions": 2,
    "server_version": "demo-1.0.0",
    "internal_config": {
        "debug_mode": False,
        "db_connection_string": "sqlite:///demo.db",
    },
}


def reset_fixtures() -> dict[str, str]:
    """Reset all fixture data to defaults. Returns confirmation."""
    return {"status": "reset", "message": "All demo fixtures reset to defaults"}


def get_user_safe(username: str) -> dict[str, Any] | None:
    """Return user data with only safe fields."""
    user = USERS.get(username)
    if user is None:
        return None
    return {k: v for k, v in user.items() if k in SAFE_USER_FIELDS}


def get_user_full(username: str) -> dict[str, Any] | None:
    """Return user data including sensitive fields (for vulnerable mode)."""
    user = USERS.get(username)
    if user is None:
        return None
    return dict(user)


"""Target configuration schemas."""
from pydantic import BaseModel, Field
from typing import Optional, Any


class AuthProfilePublic(BaseModel):
    """Auth profile summary with zero secret/token exposure."""
    name: str
    username: str
    role: str


class CreateTargetRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    base_url: str = Field(..., min_length=1)
    environment: str = Field(default="demo")
    allowed_paths: list[str] = Field(default_factory=lambda: ["/api/"])
    allowed_methods: list[str] = Field(default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE"])
    is_authorized: bool = False
    auth_profiles: dict[str, Any] = Field(default_factory=dict)


class UpdateTargetRequest(BaseModel):
    name: Optional[str] = None
    base_url: Optional[str] = None
    environment: Optional[str] = None
    allowed_paths: Optional[list[str]] = None
    allowed_methods: Optional[list[str]] = None
    is_authorized: Optional[bool] = None
    auth_profiles: Optional[dict[str, Any]] = None


class TargetResponse(BaseModel):
    id: str
    name: str
    base_url: str
    environment: str
    allowed_hosts: list[str]
    allowed_ports: list[int]
    allowed_paths: list[str]
    allowed_methods: list[str]
    is_authorized: bool
    auth_profiles_public: list[AuthProfilePublic]
    created_at: str
    updated_at: str
    last_scan_id: Optional[str] = None
    last_scan_status: Optional[str] = None


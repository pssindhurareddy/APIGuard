"""Automated tests for ScopeGuard boundary enforcement (Ethical Safeguards)."""
import sys
from pathlib import Path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import pytest
from app.services.scope_guard import ScopeGuard, ScopeViolation


def test_scope_guard_permits_in_scope_loopback():
    guard = ScopeGuard(
        allowed_hosts=["127.0.0.1"],
        allowed_ports=[8001],
        allowed_paths=["/api/"],
        allowed_methods=["GET", "POST"],
        require_loopback=True,
    )
    guard.validate_request("GET", "http://127.0.0.1:8001/api/profile")
    guard.validate_request("POST", "http://127.0.0.1:8001/api/orders")


def test_scope_guard_rejects_out_of_scope_host():
    guard = ScopeGuard(
        allowed_hosts=["127.0.0.1"],
        allowed_ports=[8001],
        allowed_paths=["/api/"],
        allowed_methods=["GET"],
        require_loopback=True,
    )
    with pytest.raises(ScopeViolation, match="out-of-scope"):
        guard.validate_url("http://192.168.1.50:8001/api/profile")


def test_scope_guard_rejects_public_internet_host():
    guard = ScopeGuard(
        allowed_hosts=["127.0.0.1"],
        allowed_ports=[8001],
        allowed_paths=["/api/"],
        allowed_methods=["GET"],
        require_loopback=True,
    )
    with pytest.raises(ScopeViolation):
        guard.validate_url("http://evil.com:8001/api/profile")


def test_scope_guard_rejects_out_of_scope_port():
    guard = ScopeGuard(
        allowed_hosts=["127.0.0.1"],
        allowed_ports=[8001],
        allowed_paths=["/api/"],
        allowed_methods=["GET"],
    )
    with pytest.raises(ScopeViolation, match="Port 9000"):
        guard.validate_url("http://127.0.0.1:9000/api/profile")


def test_scope_guard_rejects_unapproved_path():
    guard = ScopeGuard(
        allowed_hosts=["127.0.0.1"],
        allowed_ports=[8001],
        allowed_paths=["/api/"],
        allowed_methods=["GET"],
    )
    with pytest.raises(ScopeViolation, match="outside permitted path"):
        guard.validate_url("http://127.0.0.1:8001/admin/secret")


def test_scope_guard_rejects_unapproved_method():
    guard = ScopeGuard(
        allowed_hosts=["127.0.0.1"],
        allowed_ports=[8001],
        allowed_paths=["/api/"],
        allowed_methods=["GET"],
    )
    with pytest.raises(ScopeViolation, match="method 'DELETE' is disallowed"):
        guard.validate_method("DELETE")


def test_scope_guard_rejects_url_credentials():
    guard = ScopeGuard(
        allowed_hosts=["127.0.0.1"],
        allowed_ports=[8001],
        allowed_paths=["/api/"],
        allowed_methods=["GET"],
    )
    with pytest.raises(ScopeViolation, match="URL credentials"):
        guard.validate_url("http://admin:secret@127.0.0.1:8001/api/profile")


def test_scope_guard_rejects_out_of_scope_redirect():
    guard = ScopeGuard(
        allowed_hosts=["127.0.0.1"],
        allowed_ports=[8001],
        allowed_paths=["/api/"],
        allowed_methods=["GET"],
    )
    with pytest.raises(ScopeViolation):
        guard.validate_redirect(
            "http://127.0.0.1:8001/api/profile",
            "http://attacker.example.com/steal"
        )


def test_scope_guard_request_budget_limit():
    guard = ScopeGuard(
        allowed_hosts=["127.0.0.1"],
        allowed_ports=[8001],
        allowed_paths=["/api/"],
        allowed_methods=["GET"],
    )
    guard.set_max_requests(2)
    guard.validate_request("GET", "http://127.0.0.1:8001/api/profile")
    guard.validate_request("GET", "http://127.0.0.1:8001/api/health")
    with pytest.raises(ScopeViolation, match="budget exceeded"):
        guard.validate_request("GET", "http://127.0.0.1:8001/api/health")

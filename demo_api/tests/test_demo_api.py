"""Tests for demo API verifying seeded weaknesses in vulnerable mode and corrections in secure mode."""
import pytest
import httpx
from demo_api.app.main import create_app


@pytest.mark.asyncio
async def test_vulnerable_health_and_profile():
    app = create_app("vulnerable")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Health check
        res = await client.get("/api/health")
        assert res.status_code == 200
        assert res.json()["mode"] == "vulnerable"

        # Vulnerable profile returns data without token!
        p_res = await client.get("/api/profile")
        assert p_res.status_code == 200
        data = p_res.json()
        assert "password_hash" in data
        assert "api_key" in data


@pytest.mark.asyncio
async def test_secure_health_and_profile():
    app = create_app("secure")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Health check
        res = await client.get("/api/health")
        assert res.status_code == 200
        assert res.json()["mode"] == "secure"

        # Secure profile denies access without token
        p_res = await client.get("/api/profile")
        assert p_res.status_code == 401

        # Secure profile with token returns ONLY safe fields
        headers = {"Authorization": "Bearer demo-token-alice-12345"}
        authed_res = await client.get("/api/profile", headers=headers)
        assert authed_res.status_code == 200
        data = authed_res.json()
        assert "password_hash" not in data
        assert "api_key" not in data
        assert "internal_notes" not in data
        assert data["username"] == "alice"


@pytest.mark.asyncio
async def test_vulnerable_bola_orders():
    app = create_app("vulnerable")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Alice requests Bob's order (order-1002) - vulnerable mode allows it
        headers = {"Authorization": "Bearer demo-token-alice-12345"}
        res = await client.get("/api/orders/order-1002", headers=headers)
        assert res.status_code == 200
        assert res.json()["owner"] == "bob"


@pytest.mark.asyncio
async def test_secure_bola_orders_blocked():
    app = create_app("secure")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Alice requests Bob's order (order-1002) - secure mode blocks with 403
        headers = {"Authorization": "Bearer demo-token-alice-12345"}
        res = await client.get("/api/orders/order-1002", headers=headers)
        assert res.status_code == 403


@pytest.mark.asyncio
async def test_vulnerable_admin_stats():
    app = create_app("vulnerable")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Ordinary user gets admin stats in vulnerable mode
        headers = {"Authorization": "Bearer demo-token-alice-12345"}
        res = await client.get("/api/admin/stats", headers=headers)
        assert res.status_code == 200
        assert "server_version" in res.json()


@pytest.mark.asyncio
async def test_secure_admin_stats_enforced():
    app = create_app("secure")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Ordinary user denied
        headers = {"Authorization": "Bearer demo-token-alice-12345"}
        res = await client.get("/api/admin/stats", headers=headers)
        assert res.status_code == 403

        # Admin allowed
        admin_headers = {"Authorization": "Bearer demo-token-admin-99999"}
        admin_res = await client.get("/api/admin/stats", headers=admin_headers)
        assert admin_res.status_code == 200


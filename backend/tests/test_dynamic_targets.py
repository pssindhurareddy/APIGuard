"""Tests for the features that let APIGuard scan third-party APIs such as VAmPI:
login-based auth profiles, resource discovery, generic path templating, unique
probe values and *verified* mass-assignment detection.

A tiny in-memory FastAPI app imitates VAmPI's behaviour so these tests need no
running server.
"""
import httpx
import pytest
from fastapi import FastAPI, Header, HTTPException, Request

from app.checks.base import BaseCheck
from app.checks.authorization import AuthorizationCheck
from app.checks.input_validation import InputValidationCheck
from app.services.scan_orchestrator import ScanOrchestrator
from backend.tests.test_detection_engine import MockASGIRequestEngine


def make_fake_vampi(vulnerable: bool) -> FastAPI:
    app = FastAPI()
    users = {"name1": {"password": "pass1", "admin": False}, "name2": {"password": "pass2", "admin": False}}
    books = {"bookTitle7": "name1", "bookTitle42": "name2"}

    def who(authorization):
        if not authorization or not authorization.startswith("Bearer jwt-"):
            raise HTTPException(401, "invalid token")
        return authorization.removeprefix("Bearer jwt-")

    @app.post("/users/v1/login")
    async def login(body: dict):
        u = users.get(body.get("username"))
        if u and u["password"] == body.get("password"):
            return {"auth_token": "jwt-" + body["username"]}
        return {"status": "fail"}

    @app.post("/users/v1/register")
    async def register(body: dict):
        if not all(k in body for k in ("username", "password", "email")):
            raise HTTPException(400, "missing")
        users[body["username"]] = {"password": body["password"],
                                   "admin": bool(body.get("admin")) if vulnerable else False}
        return {"status": "success"}

    @app.get("/me")
    async def me(authorization: str = Header(None)):
        name = who(authorization)
        return {"data": {"username": name, "admin": users[name]["admin"]}}

    @app.get("/books/v1")
    async def list_books():
        return {"Books": [{"book_title": t, "user": u} for t, u in books.items()]}

    @app.get("/books/v1/{title}")
    async def get_book(title: str, authorization: str = Header(None)):
        name = who(authorization)
        if title not in books or (not vulnerable and books[title] != name):
            raise HTTPException(404, "Book not found")
        return {"book_title": title, "owner": books[title]}

    return app


def vampi_config() -> dict:
    login = lambda u, p: {"path": "/users/v1/login", "body": {"username": u, "password": p}, "token_field": "auth_token"}
    return {
        "base_url": "http://127.0.0.1:8003",
        "auth_profiles": {
            "alice": {"username": "name1", "login": login("name1", "pass1")},
            "bob": {"username": "name2", "login": login("name2", "pass2")},
        },
        "resource_discovery": [{"path": "/books/v1", "list_field": "Books", "owner_field": "user",
                                "value_field": "book_title", "resource_key": "book_title"}],
        "test_resources": {"alice": {"username": "name1"}, "bob": {"username": "name2"}},
        "endpoint_policies": [
            {"path": "/books/v1/{book_title}", "method": "GET", "authentication_required": True,
             "ownership_required": True, "resource_key": "book_title"},
            {"path": "/users/v1/register", "method": "POST", "request_schema": {
                "required_fields": ["username", "password", "email"],
                "example_body": {"username": "u_{unique}", "password": "p_{unique}", "email": "e_{unique}@x.io"},
                "mass_assignment": {"inject": {"admin": True}, "verify": {
                    "login": {"path": "/users/v1/login", "credential_fields": ["username", "password"],
                              "token_field": "auth_token"},
                    "request": {"method": "GET", "path": "/me"},
                    "field": "data.admin", "privileged_value": True}}}},
        ],
    }


async def prepared(vulnerable: bool):
    cfg = vampi_config()
    engine = MockASGIRequestEngine(make_fake_vampi(vulnerable), cfg["base_url"])
    await ScanOrchestrator()._prepare_runtime_context(cfg, engine)
    return cfg, engine


def test_fill_path_and_unique_placeholders():
    assert BaseCheck._fill_path("/a/{x}/b/{y}", {"x": 1, "y": "z"}) == "/a/1/b/z"
    a = BaseCheck._materialize({"u": "user_{unique}", "n": 5})
    b = BaseCheck._materialize({"u": "user_{unique}", "n": 5})
    assert a["u"] != b["u"] and "{unique}" not in a["u"] and a["n"] == 5
    assert BaseCheck._get_field({"data": {"admin": True}}, "data.admin") is True


@pytest.mark.asyncio
async def test_login_profiles_and_resource_discovery():
    cfg, _ = await prepared(vulnerable=True)
    assert cfg["auth_profiles"]["alice"]["token"] == "jwt-name1"
    assert cfg["test_resources"]["alice"]["book_title"] == "bookTitle7"
    assert cfg["test_resources"]["bob"]["book_title"] == "bookTitle42"


@pytest.mark.asyncio
async def test_failed_login_raises_clear_error():
    cfg = vampi_config()
    cfg["auth_profiles"]["alice"]["login"]["body"]["password"] = "wrong"
    engine = MockASGIRequestEngine(make_fake_vampi(True), cfg["base_url"])
    with pytest.raises(RuntimeError, match="Login for auth profile 'alice' failed"):
        await ScanOrchestrator()._prepare_runtime_context(cfg, engine)


@pytest.mark.asyncio
@pytest.mark.parametrize("vulnerable,expected", [(True, "CONFIRMED"), (False, "PASS")])
async def test_bola_on_discovered_resources(vulnerable, expected):
    cfg, engine = await prepared(vulnerable)
    results = await AuthorizationCheck(engine, cfg).run()
    bola = [r for r in results if r.test_id in ("AUTHZ-001", "AUTHZ-003")]
    assert bola and all(r.status == expected for r in bola)


@pytest.mark.asyncio
@pytest.mark.parametrize("vulnerable,expected", [(True, "CONFIRMED"), (False, "PASS")])
async def test_mass_assignment_is_verified_not_assumed(vulnerable, expected):
    """Secure mode ACCEPTS the extra field but ignores it: must be PASS, not a false positive."""
    cfg, engine = await prepared(vulnerable)
    results = await InputValidationCheck(engine, cfg).run()
    ma = [r for r in results if r.test_id == "INPUT-005"]
    assert len(ma) == 1 and ma[0].status == expected
    assert ma[0].evidence["observed_value"] is vulnerable

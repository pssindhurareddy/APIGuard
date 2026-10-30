"""Fixture reset endpoint for repeatable demonstrations."""
from fastapi import APIRouter
from ..fixtures import reset_fixtures

router = APIRouter()


@router.post("/api/fixtures/reset")
async def reset():
    """Reset all demo fixtures to default state."""
    return reset_fixtures()


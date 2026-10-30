"""Order endpoints - demonstrate authorization and input validation vulnerabilities."""
from fastapi import APIRouter, Request, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from typing import Optional
from ..security import (
    get_current_user_required,
    get_current_user_optional,
    get_mode,
    extract_token,
    DEMO_TOKENS,
)
from ..fixtures import ORDERS, USERS

router = APIRouter()


class CreateOrderRequest(BaseModel):
    """Order creation request schema.

    extra="forbid" rejects unknown attributes (e.g. is_admin) with HTTP 422,
    which closes the mass-assignment weakness probed by INPUT-005.
    """
    model_config = ConfigDict(extra="forbid")

    product: str = Field(..., min_length=1, max_length=200)
    quantity: int = Field(..., gt=0, le=1000)
    price: float = Field(..., gt=0, le=100000)


class CreateOrderRequestVulnerable(BaseModel):
    """Vulnerable order creation - no validation constraints."""
    product: Optional[str] = None
    quantity: Optional[int] = None  # No range validation
    price: Optional[float] = None


@router.get("/api/orders/{order_id}")
async def get_order(
    order_id: str,
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """Get order by ID.
    
    VULNERABLE MODE:
    - BOLA: Any authenticated user can access any order (no ownership check)
    
    SECURE MODE:
    - Only the order owner or admin can access the order
    """
    mode = get_mode(request)

    # SECURE: authenticate BEFORE looking up the object, so unauthenticated
    # callers cannot probe which order IDs exist (404 vs 401 oracle).
    if mode != "vulnerable":
        get_current_user_required(authorization)

    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    
    if mode == "vulnerable":
        # VULNERABILITY: No ownership check - Alice can see Bob's orders
        # Still require SOME auth to make the test meaningful
        token = extract_token(authorization)
        if token and token not in DEMO_TOKENS:
            raise HTTPException(status_code=401, detail="Invalid token")
        return order
    else:
        # SECURE: Require authentication
        username = get_current_user_required(authorization)
        # SECURE: Ownership check
        user_data = USERS.get(username, {})
        if order["owner"] != username and user_data.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Access denied: you do not own this order")
        return order


@router.post("/api/orders")
async def create_order(
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """Create a new order.
    
    VULNERABLE MODE:
    - Accepts invalid/missing fields, negative quantities, etc.
    
    SECURE MODE:
    - Validates all fields with proper constraints
    """
    mode = get_mode(request)

    # SECURE: authenticate before parsing/validating the body.
    if mode != "vulnerable":
        get_current_user_required(authorization)

    # Parse raw body
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid JSON in request body")
    
    if mode == "vulnerable":
        # VULNERABILITY: No proper input validation
        # Accept whatever comes in
        username = get_current_user_optional(authorization) or "anonymous"
        
        # Don't validate - accept negative quantities, missing fields, etc.
        order_id = f"order-{2000 + len(ORDERS)}"
        new_order = {
            "id": order_id,
            "owner": username,
            "product": body.get("product", ""),
            "quantity": body.get("quantity", 0),
            "price": body.get("price", 0),
            "status": "pending",
            "created_at": "2024-08-01T12:00:00Z",
        }
        return {"message": "Order created", "order": new_order}
    else:
        # SECURE: Require authentication
        username = get_current_user_required(authorization)
        
        # SECURE: Validate with strict schema
        try:
            validated = CreateOrderRequest(**body)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Validation error: {str(e)}")
        
        order_id = f"order-{2000 + len(ORDERS)}"
        new_order = {
            "id": order_id,
            "owner": username,
            "product": validated.product,
            "quantity": validated.quantity,
            "price": validated.price,
            "status": "pending",
            "created_at": "2024-08-01T12:00:00Z",
        }
        return {"message": "Order created", "order": new_order}


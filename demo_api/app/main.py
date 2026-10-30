"""APIGuard Demo API - Intentionally Vulnerable and Secure REST API.

This application runs in two modes:
- vulnerable (port 8001): Contains deliberate security weaknesses
- secure (port 8002): Same API with proper security controls

ALL DATA IS SYNTHETIC. ALL TOKENS ARE FAKE.
This is for educational/testing purposes only.
"""

import argparse
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes import health, profile, orders, admin, fixtures_route


def create_app(mode: str = "vulnerable") -> FastAPI:
    """Create the demo API application.
    
    Args:
        mode: 'vulnerable' or 'secure'
    """
    title = f"APIGuard Demo API ({mode.upper()} mode)"
    description = (
        "Intentionally vulnerable/secure REST API for security testing demonstration. "
        "ALL DATA IS SYNTHETIC. ALL TOKENS ARE FAKE."
    )
    
    app = FastAPI(
        title=title,
        description=description,
        version="1.0.0",
    )
    
    # Store mode in app state
    app.state.mode = mode
    
    # CORS - allow the scanner and frontend
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8000", "http://127.0.0.1:8000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Register routes
    app.include_router(health.router, tags=["Health"])
    app.include_router(profile.router, tags=["Profile"])
    app.include_router(orders.router, tags=["Orders"])
    app.include_router(admin.router, tags=["Admin"])
    app.include_router(fixtures_route.router, tags=["Fixtures"])
    
    return app


def main():
    parser = argparse.ArgumentParser(description="APIGuard Demo API")
    parser.add_argument(
        "--mode",
        choices=["vulnerable", "secure"],
        default="vulnerable",
        help="API security mode (default: vulnerable)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port to listen on (default: 8001 for vulnerable, 8002 for secure)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1)",
    )
    
    args = parser.parse_args()
    
    port = args.port
    if port is None:
        port = 8001 if args.mode == "vulnerable" else 8002
    
    app = create_app(mode=args.mode)
    
    print(f"\n{'='*60}")
    print(f"  APIGuard Demo API - {args.mode.upper()} MODE")
    print(f"  Listening on http://{args.host}:{port}")
    print(f"  ALL DATA IS SYNTHETIC - FOR TESTING ONLY")
    print(f"{'='*60}\n")
    
    uvicorn.run(app, host=args.host, port=port)


if __name__ == "__main__":
    main()


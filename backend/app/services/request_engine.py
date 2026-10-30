"""HTTP request engine integrated with runtime scope enforcement."""
import httpx
import time
from typing import Any, Optional
from dataclasses import dataclass, field

from .scope_guard import ScopeGuard, ScopeViolation
from ..config import DEFAULT_TIMEOUT, DEFAULT_MAX_RESPONSE_SIZE


@dataclass
class RequestResult:
    """Standardized representation of HTTP communication outcome."""
    success: bool
    status_code: Optional[int] = None
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None
    body_text: Optional[str] = None
    content_type: Optional[str] = None
    duration_ms: float = 0.0
    error: Optional[str] = None
    url: str = ""
    method: str = ""


class RequestEngine:
    """Controlled HTTP client executing tests through ScopeGuard boundaries."""

    def __init__(
        self,
        scope_guard: ScopeGuard,
        timeout: float = DEFAULT_TIMEOUT,
        max_response_size: int = DEFAULT_MAX_RESPONSE_SIZE,
    ):
        self.scope_guard = scope_guard
        self.timeout = timeout
        self.max_response_size = max_response_size

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict[str, str]] = None,
        json_body: Any = None,
        body: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> RequestResult:
        """Execute HTTP request with strict pre-flight scope validation."""
        start = time.monotonic()

        # Enforce scope validation BEFORE network transmission
        try:
            self.scope_guard.validate_request(method, url)
        except ScopeViolation as e:
            return RequestResult(
                success=False,
                error=f"Scope violation: {str(e)}",
                url=url,
                method=method,
                duration_ms=(time.monotonic() - start) * 1000,
            )

        req_headers = dict(headers or {})
        if content_type:
            req_headers["Content-Type"] = content_type

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
                max_redirects=0,
            ) as client:
                kwargs: dict[str, Any] = {
                    "method": method,
                    "url": url,
                    "headers": req_headers,
                }
                if json_body is not None:
                    kwargs["json"] = json_body
                elif body is not None:
                    kwargs["content"] = body

                response = await client.request(**kwargs)

                # Catch and validate redirects
                if response.is_redirect:
                    location = response.headers.get("location", "")
                    try:
                        self.scope_guard.validate_redirect(url, location)
                    except ScopeViolation as sv:
                        return RequestResult(
                            success=True,
                            status_code=response.status_code,
                            headers=dict(response.headers),
                            error=f"Out-of-scope redirect intercepted: {sv}",
                            url=url,
                            method=method,
                            duration_ms=(time.monotonic() - start) * 1000,
                        )

                # Cap response payload size
                body_bytes = response.content
                if len(body_bytes) > self.max_response_size:
                    body_text = body_bytes[:self.max_response_size].decode("utf-8", errors="replace")
                    body_text += f"\n[TRUNCATED: response exceeded {self.max_response_size} bytes limit]"
                else:
                    body_text = body_bytes.decode("utf-8", errors="replace")

                # Parse JSON body safely if Content-Type indicates JSON
                parsed_json = None
                ct = response.headers.get("content-type", "")
                if "json" in ct:
                    try:
                        parsed_json = response.json()
                    except Exception:
                        parsed_json = None

                return RequestResult(
                    success=True,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=parsed_json,
                    body_text=body_text,
                    content_type=ct,
                    duration_ms=(time.monotonic() - start) * 1000,
                    url=url,
                    method=method,
                )

        except httpx.TimeoutException:
            return RequestResult(
                success=False,
                error=f"Request timed out after {self.timeout}s",
                url=url,
                method=method,
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except httpx.ConnectError as ce:
            return RequestResult(
                success=False,
                error=f"Connection error to {url}: {ce}",
                url=url,
                method=method,
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as e:
            return RequestResult(
                success=False,
                error=f"Request execution failure: {type(e).__name__}: {str(e)}",
                url=url,
                method=method,
                duration_ms=(time.monotonic() - start) * 1000,
            )


"""OpenAPI Specification parsing API endpoint."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Any

from ..services.openapi_parser import OpenAPIParser, OpenAPIParseError

router = APIRouter()


class ParseOpenAPIRequest(BaseModel):
    content: str


@router.post("/api/openapi/parse")
async def parse_openapi_spec(req: ParseOpenAPIRequest):
    """Parse untrusted OpenAPI/Swagger content into APIGuard endpoint policies."""
    if not req.content or not req.content.strip():
        raise HTTPException(400, "Specification content cannot be empty.")

    try:
        spec_dict = OpenAPIParser.parse_spec(req.content)
        endpoints = OpenAPIParser.extract_endpoints(spec_dict)
        return {
            "title": spec_dict.get("info", {}).get("title", "Imported API Specification"),
            "version": spec_dict.get("info", {}).get("version", "1.0.0"),
            "endpoint_count": len(endpoints),
            "endpoints": endpoints,
        }
    except OpenAPIParseError as e:
        raise HTTPException(400, f"OpenAPI parse error: {str(e)}")
    except Exception as e:
        raise HTTPException(400, f"Unable to parse specification: {str(e)}")


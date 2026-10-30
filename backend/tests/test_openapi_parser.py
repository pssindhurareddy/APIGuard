"""Automated tests for OpenAPI specification parsing."""
import sys
from pathlib import Path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import pytest
from app.services.openapi_parser import OpenAPIParser, OpenAPIParseError


SAMPLE_OPENAPI_JSON = """
{
  "openapi": "3.0.0",
  "info": {
    "title": "E-Commerce Test API",
    "version": "1.0.0"
  },
  "paths": {
    "/api/profile": {
      "get": {
        "summary": "Get User Profile",
        "security": [{"BearerAuth": []}],
        "responses": {
          "200": {
            "description": "OK",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "id": {"type": "string"},
                    "username": {"type": "string"},
                    "email": {"type": "string"}
                  }
                }
              }
            }
          }
        }
      }
    },
    "/api/orders": {
      "post": {
        "summary": "Create Order",
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["product", "quantity"],
                "properties": {
                  "product": {"type": "string", "example": "Test Item"},
                  "quantity": {"type": "integer", "example": 2}
                }
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Created"
          }
        }
      }
    }
  }
}
"""

SAMPLE_OPENAPI_YAML = """
openapi: "3.0.0"
info:
  title: "YAML API Spec"
  version: "1.0.0"
paths:
  /api/health:
    get:
      summary: "Health Check"
      responses:
        "200":
          description: "Healthy"
"""


def test_parse_valid_json_spec():
    parsed = OpenAPIParser.parse_spec(SAMPLE_OPENAPI_JSON)
    endpoints = OpenAPIParser.extract_endpoints(parsed)
    assert len(endpoints) == 2

    profile_ep = next(e for e in endpoints if e["path"] == "/api/profile")
    assert profile_ep["method"] == "GET"
    assert profile_ep["authentication_required"] is True
    assert set(profile_ep["allowed_response_fields"]) == {"id", "username", "email"}

    orders_ep = next(e for e in endpoints if e["path"] == "/api/orders")
    assert orders_ep["method"] == "POST"
    assert orders_ep["request_schema"]["required_fields"] == ["product", "quantity"]
    assert orders_ep["request_schema"]["field_types"]["quantity"] == "integer"


def test_parse_valid_yaml_spec():
    parsed = OpenAPIParser.parse_spec(SAMPLE_OPENAPI_YAML)
    endpoints = OpenAPIParser.extract_endpoints(parsed)
    assert len(endpoints) == 1
    assert endpoints[0]["path"] == "/api/health"
    assert endpoints[0]["method"] == "GET"


def test_parse_malformed_spec_raises_error():
    with pytest.raises(OpenAPIParseError):
        OpenAPIParser.parse_spec("{ broken invalid json : [")

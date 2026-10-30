"""OpenAPI Specification parser and endpoint policy extractor.

Treats all imported specifications as untrusted input.
Extracts paths, methods, schemas, and parameters safely.
"""
import json
import yaml
from typing import Any, Optional


class OpenAPIParseError(Exception):
    """Raised when an OpenAPI document is invalid or unsupported."""
    pass


class OpenAPIParser:
    """Parses OpenAPI 3.0+ and Swagger 2.0 specs into APIGuard target policies."""

    @staticmethod
    def parse_spec(content: str) -> dict[str, Any]:
        """Parse raw JSON or YAML text into a dictionary."""
        # Try JSON first
        try:
            return json.loads(content)
        except Exception:
            pass

        # Try YAML safe load
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict):
                return data
            raise OpenAPIParseError("Parsed YAML content did not produce a root dictionary.")
        except Exception as e:
            raise OpenAPIParseError(f"Failed to parse specification as JSON or YAML: {e}")

    @classmethod
    def extract_endpoints(cls, spec_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract paths, operations, and schemas from parsed OpenAPI definition."""
        paths_obj = spec_data.get("paths", {})
        if not isinstance(paths_obj, dict):
            raise OpenAPIParseError("Specification is missing a valid 'paths' dictionary.")

        endpoints: list[dict[str, Any]] = []

        for path, path_item in paths_obj.items():
            if not isinstance(path_item, dict):
                continue

            for method in ("get", "post", "put", "patch", "delete"):
                if method not in path_item:
                    continue

                operation = path_item[method]
                if not isinstance(operation, dict):
                    continue

                # Check security requirement
                has_security = bool(operation.get("security") or spec_data.get("security"))

                # Extract request schema if POST/PUT/PATCH
                request_schema = None
                if method in ("post", "put", "patch"):
                    request_schema = cls._extract_request_schema(operation)

                # Extract response fields if defined
                allowed_fields = cls._extract_response_fields(operation)

                endpoint_def = {
                    "path": path,
                    "method": method.upper(),
                    "operation_id": operation.get("operationId", f"{method}_{path.replace('/', '_')}"),
                    "summary": operation.get("summary", ""),
                    "authentication_required": has_security,
                    "request_schema": request_schema,
                    "allowed_response_fields": allowed_fields,
                    "check_data_exposure": True,
                }
                endpoints.append(endpoint_def)

        return endpoints

    @staticmethod
    def _extract_request_schema(operation: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Extract JSON request body schema if present."""
        request_body = operation.get("requestBody", {})
        content = request_body.get("content", {})
        json_media = content.get("application/json", {})
        schema = json_media.get("schema", {})

        if not schema:
            return None

        required = schema.get("required", [])
        properties = schema.get("properties", {})

        field_types: dict[str, str] = {}
        example_body: dict[str, Any] = {}

        for prop_name, prop_spec in properties.items():
            p_type = prop_spec.get("type", "string")
            field_types[prop_name] = p_type
            if p_type == "integer":
                example_body[prop_name] = prop_spec.get("example", 1)
            elif p_type == "number":
                example_body[prop_name] = prop_spec.get("example", 1.0)
            elif p_type == "boolean":
                example_body[prop_name] = prop_spec.get("example", True)
            else:
                example_body[prop_name] = prop_spec.get("example", "test_value")

        return {
            "required_fields": required,
            "field_types": field_types,
            "example_body": example_body,
            "strict": False,
        }

    @staticmethod
    def _extract_response_fields(operation: dict[str, Any]) -> list[str]:
        """Extract allowed response property names from 200/201 response schema."""
        responses = operation.get("responses", {})
        ok_response = responses.get("200") or responses.get("201") or {}
        content = ok_response.get("content", {})
        json_media = content.get("application/json", {})
        schema = json_media.get("schema", {})
        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            return list(properties.keys())
        return []


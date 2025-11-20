# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A validator for Firecracker API Swagger schema"""

from pathlib import Path

import yaml
from jsonschema import Draft4Validator, ValidationError


def _filter_none_recursive(data):
    if isinstance(data, dict):
        return {k: _filter_none_recursive(v) for k, v in data.items() if v is not None}
    if isinstance(data, list):
        return [_filter_none_recursive(item) for item in data if item is not None]
    return data


class SwaggerValidator:
    """Validator for API requests against the Swagger/OpenAPI specification"""

    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize the validator with the Swagger specification."""
        if self._initialized:
            return
        self._initialized = True

        swagger_path = (
            Path(__file__).parent.parent.parent
            / "src"
            / "firecracker"
            / "swagger"
            / "firecracker.yaml"
        )

        with open(swagger_path, "r", encoding="utf-8") as f:
            self.swagger_spec = yaml.safe_load(f)

        # Cache validators for each endpoint
        self._validators = {}
        self._build_validators()

    def _build_validators(self):
        """Build JSON schema validators for each endpoint."""
        paths = self.swagger_spec.get("paths", {})
        definitions = self.swagger_spec.get("definitions", {})

        for path, methods in paths.items():
            for method, spec in methods.items():
                if method.upper() not in ["GET", "PUT", "PATCH", "POST", "DELETE"]:
                    continue

                # Build request body validators
                parameters = spec.get("parameters", [])
                for param in parameters:
                    if param.get("in") == "body" and "schema" in param:
                        schema = self._resolve_schema(param["schema"], definitions)
                        if method.upper() == "PATCH":
                            # do not validate required fields on PATCH requests
                            schema["required"] = []
                        key = ("request", method.upper(), path)
                        self._validators[key] = Draft4Validator(schema)

                # Build response validators for 200/204 responses
                responses = spec.get("responses", {})
                for status_code, response_spec in responses.items():
                    if str(status_code) in ["200", "204"] and "schema" in response_spec:
                        schema = self._resolve_schema(
                            response_spec["schema"], definitions
                        )
                        key = ("response", method.upper(), path, str(status_code))
                        self._validators[key] = Draft4Validator(schema)

    def _resolve_schema(self, schema, definitions):
        """Resolve $ref references in schema."""
        if "$ref" in schema:
            ref_path = schema["$ref"]
            if ref_path.startswith("#/definitions/"):
                def_name = ref_path.split("/")[-1]
                if def_name in definitions:
                    return self._resolve_schema(definitions[def_name], definitions)

        # Recursively resolve nested schemas
        resolved = schema.copy()
        if "properties" in resolved:
            resolved["properties"] = {
                k: self._resolve_schema(v, definitions)
                for k, v in resolved["properties"].items()
            }
        if "items" in resolved and isinstance(resolved["items"], dict):
            resolved["items"] = self._resolve_schema(resolved["items"], definitions)

        if not "additionalProperties" in resolved:
            resolved["additionalProperties"] = False

        return resolved

    def validate_request(self, method, path, body):
        """
        Validate a request body against the Swagger specification.

        Args:
            method: HTTP method (GET, PUT, PATCH, etc.)
            path: API path (e.g., "/drives/{drive_id}")
            body: Request body as a dictionary

        Raises:
            ValidationError: If the request body doesn't match the schema
        """
        # Normalize path - replace specific IDs with parameter placeholders
        normalized_path = self._normalize_path(path)
        key = ("request", method.upper(), normalized_path)

        if key in self._validators:
            validator = self._validators[key]
            # Remove None values from body before validation
            cleaned_body = _filter_none_recursive(body)
            validator.validate(cleaned_body)
        else:
            raise ValidationError(f"{key} is not in the schema")

    def validate_response(self, method, path, status_code, body):
        """
        Validate a response body against the Swagger specification.

        Args:
            method: HTTP method (GET, PUT, PATCH, etc.)
            path: API path (e.g., "/drives/{drive_id}")
            status_code: HTTP status code (e.g., 200, 204)
            body: Response body as a dictionary

        Raises:
            ValidationError: If the response body doesn't match the schema
        """
        # Normalize path - replace specific IDs with parameter placeholders
        normalized_path = self._normalize_path(path)
        key = ("response", method.upper(), normalized_path, str(status_code))

        if key in self._validators:
            validator = self._validators[key]
            # Remove None values from body before validation
            cleaned_body = _filter_none_recursive(body)
            validator.validate(cleaned_body)
        else:
            raise ValidationError(f"{key} is not in the schema")

    def _normalize_path(self, path):
        """
        Normalize a path by replacing specific IDs with parameter placeholders.

        E.g., "/drives/rootfs" -> "/drives/{drive_id}"
        """
        # Match against known patterns in the swagger spec
        paths = self.swagger_spec.get("paths", {})

        # Direct match
        if path in paths:
            return path

        # Try to match parameterized paths
        parts = path.split("/")
        for swagger_path in paths.keys():
            swagger_parts = swagger_path.split("/")
            if len(parts) == len(swagger_parts):
                match = True
                for _, (part, swagger_part) in enumerate(zip(parts, swagger_parts)):
                    # Check if it's a parameter placeholder or exact match
                    if swagger_part.startswith("{") and swagger_part.endswith("}"):
                        continue  # This is a parameter, any value matches
                    if part != swagger_part:
                        match = False
                        break

                if match:
                    return swagger_path

        return path

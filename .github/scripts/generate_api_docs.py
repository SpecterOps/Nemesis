#!/usr/bin/env python3
"""
Generate simplified API documentation from FastAPI OpenAPI spec.
This script extracts the OpenAPI specification from the web-api service
and generates clean markdown documentation in docs/api/
"""

import json
import os
import sys
from pathlib import Path
from typing import Any

# Add the web_api module to the path
sys.path.insert(0, str(Path(__file__).parent.parent / "projects" / "web_api"))


def extract_openapi_spec() -> dict[str, Any]:
    """Extract OpenAPI specification from the FastAPI app."""
    try:
        # Set minimal environment variables to avoid database connection issues
        os.environ.setdefault("POSTGRES_CONNECTION_URI", "postgresql://test:test@localhost/test")
        os.environ.setdefault("MINIO_ROOT_USER", "test")
        os.environ.setdefault("MINIO_ROOT_PASSWORD", "test")
        os.environ.setdefault("MINIO_SERVER", "localhost:9000")
        os.environ.setdefault("BUCKET_NAME", "test")

        # Mock Dapr dependencies to avoid connection issues
        import sys
        from unittest.mock import MagicMock
        from types import ModuleType

        # Create a mock module factory that returns modules, not MagicMocks
        def create_mock_module(name):
            """Create a proper mock module that can act as a package."""
            module = ModuleType(name)
            module.__path__ = []  # Makes it a package
            module.__package__ = name
            # Add a __getattr__ that returns more mock modules for any submodule access
            def mock_getattr(attr_name):
                if attr_name.startswith('_'):
                    raise AttributeError(f"module '{name}' has no attribute '{attr_name}'")
                submodule_name = f"{name}.{attr_name}"
                if submodule_name not in sys.modules:
                    sys.modules[submodule_name] = create_mock_module(submodule_name)
                return sys.modules[submodule_name]
            module.__getattr__ = mock_getattr
            return module

        # Create base dapr module
        dapr_module = create_mock_module("dapr")
        sys.modules["dapr"] = dapr_module

        # Pre-create all nested submodules that we'll need
        # This needs to be comprehensive to handle all possible imports
        nested_modules = [
            "dapr.aio",
            "dapr.aio.clients",
            "dapr.aio.clients.grpc",
            "dapr.aio.clients.grpc.client",
            "dapr.aio.clients.grpc._response",
            "dapr.aio.clients.grpc._request",
            "dapr.aio.clients.grpc.subscription",
            "dapr.clients",
            "dapr.clients.grpc",
            "dapr.clients.grpc.client",
            "dapr.clients.grpc._response",
            "dapr.clients.grpc._request",
            "dapr.clients.grpc.subscription",
            "dapr.ext",
            "dapr.ext.fastapi",
        ]

        for module_name in nested_modules:
            sys.modules[module_name] = create_mock_module(module_name)

        # Create mock DaprClient that returns proper secret values
        # Need to handle multiple secret keys that might be requested
        def mock_get_secret(store_name, key):
            mock_response = MagicMock()
            secrets_map = {
                "POSTGRES_USER": "test",
                "POSTGRES_PASSWORD": "test",
                "POSTGRES_HOST": "localhost",
                "POSTGRES_PORT": "5432",
                "POSTGRES_DB": "test",
                "POSTGRES_PARAMETERS": "sslmode=disable",
                "MINIO_ROOT_USER": "test",
                "MINIO_ROOT_PASSWORD": "test",
                "MINIO_SERVER": "localhost:9000",
                "BUCKET_NAME": "test",
            }
            mock_response.secret = {key: secrets_map.get(key, "test")}
            return mock_response

        mock_dapr_client = MagicMock()
        mock_dapr_client.return_value.__enter__.return_value.get_secret.side_effect = mock_get_secret
        mock_dapr_client.return_value.__exit__.return_value = None

        # Add specific mocked classes
        sys.modules["dapr.aio.clients"].DaprClient = MagicMock()
        sys.modules["dapr.clients"].DaprClient = mock_dapr_client
        sys.modules["dapr.ext.fastapi"].DaprApp = MagicMock()

        from web_api.main import app

        return app.openapi()
    except ImportError as e:
        print(f"Error importing web_api.main: {e}")
        print("Make sure to run: cd projects/web_api && poetry install")
        sys.exit(1)
    except Exception as e:
        import traceback
        print(f"Error generating OpenAPI spec: {e}")
        print("\nFull traceback:")
        traceback.print_exc()
        sys.exit(1)


def format_parameter(param: dict[str, Any]) -> str:
    """Format a parameter for documentation."""
    param_type = param.get("schema", {}).get("type", "unknown")
    required = "**required**" if param.get("required", False) else "optional"
    description = param.get("description", "")

    return f"- `{param['name']}` ({param_type}, {required}): {description}"


def format_request_body(request_body: dict[str, Any]) -> str:
    """Format request body information."""
    if not request_body:
        return ""

    content = request_body.get("content", {})
    if "application/json" in content:
        schema = content["application/json"].get("schema", {})
        if "$ref" in schema:
            # Extract model name from reference
            model_name = schema["$ref"].split("/")[-1]
            return f"**Request Body:** `{model_name}` (JSON)"
        elif schema.get("type") == "object":
            return "**Request Body:** JSON object"

    return "**Request Body:** See OpenAPI spec for details"


def generate_endpoint_docs(paths: dict[str, Any]) -> str:
    """Generate documentation for all endpoints."""
    docs = []

    # Group endpoints by tags
    tagged_endpoints = {}
    untagged_endpoints = []

    for path, methods in paths.items():
        for method, details in methods.items():
            if method.upper() not in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                continue

            tags = details.get("tags", [])
            endpoint_info = {"path": path, "method": method.upper(), "details": details}

            if tags:
                tag = tags[0]  # Use first tag
                if tag not in tagged_endpoints:
                    tagged_endpoints[tag] = []
                tagged_endpoints[tag].append(endpoint_info)
            else:
                untagged_endpoints.append(endpoint_info)

    # Generate docs for each tag group
    for tag, endpoints in sorted(tagged_endpoints.items()):
        docs.append(f"## {tag.title()}")
        docs.append("")

        for endpoint in sorted(endpoints, key=lambda x: (x["path"], x["method"])):
            docs.extend(format_endpoint(endpoint))

        docs.append("")

    # Add untagged endpoints if any
    if untagged_endpoints:
        docs.append("## Other Endpoints")
        docs.append("")

        for endpoint in sorted(untagged_endpoints, key=lambda x: (x["path"], x["method"])):
            docs.extend(format_endpoint(endpoint))

        docs.append("")

    return "\n".join(docs)


def format_endpoint(endpoint: dict[str, Any]) -> list[str]:
    """Format a single endpoint for documentation."""
    path = endpoint["path"]
    method = endpoint["method"]
    details = endpoint["details"]

    docs = []

    # Endpoint header
    summary = details.get("summary", "")
    docs.append(f"### `{method} {path}`")
    docs.append("")

    if summary:
        docs.append(summary)
        docs.append("")

    # Description
    description = details.get("description", "")
    if description and description != summary:
        docs.append(description)
        docs.append("")

    # Parameters
    parameters = details.get("parameters", [])
    if parameters:
        docs.append("**Parameters:**")
        docs.append("")
        for param in parameters:
            docs.append(format_parameter(param))
        docs.append("")

    # Request body
    request_body = details.get("requestBody", {})
    if request_body:
        body_docs = format_request_body(request_body)
        if body_docs:
            docs.append(body_docs)
            docs.append("")

    # Response summary (simplified)
    responses = details.get("responses", {})
    if responses:
        success_responses = [code for code in responses.keys() if code.startswith("2")]
        if success_responses:
            docs.append(f"**Returns:** {', '.join(success_responses)} on success")
            docs.append("")

    docs.append("---")
    docs.append("")

    return docs


def generate_markdown_docs(spec: dict[str, Any]) -> str:
    """Generate complete markdown documentation."""
    info = spec.get("info", {})
    title = info.get("title", "API Documentation")
    version = info.get("version", "Unknown")
    description = info.get("description", "")

    docs = [
        f"# {title}",
        "",
        f"**Version:** {version}",
        "",
    ]

    if description:
        docs.extend([description, ""])

    docs.extend(["This documentation is automatically generated from the OpenAPI specification.", "", "---", ""])

    # Add endpoints
    paths = spec.get("paths", {})
    if paths:
        docs.append(generate_endpoint_docs(paths))

    return "\n".join(docs)


def main():
    """Main function to generate API documentation."""
    print("Extracting OpenAPI specification...")
    spec = extract_openapi_spec()

    print("Generating markdown documentation...")
    markdown_content = generate_markdown_docs(spec)

    # Ensure docs directory exists (repo root)
    docs_dir = Path(__file__).parent.parent.parent / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)

    # Write main API documentation
    api_docs_file = docs_dir / "api.md"
    with open(api_docs_file, "w", encoding="utf-8") as f:
        f.write(markdown_content)

    print(f"API documentation generated: {api_docs_file}")

    # Also save the raw OpenAPI spec for reference
    openapi_file = docs_dir / "openapi.json"
    with open(openapi_file, "w", encoding="utf-8") as f:
        json.dump(spec, f, indent=2)

    print(f"OpenAPI specification saved: {openapi_file}")
    print("Documentation generation complete!")


if __name__ == "__main__":
    main()

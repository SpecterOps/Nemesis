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

        # Mock dapr modules before importing web_api.main
        mock_dapr_clients = MagicMock()
        mock_dapr_ext_fastapi = MagicMock()
        sys.modules["dapr.clients"] = mock_dapr_clients
        sys.modules["dapr.ext.fastapi"] = mock_dapr_ext_fastapi

        # Mock the specific classes that are imported
        mock_dapr_clients.DaprClient = MagicMock()
        mock_dapr_ext_fastapi.DaprApp = MagicMock()

        from web_api.main import app

        return app.openapi()
    except ImportError as e:
        print(f"Error importing web_api.main: {e}")
        print("Make sure to run: cd projects/web_api && poetry install")
        sys.exit(1)
    except Exception as e:
        print(f"Error generating OpenAPI spec: {e}")
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

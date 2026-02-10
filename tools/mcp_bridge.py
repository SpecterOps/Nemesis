#!/usr/bin/env python3
"""
MCP stdio-to-HTTP bridge for Claude Desktop.

This script acts as a bridge between Claude Desktop (which expects stdio transport)
and the Nemesis MCP server (which runs over HTTP at https://localhost:7443/mcp).

It reads MCP protocol messages from stdin, forwards them to the HTTP endpoint,
and writes responses back to stdout.

Example claude_desktop_config.json:
```json
{
  "mcpServers": {
    "nemesis": {
      "command": "python3",
      "args": ["/Users/User/path/to/Nemesis/tools/mcp_bridge.py"]
    }
  }
}
```
"""

import base64
import json
import ssl
import sys
import urllib.error
import urllib.request
from typing import Any

# Configuration
MCP_URL = "https://localhost:7443/mcp"
USERNAME = "n"
PASSWORD = "n"

# Create basic auth header
auth_string = f"{USERNAME}:{PASSWORD}"
auth_bytes = auth_string.encode("ascii")
auth_b64 = base64.b64encode(auth_bytes).decode("ascii")

# Create SSL context that doesn't verify certificates (for self-signed certs)
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE


def log_error(message: str) -> None:
    """Log errors to stderr."""
    print(f"[mcp_bridge] {message}", file=sys.stderr, flush=True)


def forward_message(message: dict[str, Any]) -> dict[str, Any] | None:
    """Forward a message to the MCP HTTP endpoint and return the response."""
    try:
        # Prepare the request
        data = json.dumps(message).encode("utf-8")
        req = urllib.request.Request(
            MCP_URL,
            data=data,
            headers={
                "Authorization": f"Basic {auth_b64}",
                "Content-Type": "application/json",
            },
        )

        # Make the request
        with urllib.request.urlopen(req, context=ssl_context, timeout=30) as response:
            response_data = response.read().decode("utf-8")
            return json.loads(response_data)

    except urllib.error.HTTPError as e:
        log_error(f"HTTP error {e.code}: {e.reason}")
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "error": {"code": -32603, "message": f"HTTP {e.code}: {e.reason}"},
        }
    except urllib.error.URLError as e:
        log_error(f"URL error: {e.reason}")
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "error": {"code": -32603, "message": f"Connection error: {str(e.reason)}"},
        }
    except json.JSONDecodeError as e:
        log_error(f"Failed to decode response: {e}")
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "error": {"code": -32603, "message": f"Invalid JSON response: {str(e)}"},
        }
    except Exception as e:
        log_error(f"Unexpected error: {e}")
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "error": {"code": -32603, "message": f"Bridge error: {str(e)}"},
        }


def main():
    """Main bridge loop: read from stdin, forward to HTTP, write to stdout."""
    log_error("MCP bridge started")
    log_error(f"Connecting to: {MCP_URL}")

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                # Parse the incoming MCP message
                message = json.loads(line)
                log_error(f"Received message: {message.get('method', 'unknown')}")

                # Check if this is a notification (no id field)
                is_notification = "id" not in message

                # Forward to HTTP endpoint
                response = forward_message(message)

                # Only send response for requests (not notifications)
                if response and not is_notification:
                    # Write response to stdout
                    print(json.dumps(response), flush=True)
                    log_error(f"Sent response for: {message.get('method', 'unknown')}")
                elif is_notification:
                    log_error(f"Notification handled (no response): {message.get('method', 'unknown')}")

            except json.JSONDecodeError as e:
                log_error(f"Failed to parse input JSON: {e}")
                error_response = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {str(e)}"},
                }
                print(json.dumps(error_response), flush=True)

    except KeyboardInterrupt:
        log_error("Bridge stopped by user")
    except Exception as e:
        log_error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

"""Reject browser requests that another site triggered (CSRF / cross-site navigation).

Nemesis sits behind Traefik basic auth, and browsers attach those cached credentials to requests a
different site makes them send (a form POST to /api/files, a link to /api/reports/system/pdf).
Browsers label every request with where it came from (`Sec-Fetch-Site`, and `Origin` on most
non-GET requests); requests from the Nemesis UI itself are `same-origin`, typed URLs and bookmarks
are `none`. API clients (the CLI, C2 connectors, Jupyter, Dapr and health checks) send neither
header, so they are unaffected.
"""

from urllib.parse import urlsplit

from starlette.types import ASGIApp, Receive, Scope, Send

# Sec-Fetch-Site values that mean "a page on another site (or sibling subdomain) caused this"
_FOREIGN_SITES = {"cross-site", "same-site"}
_BODY = b'{"detail":"Cross-site requests to the Nemesis API are not allowed"}'


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key == name:
            return value.decode("latin-1")
    return None


def is_cross_site_request(scope: Scope) -> bool:
    """True when the browser says another site initiated this request."""
    fetch_site = _header(scope, b"sec-fetch-site")
    if fetch_site is not None:
        return fetch_site.strip().lower() in _FOREIGN_SITES

    # Older browsers: fall back to comparing Origin with the host the request was sent to
    origin = _header(scope, b"origin")
    if origin is None:
        return False  # not a browser cross-origin request (CLI, services, simple same-origin GETs)
    if origin.strip().lower() == "null":
        return True  # sandboxed/opaque origins (data: URLs, sandboxed iframes, some redirects)
    host = _header(scope, b"x-forwarded-host") or _header(scope, b"host") or ""
    host = host.split(",")[0].strip().lower()
    # Scheme the client used (Traefik terminates TLS and says so in X-Forwarded-Proto)
    scheme = (_header(scope, b"x-forwarded-proto") or scope.get("scheme") or "http").split(",")[0].strip().lower()
    scheme = {"ws": "http", "wss": "https"}.get(scheme, scheme)
    parsed = urlsplit(origin.strip())
    return parsed.netloc.lower() != host or parsed.scheme.lower() != scheme


class CrossSiteRequestBlocker:
    """ASGI middleware answering cross-site HTTP requests with 403 and refusing such websockets."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket") or not is_cross_site_request(scope):
            await self.app(scope, receive, send)
            return

        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return

        await send(
            {
                "type": "http.response.start",
                "status": 403,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(_BODY)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": _BODY})

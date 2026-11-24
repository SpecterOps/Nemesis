"""Certificate verification for the ``mythic`` scripting library.

mythic 0.2.x hard-codes ``ssl=False`` for its GraphQL HTTP transport and REST helpers, and ``CERT_NONE`` for its
websocket transport, so logins, queries and subscriptions never verify the Mythic server certificate. This module
replaces those helpers in ``mythic.mythic_utilities`` with versions that honour the connector's
``networking.validate_https_certs`` setting. The library resolves the helpers through its module globals at call
time, so ``mythic.login``, ``execute_custom_query`` and ``subscribe_custom_query`` all use the replacements.
"""

import ssl
from collections.abc import AsyncGenerator

import aiohttp
from gql.transport.aiohttp import AIOHTTPTransport
from gql.transport.websockets import WebsocketsTransport
from mythic import mythic_classes, mythic_utilities

_verify_certificates = True
_ca_file: str | None = None
_installed = False


def verifying_context(ca_file: str | None = None) -> ssl.SSLContext:
    """Return a certificate-verifying context: the system trust store, or only the CAs in ``ca_file`` if given."""
    return ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()


def client_ssl(use_tls: bool, verify: bool, ca_file: str | None = None) -> ssl.SSLContext | bool:
    """``ssl`` argument for the connector's own aiohttp requests to Mythic (preflight and file downloads)."""
    if not use_tls or not verify:
        return False
    return verifying_context(ca_file)


def ssl_setting(mythic: mythic_classes.Mythic, *, websocket: bool = False) -> ssl.SSLContext | bool:
    """Return the ``ssl`` argument for a connection to ``mythic``.

    Plain http/ws connections get ``False``. TLS connections get a verifying default context, or a context with
    verification disabled when ``validate_https_certs`` is off (aiohttp also accepts ``False`` for that).
    """
    if not mythic.ssl:
        return False
    if _verify_certificates:
        return verifying_context(_ca_file)
    if not websocket:
        return False
    # websockets treats ssl=False on a wss:// URL as "use the default verifying context", so an explicit
    # non-verifying context is required to honour the opt-out.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


async def get_http_transport(mythic: mythic_classes.Mythic) -> AIOHTTPTransport:
    return AIOHTTPTransport(
        url=f"{mythic.http}{mythic.server_ip}:{mythic.server_port}/graphql/",
        headers=mythic_utilities.get_headers(mythic),
        ssl=ssl_setting(mythic),
    )


async def get_ws_transport(mythic: mythic_classes.Mythic) -> WebsocketsTransport:
    return WebsocketsTransport(
        url=f"{mythic.ws}{mythic.server_ip}:{mythic.server_port}/graphql/",
        headers=mythic_utilities.get_headers(mythic),
        ssl=ssl_setting(mythic, websocket=True),
    )


async def http_post(mythic: mythic_classes.Mythic, data: dict, url: str) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.post(
            url, json=data, headers=mythic_utilities.get_headers(mythic), ssl=ssl_setting(mythic)
        ) as resp:
            return await resp.json()


async def http_post_form(mythic: mythic_classes.Mythic, data: aiohttp.FormData, url: str) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.post(
            url, data=data, headers=mythic_utilities.get_headers(mythic), ssl=ssl_setting(mythic)
        ) as resp:
            return await resp.json()


async def http_get_dictionary(mythic: mythic_classes.Mythic, url: str) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=mythic_utilities.get_headers(mythic), ssl=ssl_setting(mythic)) as resp:
            return await resp.json()


async def http_get(mythic: mythic_classes.Mythic, url: str) -> bytes:
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=mythic_utilities.get_headers(mythic), ssl=ssl_setting(mythic)) as resp:
            return await resp.content.read()


async def http_get_chunked(mythic: mythic_classes.Mythic, url: str, chunk_size: int = 512000) -> AsyncGenerator:
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=mythic_utilities.get_headers(mythic), ssl=ssl_setting(mythic)) as resp:
            async for data in resp.content.iter_chunked(abs(chunk_size)):
                yield data


_REPLACEMENTS = {
    "get_http_transport": get_http_transport,
    "get_ws_transport": get_ws_transport,
    "http_post": http_post,
    "http_post_form": http_post_form,
    "http_get_dictionary": http_get_dictionary,
    "http_get": http_get,
    "http_get_chunked": http_get_chunked,
}


def install(verify_certificates: bool, ca_file: str | None = None) -> None:
    """Route the mythic library's connections through this module, verifying certificates unless disabled.

    ``ca_file`` replaces the system trust store with the CAs in that PEM file. The settings are process-wide: the
    connector runs one Mythic instance per process.
    """
    global _verify_certificates, _ca_file, _installed
    _verify_certificates = bool(verify_certificates)
    _ca_file = ca_file
    if not _installed:
        for name, replacement in _REPLACEMENTS.items():
            if not hasattr(mythic_utilities, name):
                raise RuntimeError(f"mythic library no longer provides mythic_utilities.{name}; update tls.py")
            setattr(mythic_utilities, name, replacement)
        _installed = True

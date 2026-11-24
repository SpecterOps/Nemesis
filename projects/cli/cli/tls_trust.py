"""Certificate trust settings shared by every CLI command and connector.

Each HTTPS connection either verifies certificates against the system trust store (the default), verifies against
only the CAs in an optional PEM ``ca_file`` (for example a self-signed Nemesis or C2 certificate), or skips
verification when ``--ignore-cert-errors`` / ``validate_https_certs: false`` is set. Skipping verification wins
over a CA file.
"""

import ssl
from pathlib import Path

CA_FILE_ENVVAR = "NEMESIS_CA_FILE"


def resolve_ca_file(value: str | Path | None, setting: str = "ca_file") -> str | None:
    """Return ``value`` as an absolute path to an existing file (``~`` expanded), or None when unset.

    Raises ValueError for an empty value or a missing file, so bad paths fail when the config is loaded rather than
    on the first connection.
    """
    if value is None:
        return None
    if not isinstance(value, (str, Path)) or not str(value).strip():
        raise ValueError(f"{setting} must be a nonempty path")
    path = Path(value).expanduser()
    if not path.is_file():
        raise ValueError(f"{setting} not found: {path}")
    return str(path.resolve())


def verifying_context(ca_file: str | None = None) -> ssl.SSLContext:
    """A certificate-verifying context: the system trust store, or only the CAs in ``ca_file`` if given."""
    return ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()


def aiohttp_ssl(verify: bool, ca_file: str | None = None) -> ssl.SSLContext | bool:
    """``ssl`` argument for aiohttp: a verifying context, or False to skip verification."""
    return verifying_context(ca_file) if verify else False


def httpx_verify(verify: bool, ca_file: str | None = None) -> ssl.SSLContext | bool:
    """``verify`` argument for httpx: a verifying context, or False to skip verification."""
    return verifying_context(ca_file) if verify else False


def requests_verify(verify: bool, ca_file: str | None = None) -> str | bool:
    """``verify`` argument for requests: the CA file path, True for the system store, or False to skip."""
    if not verify:
        return False
    return ca_file or True

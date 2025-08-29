"""Helper functions for Chromium data processing."""

import re
from datetime import UTC, datetime, timedelta

import psycopg
import structlog
from dapr.clients import DaprClient
from impacket.dpapi import DPAPI_BLOB
from impacket.uuid import bin_to_string

logger = structlog.get_logger(module=__name__)


def get_postgres_connection_str() -> str:
    """Get PostgreSQL connection string from Dapr."""
    with DaprClient() as client:
        secret = client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_STRING")
        return secret.secret["POSTGRES_CONNECTION_STRING"]


def convert_chromium_timestamp(timestamp: int, str_format: bool = False) -> datetime | str | None:
    """Convert Chromium timestamp to datetime.

    Args:
        timestamp: Chromium timestamp (microseconds since 1601-01-01)
        str_format: Whether to return the timestamp in a string iso format (default is a datetime)

    Returns:
        datetime object or None if invalid
    """
    if not timestamp or timestamp == 0:
        return None

    try:
        epoch = datetime(1601, 1, 1, tzinfo=UTC)
        dt = epoch + timedelta(microseconds=timestamp)
        if str_format:
            return dt.isoformat()
        else:
            return dt
    except (ValueError, OverflowError):
        return None


def parse_chromium_file_path(file_path: str) -> tuple[str | None, str]:
    """Extract username and browser from Chromium file path.

    Args:
        file_path: Path to the Chromium file

    Returns:
        Tuple of (username, browser_name)
    """

    # normalize first
    file_path = file_path.replace("\\", "/")

    # Chrome/Edge/Brave pattern
    match = re.search(
        r".*/(?P<username>[^/]+)/AppData/Local/(?:Google|Microsoft|BraveSoftware)/(?P<browser>Chrome|Edge|Brave-Browser)/",
        file_path,
        re.IGNORECASE,
    )

    if match:
        username = match.group("username").lower()
        browser_str = match.group("browser").lower()

        if "chrome" in browser_str:
            return username, "chrome"
        elif "edge" in browser_str:
            return username, "edge"
        elif "brave" in browser_str:
            return username, "brave"

    # Opera pattern
    match = re.search(r".*/(?P<username>[^/]+)/AppData/Roaming/Opera Software/Opera Stable/", file_path, re.IGNORECASE)

    if match:
        username = match.group("username").lower()
        return username, "opera"

    return None, "unknown"


def detect_encryption_type(encrypted_value: bytes) -> tuple[str, str | None]:
    """Detect encryption type and extract masterkey GUID if applicable.

    Args:
        encrypted_value: Raw encrypted value bytes

    Returns:
        Tuple of (encryption_type, masterkey_guid)
    """
    if not encrypted_value or len(encrypted_value) < 4:
        return "unknown", None

    # Check for DPAPI (first 4 bytes are \x01\x00\x00\x00)
    if encrypted_value[:4] == b"\x01\x00\x00\x00":
        try:
            blob = DPAPI_BLOB(encrypted_value)
            if blob.rawData is not None:
                blob.rawData = blob.rawData[: len(blob.getData())]
                masterkey_guid = bin_to_string(blob["GuidMasterKey"]).lower()
                return "dpapi", masterkey_guid
        except Exception as e:
            logger.warning("Failed to parse DPAPI blob", error=str(e))
            return "dpapi", None
        return "dpapi", None

    # Check for key-based encryption (v10, v11)
    if len(encrypted_value) >= 3:
        prefix = encrypted_value[:3]
        try:
            prefix_str = prefix.decode("ascii")
            if prefix_str in ["v10", "v11"]:
                return "key", None
            elif prefix_str == "v20":
                return "abe", None
        except UnicodeDecodeError:
            pass

    return "unknown", None


def get_state_key_id(source: str, username: str | None, browser: str, pg_conn=None) -> int | None:
    """Get state key ID for key/abe encryption types.

    Args:
        source: Source value
        username: Username value
        browser: Browser value
        pg_conn: existing Postgres connection

    Returns:
        State key ID if found, None otherwise
    """
    if pg_conn:
        try:
            with pg_conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM chromium.state_keys WHERE source = %s AND username = %s AND browser = %s",
                    (source, username, browser),
                )
                result = cur.fetchone()
                return result[0] if result else None
        except Exception as e:
            logger.warning("Failed to lookup state key ID", error=str(e))
            return None
    else:
        try:
            conn_str = get_postgres_connection_str()
            with psycopg.connect(conn_str) as pg_conn:
                with pg_conn.cursor() as cur:
                    cur.execute(
                        "SELECT id FROM chromium.state_keys WHERE source = %s AND username = %s AND browser = %s",
                        (source, username, browser),
                    )
                    result = cur.fetchone()
                    return result[0] if result else None
        except Exception as e:
            logger.warning("Failed to lookup state key ID", error=str(e))
            return None

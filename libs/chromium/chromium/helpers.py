"""Helper functions for Chromium data processing."""

import re
import struct
from datetime import UTC, datetime, timedelta
from functools import lru_cache

import psycopg
import structlog
from Crypto.Cipher import AES, ChaCha20_Poly1305
from dapr.clients import DaprClient
from nemesis_dpapi import Blob

logger = structlog.get_logger(module=__name__)


def is_sqlite3(filename):
    try:
        with open(filename, "rb") as f:
            header = f.read(16)
        return header.startswith(b"SQLite format 3\0")
    except OSError:
        return False


@lru_cache(maxsize=1)
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
            blob = Blob.from_bytes(encrypted_value)
            return "dpapi", str(blob.masterkey_guid)
        except Exception as e:
            raise Exception(f"Found DPAPI app bound key, but couldn't parse blob: {str(e)}") from e

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


def get_state_key_bytes(state_key_id: int, encryption_type: str, pg_conn=None) -> bytes | None:
    """Get decrypted state key bytes for key/abe encryption types.

    Args:
        state_key_id: State key ID
        encryption_type: Either 'key' or 'abe'
        pg_conn: existing Postgres connection

    Returns:
        Decrypted key bytes if found and decrypted, None otherwise
    """
    if encryption_type not in ["key", "abe"]:
        return None

    column_name = "key_bytes_dec" if encryption_type == "key" else "app_bound_key_dec"
    is_decrypted_col = "key_is_decrypted" if encryption_type == "key" else "app_bound_key_is_decrypted"

    if pg_conn:
        try:
            with pg_conn.cursor() as cur:
                cur.execute(
                    f"SELECT {column_name}, {is_decrypted_col} FROM chromium.state_keys WHERE id = %s",
                    (state_key_id,),
                )
                result = cur.fetchone()
                if result and result[1]:  # Check if is_decrypted is True
                    return result[0]
                return None
        except Exception as e:
            logger.warning("Failed to lookup state key bytes", error=str(e))
            return None
    else:
        try:
            conn_str = get_postgres_connection_str()
            with psycopg.connect(conn_str) as pg_conn:
                with pg_conn.cursor() as cur:
                    cur.execute(
                        f"SELECT {column_name}, {is_decrypted_col} FROM chromium.state_keys WHERE id = %s",
                        (state_key_id,),
                    )
                    result = cur.fetchone()
                    if result and result[1]:  # Check if is_decrypted is True
                        return result[0]
                    return None
        except Exception as e:
            logger.warning("Failed to lookup state key bytes", error=str(e))
            return None


def get_all_state_keys_from_source(source: str, pg_conn=None) -> list[dict]:
    """Get all decrypted state keys from the same source.

    Args:
        source: Source value
        pg_conn: existing Postgres connection

    Returns:
        List of dictionaries containing state key information
    """
    state_keys = []

    if pg_conn:
        try:
            with pg_conn.cursor() as cur:
                cur.execute(
                    """SELECT id, username, browser, key_bytes_dec, key_is_decrypted,
                              app_bound_key_dec, app_bound_key_is_decrypted
                       FROM chromium.state_keys WHERE source = %s""",
                    (source,),
                )
                results = cur.fetchall()
                for result in results:
                    state_key_info = {
                        "id": result[0],
                        "username": result[1],
                        "browser": result[2],
                        "key_bytes_dec": result[3] if result[4] else None,  # Only if decrypted
                        "app_bound_key_dec": result[5] if result[6] else None,  # Only if decrypted
                    }
                    state_keys.append(state_key_info)
                return state_keys
        except Exception as e:
            logger.warning("Failed to lookup all state keys from source", error=str(e))
            return []
    else:
        try:
            conn_str = get_postgres_connection_str()
            with psycopg.connect(conn_str) as pg_conn:
                with pg_conn.cursor() as cur:
                    cur.execute(
                        """SELECT id, username, browser, key_bytes_dec, key_is_decrypted,
                                  app_bound_key_dec, app_bound_key_is_decrypted
                           FROM chromium.state_keys WHERE source = %s""",
                        (source,),
                    )
                    results = cur.fetchall()
                    for result in results:
                        state_key_info = {
                            "id": result[0],
                            "username": result[1],
                            "browser": result[2],
                            "key_bytes_dec": result[3] if result[4] else None,  # Only if decrypted
                            "app_bound_key_dec": result[5] if result[6] else None,  # Only if decrypted
                        }
                        state_keys.append(state_key_info)
                    return state_keys
        except Exception as e:
            logger.warning("Failed to lookup all state keys from source", error=str(e))
            return []


def is_valid_text(data: bytes) -> bool:
    """Check if decrypted bytes represent valid ASCII or UTF-8 text.

    Args:
        data: Bytes to validate

    Returns:
        True if data is valid text, False otherwise
    """
    if not data:
        return False

    try:
        # Try to decode as UTF-8
        text = data.decode("utf-8")
        # Check if it contains mostly printable characters
        printable_chars = sum(1 for c in text if c.isprintable() or c.isspace())
        return printable_chars / len(text) > 0.8  # At least 80% printable
    except UnicodeDecodeError:
        try:
            # Try ASCII as fallback
            text = data.decode("ascii")
            printable_chars = sum(1 for c in text if c in "\x20-\x7e\t\n\r")
            return printable_chars / len(text) > 0.8
        except UnicodeDecodeError:
            return False


def try_decrypt_with_all_keys(
    encrypted_value: bytes, source: str, encryption_type: str, pg_conn=None
) -> tuple[bytes | None, int | None]:
    """Try to decrypt with all available state keys from the same source.

    Args:
        encrypted_value: Raw encrypted value bytes
        source: Source value to look up keys from
        encryption_type: Either 'key' or 'abe'
        pg_conn: existing Postgres connection

    Returns:
        Tuple of (decrypted_bytes, state_key_id) if successful, (None, None) otherwise
    """
    if encryption_type not in ["key", "abe"]:
        return None, None

    state_keys = get_all_state_keys_from_source(source, pg_conn)

    for state_key in state_keys:
        key_bytes = state_key.get("key_bytes_dec") if encryption_type == "key" else state_key.get("app_bound_key_dec")

        if not key_bytes:
            continue

        try:
            decrypted_bytes = decrypt_chrome_string(encrypted_value, key_bytes, encryption_type)
            if decrypted_bytes:
                # Apply offset handling for cookies
                if encryption_type == "abe" and len(decrypted_bytes) > 32:
                    # v20 cookies typically have 32-byte offset
                    test_bytes = decrypted_bytes[32:]
                elif encryption_type == "key" and len(decrypted_bytes) > 48:
                    # v10/v11 cookies may have 32-byte prefix + 16-byte suffix
                    test_bytes = decrypted_bytes[32:-16]
                elif encryption_type == "key" and len(decrypted_bytes) > 16:
                    # Or just 16-byte suffix
                    test_bytes = decrypted_bytes[:-16]
                else:
                    test_bytes = decrypted_bytes

                # Check if the result is valid text
                if is_valid_text(test_bytes):
                    logger.debug(
                        "Successfully decrypted with backup key",
                        state_key_id=state_key["id"],
                        username=state_key["username"],
                        browser=state_key["browser"],
                    )
                    return decrypted_bytes, state_key["id"]
        except Exception:
            # Continue trying other keys
            continue

    return None, None


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def parse_abe_blob(abe_data: bytes, chromekey: bytes | None = None) -> dict | None:
    """Parse ABE (App-Bound Encryption) blob data.

    Args:
        abe_data: Raw ABE blob bytes

    Returns:
        Dictionary containing parsed ABE data, None if parsing fails
    """
    try:
        abe_parsed = {}
        header_len = struct.unpack("<I", abe_data[:4])[0]
        abe_parsed["header"] = abe_data[4 : 4 + header_len].strip(b"\x02").decode(errors="ignore")
        content_len = struct.unpack("<I", abe_data[4 + header_len : 4 + header_len + 4])[0]
        content = abe_data[8 + header_len : 8 + header_len + content_len]

        abe_parsed["version"] = int(content[0])
        content = content[1:]
        if abe_parsed["version"] <= 2:  # Versions 1 and 2
            # Version|IV|ciphertext|tag, 1|12|32|16 bytes
            abe_parsed["iv"] = content[:12]
            abe_parsed["cipherdata"] = content[12 : 12 + 32]
            abe_parsed["tag"] = content[12 + 32 : 12 + 32 + 16]
        else:  # Version 3
            # Version|encAES|IV|ciphertext|tag, 1|32|12|32|16 bytes
            # adapted from:
            #   https://github.com/KingOfTheNOPs/cookie-monster/blob/4ec4b3555682ac1e71a6428a4b0f45b2cf1fd8f7/decrypt.py
            #   https://github.com/tijldeneut/diana/blob/b9473b5004ecf1d7bdd5852232b5cd06a5378e5e/diana-browserdec.py
            abe_parsed["encrAES"] = content[:32]
            abe_parsed["iv"] = content[32 : 32 + 12]
            abe_parsed["cipherdata"] = content[32 + 12 : 32 + 12 + 32]
            abe_parsed["tag"] = content[32 + 12 + 32 : 32 + 12 + 32 + 16]

            if chromekey:
                xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
                abe_parsed["xored_aes_key"] = byte_xor(chromekey, xor_key)
        return abe_parsed
    except Exception as e:
        logger.warning("Failed to parse ABE blob", error=str(e))
        return None


def derive_abe_key(abe_data: dict) -> bytes | None:
    """Derive ABE key from parsed ABE data.

    Args:
        abe_data: Parsed ABE data dictionary

    Returns:
        Derived ABE key bytes, None if derivation fails
    """
    try:
        if abe_data["version"] == 1:
            cipher = AES.new(
                bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787"),
                AES.MODE_GCM,
                nonce=abe_data["iv"],
            )
        elif abe_data["version"] == 2:
            cipher = ChaCha20_Poly1305.new(
                key=bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660"),
                nonce=abe_data["iv"],
            )
        elif abe_data["version"] == 3:
            if abe_data["xored_aes_key"]:
                cipher = AES.new(abe_data["xored_aes_key"], AES.MODE_GCM, nonce=abe_data["iv"])
            else:
                # Version 3 requires CNG decryption of encrypted AES key
                logger.warning("xored_aes_key not present, ABE version 3 requires CNG decrypted (or memory-extracted) 'Google Chromekey1'")
            return None
        else:
            logger.warning("Unknown ABE version", version=abe_data["version"])
            return None

        return cipher.decrypt_and_verify(abe_data["cipherdata"], abe_data["tag"])
    except Exception as e:
        logger.warning("Failed to derive ABE key", error=str(e))
        return None


def decrypt_chrome_string(encrypted_data: bytes, key_bytes: bytes, encryption_type: str) -> bytes | None:
    """Decrypt Chrome encrypted string using key or ABE encryption.

    Args:
        encrypted_data: Raw encrypted data bytes
        key_bytes: Decrypted key bytes (BME key for 'key', ABE key for 'abe')
        encryption_type: Either 'key' or 'abe'

    Returns:
        Decrypted bytes, None if decryption fails
    """
    if not encrypted_data or len(encrypted_data) < 3:
        return None

    try:
        if encryption_type == "key" and encrypted_data[:3] in [b"v10", b"v11"]:
            # Version|IV|ciphertext, 4|12|<var>
            iv = encrypted_data[3 : 3 + 12]
            ciphertext = encrypted_data[15:]
            cipher = AES.new(key_bytes, AES.MODE_GCM, iv)
            return cipher.decrypt(ciphertext)

        elif encryption_type == "abe" and encrypted_data[:3] == b"v20":
            # Version|IV|ciphertext|tag, 3|12|<var>|16 bytes
            iv = encrypted_data[3 : 3 + 12]
            ciphertext = encrypted_data[15:-16]
            tag = encrypted_data[-16:]
            cipher = AES.new(key_bytes, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            # v20 cookies have 32-byte offset, but this varies by data type
            return decrypted
        else:
            logger.warning("Unsupported encryption format", prefix=encrypted_data[:3], encryption_type=encryption_type)
            return None

    except Exception as e:
        logger.warning("Failed to decrypt Chrome string", error=str(e))
        return None

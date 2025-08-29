"""Chromium Cookies file parsing and database operations."""

import sqlite3

import psycopg
import structlog
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio

from .helpers import (
    convert_chromium_timestamp,
    detect_encryption_type,
    get_postgres_connection_str,
    get_state_key_id,
    parse_chromium_file_path,
)

logger = structlog.get_logger(module=__name__)


def process_chromium_cookies(object_id: str, file_path: str | None = None) -> None:
    """Process Chromium Cookies file and insert cookies into database.

    Args:
        object_id: The object ID of the Cookies file
        file_path: Optional path to already downloaded file
    """
    logger.info("Processing Chromium Cookies file", object_id=object_id)

    file_enriched = get_file_enriched(object_id)

    # Extract username and browser from file path
    username, browser = parse_chromium_file_path(file_enriched.path or "")
    logger.debug("[process_chromium_cookies]", username=username, browser=browser)

    # Get database file
    if file_path:
        db_path = file_path
    else:
        storage = StorageMinio()
        with storage.download(file_enriched.object_id) as temp_file:
            db_path = temp_file.name

    conn_str = get_postgres_connection_str()
    with psycopg.connect(conn_str) as pg_conn:
        _insert_cookies(file_enriched, username, browser, db_path, pg_conn)

    logger.debug("Completed processing Chromium Cookies", object_id=object_id)


def _translate_samesite(samesite_int: int) -> str:
    """Translate samesite integer value to string.

    Args:
        samesite_int: Integer value from database

    Returns:
        String representation of samesite value
    """
    samesite_map = {-1: "Unspecified", 0: "None", 1: "Lax", 2: "Strict"}
    return samesite_map.get(samesite_int, "Unknown")


def _insert_cookies(file_enriched, username: str | None, browser: str, db_path: str, pg_conn) -> None:
    """Extract cookies from Cookies database and insert into chromium.cookies table."""
    try:
        # Read from SQLite
        with sqlite3.connect(db_path) as conn:
            conn.text_factory = bytes  # Get raw bytes, we'll handle text decoding manually
            cursor = conn.cursor()

            # Query cookies table
            cursor.execute("""
                SELECT host_key, name, path, creation_utc, expires_utc, last_access_utc,
                       last_update_utc, is_secure, is_httponly, is_persistent, samesite,
                       source_port, encrypted_value
                FROM cookies
            """)
            rows = cursor.fetchall()

        if not rows:
            return

        # Prepare data for PostgreSQL
        cookies_data = []
        for row in rows:
            (
                host_key,
                name,
                path,
                creation_utc,
                expires_utc,
                last_access_utc,
                last_update_utc,
                is_secure,
                is_httponly,
                is_persistent,
                samesite,
                source_port,
                encrypted_value,
            ) = row

            # Decode text fields from bytes (since we set text_factory = bytes)
            host_key = host_key.decode("utf-8", errors="replace") if host_key else None
            name = name.decode("utf-8", errors="replace") if name else None
            path = path.decode("utf-8", errors="replace") if path else None

            # encrypted_value is already binary (what we want)
            if encrypted_value is None:
                encrypted_value = b""

            # Detect encryption type and get masterkey GUID
            encryption_type, masterkey_guid = detect_encryption_type(encrypted_value)

            # Get state key ID for key/abe encryption
            state_key_id = None
            if encryption_type in ["key", "abe"]:
                state_key_id = get_state_key_id(file_enriched.source, username, browser, pg_conn)

            cookie_data = {
                "originating_object_id": file_enriched.object_id,
                "agent_id": file_enriched.agent_id,
                "source": file_enriched.source,
                "project": file_enriched.project,
                "username": username,
                "browser": browser,
                "host_key": host_key,
                "name": name,
                "path": path,
                "creation_utc": convert_chromium_timestamp(creation_utc),
                "expires_utc": convert_chromium_timestamp(expires_utc),
                "last_access_utc": convert_chromium_timestamp(last_access_utc),
                "last_update_utc": convert_chromium_timestamp(last_update_utc),
                "is_secure": bool(is_secure),
                "is_httponly": bool(is_httponly),
                "is_persistent": bool(is_persistent),
                "samesite": _translate_samesite(samesite) if samesite is not None else "Unknown",
                "source_port": source_port,
                "encryption_type": encryption_type,
                "masterkey_guid": masterkey_guid,
                "state_key_id": state_key_id,
                "is_decrypted": False,
                "value_enc": encrypted_value,
                "value_dec": None,
            }
            cookies_data.append(cookie_data)

        # Insert into PostgreSQL
        with pg_conn.cursor() as cur:
            insert_sql = """
                INSERT INTO chromium.cookies
                (originating_object_id, agent_id, source, project, username, browser,
                    host_key, name, path, creation_utc, expires_utc, last_access_utc,
                    last_update_utc, is_secure, is_httponly, is_persistent, samesite,
                    source_port, encryption_type, masterkey_guid, state_key_id,
                    is_decrypted, value_enc, value_dec)
                VALUES (%(originating_object_id)s, %(agent_id)s, %(source)s, %(project)s,
                        %(username)s, %(browser)s, %(host_key)s, %(name)s, %(path)s,
                        %(creation_utc)s, %(expires_utc)s, %(last_access_utc)s,
                        %(last_update_utc)s, %(is_secure)s, %(is_httponly)s, %(is_persistent)s,
                        %(samesite)s, %(source_port)s, %(encryption_type)s, %(masterkey_guid)s,
                        %(state_key_id)s, %(is_decrypted)s, %(value_enc)s, %(value_dec)s)
                ON CONFLICT (source, username, browser, host_key, name, path)
                DO UPDATE SET
                    host_key = EXCLUDED.host_key,
                    name = EXCLUDED.name,
                    path = EXCLUDED.path,
                    creation_utc = EXCLUDED.creation_utc,
                    expires_utc = EXCLUDED.expires_utc,
                    last_access_utc = EXCLUDED.last_access_utc,
                    last_update_utc = EXCLUDED.last_update_utc,
                    is_secure = EXCLUDED.is_secure,
                    is_httponly = EXCLUDED.is_httponly,
                    is_persistent = EXCLUDED.is_persistent,
                    samesite = EXCLUDED.samesite,
                    source_port = EXCLUDED.source_port,
                    encryption_type = EXCLUDED.encryption_type,
                    masterkey_guid = EXCLUDED.masterkey_guid,
                    state_key_id = EXCLUDED.state_key_id,
                    is_decrypted = EXCLUDED.is_decrypted,
                    value_enc = EXCLUDED.value_enc,
                    value_dec = EXCLUDED.value_dec
            """

            cur.executemany(insert_sql, cookies_data)
            pg_conn.commit()

        logger.info("Inserted cookies into database", count=len(cookies_data))

    except Exception as e:
        logger.exception("Error processing Cookies", error=str(e))
        raise

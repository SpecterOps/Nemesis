"""Chromium Login Data file parsing and database operations."""

import sqlite3
import asyncio

import psycopg
import structlog
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from nemesis_dpapi import Blob, DpapiManager

from .helpers import (
    convert_chromium_timestamp,
    decrypt_chrome_string,
    detect_encryption_type,
    get_postgres_connection_str,
    get_state_key_bytes,
    get_state_key_id,
    parse_chromium_file_path,
)

logger = structlog.get_logger(module=__name__)


def process_chromium_logins(
    object_id: str, file_path: str | None = None, dpapi_manager: DpapiManager | None = None
) -> None:
    """Process Chromium Login Data file and insert logins into database.

    Args:
        object_id: The object ID of the Login Data file
        file_path: Optional path to already downloaded file
        dpapi_manager: DPAPI manager for decryption
    """
    logger.info("Processing Chromium Login Data file", object_id=object_id)

    file_enriched = get_file_enriched(object_id)

    # Extract username and browser from file path
    username, browser = parse_chromium_file_path(file_enriched.path or "")
    logger.debug("[process_chromium_logins]", username=username, browser=browser)

    # Get database file
    if file_path:
        db_path = file_path
    else:
        storage = StorageMinio()
        with storage.download(file_enriched.object_id) as temp_file:
            db_path = temp_file.name

    conn_str = get_postgres_connection_str()
    with psycopg.connect(conn_str) as pg_conn:
        _insert_logins(file_enriched, username, browser, db_path, pg_conn, dpapi_manager)

    logger.debug("Completed processing Chromium Login Data", object_id=object_id)


def _insert_logins(
    file_enriched, username: str | None, browser: str, db_path: str, pg_conn, dpapi_manager: DpapiManager | None = None
) -> None:
    """Extract logins from Login Data database and insert into chromium.logins table."""
    try:
        # Read from SQLite
        with sqlite3.connect(db_path) as conn:
            conn.text_factory = bytes  # Get raw bytes, we'll handle text decoding manually
            cursor = conn.cursor()

            # Query logins table
            cursor.execute("""
                SELECT origin_url, username_value, signon_realm, date_created,
                       date_last_used, date_password_modified, times_used, password_value
                FROM logins
            """)
            rows = cursor.fetchall()

        if not rows:
            return

        # Prepare data for PostgreSQL
        logins_data = []
        for row in rows:
            (
                origin_url,
                username_value,
                signon_realm,
                date_created,
                date_last_used,
                date_password_modified,
                times_used,
                password_value,
            ) = row

            # Decode text fields from bytes (since we set text_factory = bytes)
            origin_url = origin_url.decode("utf-8", errors="replace") if origin_url else None
            username_value = username_value.decode("utf-8", errors="replace") if username_value else None
            signon_realm = signon_realm.decode("utf-8", errors="replace") if signon_realm else None

            # password_value is already binary (what we want)
            if password_value is None:
                password_value = b""

            # Detect encryption type and get masterkey GUID
            encryption_type, masterkey_guid = detect_encryption_type(password_value)
            is_decrypted = False
            password_value_dec = None

            # Try DPAPI decryption first
            if masterkey_guid and dpapi_manager:
                try:
                    password_dec_bytes = asyncio.run(dpapi_manager.decrypt_blob(Blob.parse(password_value)))
                    if password_dec_bytes:
                        password_value_dec = password_dec_bytes.decode('utf-8', errors='replace')
                        is_decrypted = True
                except:
                    pass

            # Get state key ID for key/abe encryption
            state_key_id = None
            if encryption_type in ["key", "abe"]:
                state_key_id = get_state_key_id(file_enriched.source, username, browser, pg_conn)
                if state_key_id:
                    # Retrieve the pre-processed state key for decryption
                    state_key_bytes = get_state_key_bytes(state_key_id, encryption_type, pg_conn)
                    if state_key_bytes:
                        try:
                            password_dec_bytes = decrypt_chrome_string(password_value, state_key_bytes, encryption_type)
                            if password_dec_bytes:
                                # For passwords, may need to strip offset bytes depending on version
                                if encryption_type == "key" and len(password_dec_bytes) > 32:
                                    # v10/v11 passwords may have 32-byte prefix + 16-byte suffix
                                    password_dec_bytes = password_dec_bytes[32:-16]
                                elif encryption_type == "key" and len(password_dec_bytes) > 16:
                                    # Or just 16-byte suffix
                                    password_dec_bytes = password_dec_bytes[:-16]
                                # v20 passwords typically don't have offset like cookies

                                password_value_dec = password_dec_bytes.decode('utf-8', errors='replace')
                                is_decrypted = True
                        except Exception as e:
                            logger.debug("Failed to decrypt password with state key",
                                       state_key_id=state_key_id,
                                       encryption_type=encryption_type,
                                       error=str(e))

            login_data = {
                "originating_object_id": file_enriched.object_id,
                "agent_id": file_enriched.agent_id,
                "source": file_enriched.source,
                "project": file_enriched.project,
                "username": username,
                "browser": browser,
                "origin_url": origin_url,
                "username_value": username_value,
                "signon_realm": signon_realm,
                "date_created": convert_chromium_timestamp(date_created),
                "date_last_used": convert_chromium_timestamp(date_last_used),
                "date_password_modified": convert_chromium_timestamp(date_password_modified),
                "times_used": times_used,
                "encryption_type": encryption_type,
                "masterkey_guid": masterkey_guid,
                "state_key_id": state_key_id,
                "is_decrypted": is_decrypted,
                "password_value_enc": password_value,
                "password_value_dec": password_value_dec,
            }
            logins_data.append(login_data)

        # Insert into PostgreSQL
        with pg_conn.cursor() as cur:
            insert_sql = """
                INSERT INTO chromium.logins
                (originating_object_id, agent_id, source, project, username, browser,
                 origin_url, username_value, signon_realm, date_created, date_last_used,
                 date_password_modified, times_used, encryption_type, masterkey_guid,
                 state_key_id, is_decrypted, password_value_enc, password_value_dec)
                VALUES (%(originating_object_id)s, %(agent_id)s, %(source)s, %(project)s,
                        %(username)s, %(browser)s, %(origin_url)s, %(username_value)s,
                        %(signon_realm)s, %(date_created)s, %(date_last_used)s,
                        %(date_password_modified)s, %(times_used)s, %(encryption_type)s,
                        %(masterkey_guid)s, %(state_key_id)s, %(is_decrypted)s,
                        %(password_value_enc)s, %(password_value_dec)s)
                ON CONFLICT (source, username, browser, origin_url, username_value)
                DO UPDATE SET
                    origin_url = EXCLUDED.origin_url,
                    username_value = EXCLUDED.username_value,
                    signon_realm = EXCLUDED.signon_realm,
                    date_created = EXCLUDED.date_created,
                    date_last_used = EXCLUDED.date_last_used,
                    date_password_modified = EXCLUDED.date_password_modified,
                    times_used = EXCLUDED.times_used,
                    encryption_type = EXCLUDED.encryption_type,
                    masterkey_guid = EXCLUDED.masterkey_guid,
                    state_key_id = EXCLUDED.state_key_id,
                    is_decrypted = EXCLUDED.is_decrypted,
                    password_value_enc = EXCLUDED.password_value_enc,
                    password_value_dec = EXCLUDED.password_value_dec
            """

            cur.executemany(insert_sql, logins_data)
            pg_conn.commit()

        logger.info("Inserted logins into database", count=len(logins_data))

    except Exception as e:
        logger.exception("Error processing Login Data", error=str(e))
        raise

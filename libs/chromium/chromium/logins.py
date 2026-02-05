"""Chromium Login Data file parsing and database operations."""

import sqlite3

import asyncpg
from common.logger import get_logger
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from nemesis_dpapi import Blob, DpapiManager

from .helpers import (
    convert_chromium_timestamp,
    decrypt_chrome_string,
    detect_encryption_type,
    get_state_key_bytes,
    get_state_key_id,
    is_sqlite3,
    parse_chromium_file_path,
    try_decrypt_with_all_keys,
)

logger = get_logger(__name__)


async def process_chromium_logins(
    object_id: str,
    file_path: str | None = None,
    dpapi_manager: DpapiManager | None = None,
    asyncpg_pool: asyncpg.Pool | None = None,
) -> None:
    """Process Chromium Login Data file and insert logins into database using asyncpg.

    Args:
        object_id: The object ID of the Login Data file
        file_path: Optional path to already downloaded file
        dpapi_manager: DPAPI manager for decryption
        asyncpg_pool: Async Postgres connection pool
    """
    logger.info("Processing Chromium Login Data file", object_id=object_id)

    file_enriched = await get_file_enriched_async(object_id, asyncpg_pool)

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

    if is_sqlite3(db_path) is False:
        logger.warning(
            "Login Data file is not a valid SQLite3 database", object_id=object_id, file_path=file_enriched.path
        )
        return

    assert asyncpg_pool is not None, "asyncpg_pool is required for login processing"
    await _insert_logins(file_enriched, username, browser, db_path, dpapi_manager, asyncpg_pool)

    logger.debug("Completed processing Chromium Login Data", object_id=object_id)


async def _insert_logins(
    file_enriched,
    username: str | None,
    browser: str,
    db_path: str,
    dpapi_manager: DpapiManager | None = None,
    asyncpg_pool: asyncpg.Pool | None = None,
) -> None:
    """Extract logins from Login Data database and insert into chromium.logins table using asyncpg."""
    assert asyncpg_pool is not None, "asyncpg_pool is required"
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
                    password_dec_bytes = await dpapi_manager.decrypt_blob(Blob.from_bytes(password_value))
                    if password_dec_bytes:
                        password_value_dec = password_dec_bytes.decode("utf-8", errors="replace")
                        is_decrypted = True
                except Exception:
                    pass

            # Get state key ID for key/abe encryption
            state_key_id = None
            if encryption_type in ["key", "abe"]:
                # Try primary approach: get state key based on username/browser
                if username:  # Only try primary approach if username was extracted
                    state_key_id = await get_state_key_id(file_enriched.source, username, browser, asyncpg_pool)
                    if state_key_id:
                        # Retrieve the pre-processed state key for decryption
                        state_key_bytes = await get_state_key_bytes(state_key_id, encryption_type, asyncpg_pool)
                        if state_key_bytes:
                            try:
                                password_dec_bytes = decrypt_chrome_string(
                                    password_value, state_key_bytes, encryption_type
                                )
                                if password_dec_bytes:
                                    # For passwords, may need to strip offset bytes depending on version
                                    if encryption_type == "key" and len(password_dec_bytes) > 32:
                                        # v10/v11 passwords may have 32-byte prefix + 16-byte suffix
                                        password_dec_bytes = password_dec_bytes[32:-16]
                                    elif encryption_type == "key" and len(password_dec_bytes) > 16:
                                        # Or just 16-byte suffix
                                        password_dec_bytes = password_dec_bytes[:-16]
                                    # v20 passwords typically don't have offset like cookies

                                    password_value_dec = password_dec_bytes.decode("utf-8", errors="replace")
                                    is_decrypted = True
                            except Exception as e:
                                logger.debug(
                                    "Failed to decrypt password with state key",
                                    state_key_id=state_key_id,
                                    encryption_type=encryption_type,
                                    error=str(e),
                                )

                # Backup approach: try all state keys from the same source if primary failed
                if not is_decrypted:
                    logger.debug(
                        "Primary decryption failed, trying backup approach with all keys from source",
                        source=file_enriched.source,
                        encryption_type=encryption_type,
                    )
                    backup_decrypted_bytes, backup_state_key_id = await try_decrypt_with_all_keys(
                        password_value, file_enriched.source, encryption_type, asyncpg_pool
                    )
                    if backup_decrypted_bytes and backup_state_key_id:
                        # Apply the same offset handling as above
                        if encryption_type == "abe" and len(backup_decrypted_bytes) > 32:
                            # v20 cookies typically have 32-byte offset
                            backup_decrypted_bytes = backup_decrypted_bytes[32:]
                        elif encryption_type == "key" and len(backup_decrypted_bytes) > 48:
                            # v10/v11 cookies may have 32-byte prefix + 16-byte suffix
                            backup_decrypted_bytes = backup_decrypted_bytes[32:-16]
                        elif encryption_type == "key" and len(backup_decrypted_bytes) > 16:
                            # Or just 16-byte suffix
                            backup_decrypted_bytes = backup_decrypted_bytes[:-16]

                        password_value_dec = backup_decrypted_bytes.decode("utf-8", errors="replace")
                        is_decrypted = True
                        state_key_id = backup_state_key_id
                        logger.debug(
                            "Successfully decrypted password using backup approach", state_key_id=backup_state_key_id
                        )

            login_data = (
                file_enriched.object_id,  # originating_object_id
                file_enriched.agent_id,  # agent_id
                file_enriched.source,  # source
                file_enriched.project,  # project
                username,  # username
                browser,  # browser
                origin_url,  # origin_url
                username_value,  # username_value
                signon_realm,  # signon_realm
                convert_chromium_timestamp(date_created),  # date_created
                convert_chromium_timestamp(date_last_used),  # date_last_used
                convert_chromium_timestamp(date_password_modified),  # date_password_modified
                times_used,  # times_used
                encryption_type,  # encryption_type
                masterkey_guid,  # masterkey_guid
                state_key_id,  # state_key_id
                is_decrypted,  # is_decrypted
                password_value,  # password_value_enc
                password_value_dec,  # password_value_dec
            )
            logins_data.append(login_data)

        # Insert into PostgreSQL using asyncpg
        async with asyncpg_pool.acquire() as conn:
            insert_sql = """
                INSERT INTO chromium.logins
                (originating_object_id, agent_id, source, project, username, browser,
                 origin_url, username_value, signon_realm, date_created, date_last_used,
                 date_password_modified, times_used, encryption_type, masterkey_guid,
                 state_key_id, is_decrypted, password_value_enc, password_value_dec)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
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

            await conn.executemany(insert_sql, logins_data)

        logger.info("Inserted logins into database", count=len(logins_data))

    except Exception as e:
        logger.exception(
            "Error processing Login Data",
            error=str(e),
            object_id=file_enriched.object_id,
            file_path=file_enriched.path,
        )
        raise

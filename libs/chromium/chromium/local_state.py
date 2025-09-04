"""Chromium Local State file parsing and database operations."""

import base64
import json
import ntpath

import psycopg
import structlog
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from file_linking import add_file_linking
from impacket.dpapi import DPAPI_BLOB
from impacket.uuid import bin_to_string
from nemesis_dpapi import Blob, DpapiManager

from .helpers import (
    detect_encryption_type,
    get_postgres_connection_str,
    parse_chromium_file_path,
)

logger = structlog.get_logger(module=__name__)


def process_chromium_local_state(
    object_id: str, file_path: str | None = None, dpapi_manager: DpapiManager | None = None
) -> None:
    """Process Chromium Local State file and insert state keys into database.

    Args:
        object_id: The object ID of the Local State file
        file_path: Optional path to already downloaded file
    """
    logger.info("Processing Chromium Local State file", object_id=object_id)

    file_enriched = get_file_enriched(object_id)

    # Extract username and browser from file path
    username, browser = parse_chromium_file_path(file_enriched.path or "")
    logger.debug("[process_chromium_local_state]", username=username, browser=browser)

    # Get file content
    if file_path:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()
    else:
        storage = StorageMinio()
        with storage.download(file_enriched.object_id) as temp_file:
            with open(temp_file.name, encoding="utf-8") as f:
                content = f.read()

    conn_str = get_postgres_connection_str()
    with psycopg.connect(conn_str) as pg_conn:
        _insert_state_keys(file_enriched, username, browser, content, pg_conn, dpapi_manager)

    logger.debug("Completed processing Chromium Local State", object_id=object_id)


def _parse_app_bound_key(app_bound_key_b64: str) -> tuple[bytes, str | None]:
    """Parse app-bound encrypted key and extract system masterkey GUID.

    Args:
        app_bound_key_b64: Base64 encoded app-bound key

    Returns:
        Tuple of (decoded_bytes, system_masterkey_guid)

    Raises:
        ValueError: If the key doesn't have APPB header
    """
    try:
        app_bound_key_bytes = base64.b64decode(app_bound_key_b64)

        # Check for APPB header (first 4 bytes)
        if len(app_bound_key_bytes) < 4 or app_bound_key_bytes[:4] != b"APPB":
            raise ValueError("App-bound key does not have APPB header")

        # Remove APPB header and parse remaining as DPAPI blob
        dpapi_bytes = app_bound_key_bytes[4:]

        blob = DPAPI_BLOB(dpapi_bytes)
        if blob.rawData is not None:
            blob.rawData = blob.rawData[: len(blob.getData())]
            system_masterkey_guid = bin_to_string(blob["GuidMasterKey"]).lower()
            return app_bound_key_bytes, system_masterkey_guid

        return app_bound_key_bytes, None

    except Exception as e:
        logger.warning("Failed to parse app-bound key", error=str(e))
        return base64.b64decode(app_bound_key_b64), None


def _insert_state_keys(
    file_enriched, username: str | None, browser: str, content: str, pg_conn, dpapi_manager: DpapiManager | None = None
) -> None:
    """Parse Local State JSON and insert state keys into chromium.state_keys table."""
    try:
        # Parse JSON content
        data = json.loads(content)

        # Extract os_crypt section
        os_crypt = data.get("os_crypt", {})

        key_bytes_dec = b""
        app_bound_key_dec_inter = b""
        app_bound_key_dec = b""

        # Get encrypted_key (pre v127)
        encrypted_key_b64 = os_crypt.get("encrypted_key")
        key_bytes_enc = b""
        key_masterkey_guid = None

        if encrypted_key_b64:
            key_bytes_enc = base64.b64decode(encrypted_key_b64)

            if len(key_bytes_enc) < 5 or key_bytes_enc[:5] != b"DPAPI":
                raise ValueError("App-bound key does not have DPAPI header")

            # Remove APPB header and parse remaining as DPAPI blob
            dpapi_bytes = key_bytes_enc[5:]

            encryption_type, masterkey_guid = detect_encryption_type(dpapi_bytes)
            if encryption_type == "dpapi":
                key_masterkey_guid = masterkey_guid
                try:
                    key_bytes_dec = dpapi_manager.decrypt_blob(Blob(dpapi_bytes))
                except Exception:
                    logger.warning(f"Unable to decrypt DPAPI blob: {key_masterkey_guid}")

        # Get app_bound_encrypted_key (post v127)
        app_bound_key_b64 = os_crypt.get("app_bound_encrypted_key")
        app_bound_key_enc = b""
        app_bound_key_system_masterkey_guid = None

        if app_bound_key_b64:
            app_bound_key_enc, app_bound_key_system_masterkey_guid = _parse_app_bound_key(app_bound_key_b64)

            drive, parts = ntpath.splitdrive(file_enriched.path)
            masterkey_path = (
                f"{drive}/Windows/System32/Microsoft/Protect/S-1-5-18/User/{app_bound_key_system_masterkey_guid}"
            )

            # add the masterkey file path (now that we know the key GUID) as a link/listing
            add_file_linking(file_enriched.source, file_enriched.path, masterkey_path, "windows:system_masterkey")

            try:
                app_bound_key_dec_inter = dpapi_manager.decrypt_blob(Blob(app_bound_key_enc))
                if app_bound_key_dec_inter:
                    try:
                        # TODO: parse app_bound_key_user_masterkey_guid
                        app_bound_key_dec = dpapi_manager.decrypt_blob(Blob(app_bound_key_dec_inter))
                    except Exception:
                        logger.warning(f"Unable to decrypt final app bound key blob: {key_masterkey_guid}")
            except Exception:
                logger.warning(f"Unable to decrypt intermediate/outer app bound key blob: {key_masterkey_guid}")

        # Skip if no keys are present
        if not key_bytes_enc and not app_bound_key_enc:
            logger.warning("No encryption keys found in Local State file")
            return

        # Prepare data for PostgreSQL
        state_key_data = {
            "originating_object_id": file_enriched.object_id,
            "agent_id": file_enriched.agent_id,
            "source": file_enriched.source,
            "project": file_enriched.project,
            "username": username,
            "browser": browser,
            "key_masterkey_guid": key_masterkey_guid,
            "key_bytes_enc": key_bytes_enc,
            "key_bytes_dec": key_bytes_dec,
            "key_is_decrypted": False,
            "app_bound_key_enc": app_bound_key_enc,
            "app_bound_key_system_masterkey_guid": app_bound_key_system_masterkey_guid,
            "app_bound_key_user_masterkey_guid": None,  # Will be populated later
            "app_bound_key_dec_inter": app_bound_key_dec_inter,
            "app_bound_key_dec": app_bound_key_dec,
            "app_bound_key_is_decrypted": False,
        }

        # Insert into PostgreSQL
        with pg_conn.cursor() as cur:
            insert_sql = """
                INSERT INTO chromium.state_keys
                (originating_object_id, agent_id, source, project, username, browser,
                 key_masterkey_guid, key_bytes_enc, key_bytes_dec, key_is_decrypted,
                 app_bound_key_enc, app_bound_key_system_masterkey_guid,
                 app_bound_key_user_masterkey_guid, app_bound_key_dec_inter, app_bound_key_dec, app_bound_key_is_decrypted)
                VALUES (%(originating_object_id)s, %(agent_id)s, %(source)s, %(project)s,
                        %(username)s, %(browser)s, %(key_masterkey_guid)s, %(key_bytes_enc)s,
                        %(key_bytes_dec)s, %(key_is_decrypted)s, %(app_bound_key_enc)s,
                        %(app_bound_key_system_masterkey_guid)s, %(app_bound_key_user_masterkey_guid)s,
                        %(app_bound_key_dec_inter)s, %(app_bound_key_dec)s, %(app_bound_key_is_decrypted)s)
                ON CONFLICT (source, username, browser)
                DO UPDATE SET
                    key_masterkey_guid = EXCLUDED.key_masterkey_guid,
                    key_bytes_enc = EXCLUDED.key_bytes_enc,
                    key_bytes_dec = EXCLUDED.key_bytes_dec,
                    key_is_decrypted = EXCLUDED.key_is_decrypted,
                    app_bound_key_enc = EXCLUDED.app_bound_key_enc,
                    app_bound_key_system_masterkey_guid = EXCLUDED.app_bound_key_system_masterkey_guid,
                    app_bound_key_user_masterkey_guid = EXCLUDED.app_bound_key_user_masterkey_guid,
                    app_bound_key_dec_inter = EXCLUDED.app_bound_key_dec_inter,
                    app_bound_key_dec = EXCLUDED.app_bound_key_dec,
                    app_bound_key_is_decrypted = EXCLUDED.app_bound_key_is_decrypted
            """

            cur.execute(insert_sql, state_key_data)

            # Get the inserted state key ID
            cur.execute(
                "SELECT id FROM chromium.state_keys WHERE source = %s AND username = %s AND browser = %s",
                (file_enriched.source, username, browser),
            )
            result = cur.fetchone()
            if result:
                state_key_id = result[0]

                cur.execute(
                    """
                    UPDATE chromium.logins
                    SET state_key_id = %s
                    WHERE source = %s AND username = %s AND browser = %s
                    AND state_key_id IS NULL
                    AND encryption_type IN ('key', 'abe')
                """,
                    (state_key_id, file_enriched.source, username, browser),
                )
                logins_updated = cur.rowcount

                cur.execute(
                    """
                    UPDATE chromium.cookies
                    SET state_key_id = %s
                    WHERE source = %s AND username = %s AND browser = %s
                    AND state_key_id IS NULL
                    AND encryption_type IN ('key', 'abe')
                """,
                    (state_key_id, file_enriched.source, username, browser),
                )
                cookies_updated = cur.rowcount

                logger.info(
                    "Updated existing entries with state key ID",
                    state_key_id=state_key_id,
                    logins_updated=logins_updated,
                    cookies_updated=cookies_updated,
                )

            pg_conn.commit()

        logger.info(
            "Inserted state keys into database",
            has_encrypted_key=bool(key_bytes_enc),
            has_app_bound_key=bool(app_bound_key_enc),
        )

    except json.JSONDecodeError as e:
        logger.exception("Failed to parse Local State JSON", error=str(e))
        raise
    except Exception as e:
        logger.exception("Error processing Local State", error=str(e))
        raise

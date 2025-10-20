"""Chromium Local State file parsing and database operations."""

import base64
import json
import posixpath
from uuid import UUID

import psycopg
from common.helpers import get_drive_from_path
from common.logger import get_logger
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from file_linking import add_file_linking
from impacket.dpapi import DPAPI_BLOB
from impacket.uuid import bin_to_string
from nemesis_dpapi import Blob, DpapiManager, MasterKeyNotDecryptedError, MasterKeyNotFoundError

from .helpers import (
    derive_abe_key,
    detect_encryption_type,
    get_postgres_connection_str,
    parse_abe_blob,
    parse_chromium_file_path,
)

logger = get_logger(__name__)


async def process_chromium_local_state(
    dpapi_manager: DpapiManager,
    object_id: str,
    file_path: str | None = None,
) -> dict | None:
    """Process Chromium Local State file and insert state keys into database.

    Args:
        object_id: The object ID of the Local State file
        file_path: Optional path to already downloaded file
    """
    logger.info("Processing Chromium Local State file", object_id=object_id)

    file_enriched = get_file_enriched(object_id)

    # Extract username and browser from file path
    username, browser = parse_chromium_file_path(file_enriched.path or "")
    logger.debug("[process_chromium_local_state()]", username=username, browser=browser)

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
        state_key_data = await _insert_state_keys(file_enriched, username, browser, content, pg_conn, dpapi_manager)

    logger.debug("Completed processing Chromium Local State", object_id=object_id)
    return state_key_data


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
        app_bound_key_bytes = base64.b64decode(app_bound_key_b64, validate=True)

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



async def _add_user_masterkey_link(file_enriched, username: str | None, masterkey_guid: UUID) -> None:
    """Add file linking entry for user masterkey."""

    # Skip trying to figure out the username/drive if we can
    if r"AppData/Local/Google/Chrome/User Data" in file_enriched.path:
        masterkey_path = posixpath.normpath(
            posixpath.join(
                file_enriched.path,
                "../../../../../Roaming/Microsoft/Protect/<WINDOWS_SECURITY_IDENTIFIER>",
                str(masterkey_guid),
            )
        )
    else:
        # Not an AppData path, so build path based on the drive letter and username (if available)
        drive = get_drive_from_path(file_enriched.path) or ""

        if not username:
            username = "<WINDOWS_USERNAME>"

        masterkey_path = (
            f"{drive}/Users/{username}/AppData/Roaming/Microsoft/Protect/<WINDOWS_SECURITY_IDENTIFIER>/{masterkey_guid}"
        )

    await add_file_linking(file_enriched.source, file_enriched.path, masterkey_path, "windows:user_masterkey")


def _get_chromekey_from_source(source: str, pg_conn) -> bytes | None:
    """Get decrypted Chrome key from chrome_keys table by source.

    Args:
        source: Source value to match
        pg_conn: PostgreSQL connection

    Returns:
        Decrypted key bytes if found and decrypted, None otherwise
    """
    try:
        with pg_conn.cursor() as cur:
            cur.execute(
                "SELECT key_bytes_dec FROM chromium.chrome_keys WHERE source = %s AND key_is_decrypted = TRUE",
                (source,),
            )
            result = cur.fetchone()
            return result[0] if result else None
    except Exception as e:
        logger.warning("Failed to lookup chrome key from source", error=str(e))
        return None


async def _insert_state_keys(
    file_enriched,
    username: str | None,
    browser: str,
    content: str,
    pg_conn,
    dpapi_manager: DpapiManager,
) -> dict | None:
    """Parse Local State JSON and insert state keys into chromium.state_keys table."""
    try:
        # Parse JSON content
        data = json.loads(content)

        # Extract os_crypt section
        os_crypt = data.get("os_crypt", {})

        # Get Chrome key from chrome_keys table if available
        chromekey = _get_chromekey_from_source(file_enriched.source, pg_conn)

        key_bytes_dec = b""
        key_is_decrypted = False
        app_bound_key_system_dec = b""
        app_bound_key_user_dec = b""
        app_bound_key_dec = b""
        app_bound_key_is_decrypted = False

        # Get encrypted_key (pre v127)
        encrypted_key_b64 = os_crypt.get("encrypted_key")
        key_bytes_enc = b""
        key_masterkey_guid = None

        if encrypted_key_b64:
            logger.debug("Found app bound key encrypted_key in Local State")
            key_bytes_enc = base64.b64decode(encrypted_key_b64)

            if len(key_bytes_enc) < 5 or key_bytes_enc[:5] != b"DPAPI":
                raise ValueError("Encrypted key does not have DPAPI header")

            # Remove DPAPI header and parse remaining as DPAPI blob
            dpapi_blob_bytes = key_bytes_enc[5:]

            encryption_type, _ = detect_encryption_type(dpapi_blob_bytes)
            if encryption_type != "dpapi":
                raise Exception(f"Unsupported encryption type for v1 state key: {encryption_type}")

            dpapi_blob = Blob.from_bytes(dpapi_blob_bytes)
            key_masterkey_guid = str(dpapi_blob.masterkey_guid)
            try:
                key_bytes_dec = await dpapi_manager.decrypt_blob(dpapi_blob)
                if key_bytes_dec:
                    key_is_decrypted = True
                    logger.debug(
                        "Successfully decrypted encrypted_key state key",
                        masterkey_guid=dpapi_blob.masterkey_guid,
                    )
                else:
                    logger.debug("Failed to decrypt encrypted_key state key with DPAPI")
            except (MasterKeyNotFoundError, MasterKeyNotDecryptedError) as e:
                logger.debug(
                    "Masterkey not found or not decrypted for encrypted_key state key",
                    masterkey_guid=dpapi_blob.masterkey_guid,
                    reason=type(e).__name__,
                )

                await _add_user_masterkey_link(file_enriched, username, dpapi_blob.masterkey_guid)

            except Exception as e:
                logger.warning(f"Unable to decrypt state key DPAPI blob: {dpapi_blob.masterkey_guid}", error=str(e))

        # Get app_bound_encrypted_key (post v127)
        app_bound_key_b64 = os_crypt.get("app_bound_encrypted_key")
        app_bound_key_enc = b""
        app_bound_key_system_masterkey_guid = None
        app_bound_key_user_masterkey_guid = None

        if app_bound_key_b64:
            logger.debug("Found v2 app bound key encrypted_key in Local State")
            app_bound_key_enc, app_bound_key_system_masterkey_guid = _parse_app_bound_key(app_bound_key_b64)
            logger.debug(f"app_bound_key_system_masterkey_guid: {app_bound_key_system_masterkey_guid}")

            drive = get_drive_from_path(file_enriched.path) or ""
            masterkey_path = (
                f"{drive}/Windows/System32/Microsoft/Protect/S-1-5-18/User/{app_bound_key_system_masterkey_guid}"
            )

            # Filename format: <hash>_<machineGuid>
            # Hash comes from Chromium calling NCryptOpenKey with the key name of "Google Chromekey1"
            # Hashing algorithm is described here: https://gist.github.com/leechristensen/40acb67ff5b788d6b78d81443b66b444
            cng_system_private_key_path = (
                f"{drive}/ProgramData/Microsoft/Crypto/SystemKeys/7096db7aeb75c0d3497ecd56d355a695_<WINDOWS_MACHINE_GUID>"
            )

            # add the masterkey file path (now that we know the key GUID) as a link/listing
            await add_file_linking(file_enriched.source, file_enriched.path, masterkey_path, "windows:system_masterkey")
            await add_file_linking(file_enriched.source, file_enriched.path, cng_system_private_key_path, "windows:cng_system_private_key - Contains Chrome key used to encrypt the Local State")

            try:
                # Parse only the DPAPI portion (after APPB header)
                if len(app_bound_key_enc) >= 4 and app_bound_key_enc[:4] == b"APPB":
                    dpapi_portion = app_bound_key_enc[4:]
                    # Step 1 - decrypt with a SYSTEM masterkey
                    app_bound_key_system_dec = await dpapi_manager.decrypt_blob(Blob.from_bytes(dpapi_portion))
                else:
                    logger.warning("App-bound key missing APPB header, cannot decrypt")
                    app_bound_key_system_dec = b""

                if app_bound_key_system_dec:
                    user_blob = Blob.from_bytes(app_bound_key_system_dec)
                    app_bound_key_user_masterkey_guid = str(user_blob.masterkey_guid)

                    try:
                        # Step 2 - decrypt with a _user_ masterkey
                        abe_blob_bytes = await dpapi_manager.decrypt_blob(user_blob)
                        if abe_blob_bytes:
                            # Store the intermediate value after USER key decryption
                            app_bound_key_user_dec = abe_blob_bytes

                            # Step 3 - parse and derive the final ABE key (using the Chromekey for v3)
                            abe_parsed = parse_abe_blob(abe_blob_bytes, chromekey)

                            if abe_parsed:
                                app_bound_key_dec = derive_abe_key(abe_parsed)

                                if app_bound_key_dec:
                                    app_bound_key_is_decrypted = True
                                    logger.debug(
                                        "Successfully derived ABE key",
                                        version=abe_parsed.get("version"),
                                        system_masterkey_guid=app_bound_key_system_masterkey_guid,
                                    )
                                else:
                                    raise Exception("Failed to derive ABE key")
                            else:
                                raise Exception("Failed to parse ABE blob")
                        else:
                            raise Exception("Failed to decrypt ABE blob with user masterkey")
                    except (MasterKeyNotFoundError, MasterKeyNotDecryptedError) as e:
                        logger.debug(
                            "ABE key not decrypted. Masterkey not found or not decrypted",
                            masterkey_guid=user_blob.masterkey_guid,
                            reason=type(e).__name__,
                        )

                        await _add_user_masterkey_link(file_enriched, username, user_blob.masterkey_guid)

                    except Exception as e:
                        logger.warning(f"Unable to decrypt/process final app bound key blob: {e}")

            except Exception as e:
                logger.warning(f"Unable to decrypt intermediate/outer app bound key blob: {e}")

        # Skip if no keys are present
        if not key_bytes_enc and not app_bound_key_enc:
            logger.warning("No encryption keys found in Local State file")
            return None

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
            "key_is_decrypted": key_is_decrypted,
            "app_bound_key_enc": app_bound_key_enc,
            "app_bound_key_system_masterkey_guid": app_bound_key_system_masterkey_guid,
            "app_bound_key_user_masterkey_guid": app_bound_key_user_masterkey_guid,
            "app_bound_key_system_dec": app_bound_key_system_dec,
            "app_bound_key_user_dec": app_bound_key_user_dec,
            "app_bound_key_dec": app_bound_key_dec,
            "app_bound_key_is_decrypted": app_bound_key_is_decrypted,
        }

        # Create a serializable copy for return (hex encode binary data)
        serializable_data = state_key_data.copy()
        for key, value in serializable_data.items():
            if isinstance(value, bytes):
                serializable_data[key] = value.hex()

        # Insert into PostgreSQL
        with pg_conn.cursor() as cur:
            insert_sql = """
                INSERT INTO chromium.state_keys
                (originating_object_id, agent_id, source, project, username, browser,
                 key_masterkey_guid, key_bytes_enc, key_bytes_dec, key_is_decrypted,
                 app_bound_key_enc, app_bound_key_system_masterkey_guid,
                 app_bound_key_user_masterkey_guid, app_bound_key_system_dec, app_bound_key_user_dec,
                 app_bound_key_dec, app_bound_key_is_decrypted)
                VALUES (%(originating_object_id)s, %(agent_id)s, %(source)s, %(project)s,
                        %(username)s, %(browser)s, %(key_masterkey_guid)s, %(key_bytes_enc)s,
                        %(key_bytes_dec)s, %(key_is_decrypted)s, %(app_bound_key_enc)s,
                        %(app_bound_key_system_masterkey_guid)s, %(app_bound_key_user_masterkey_guid)s,
                        %(app_bound_key_system_dec)s, %(app_bound_key_user_dec)s,
                        %(app_bound_key_dec)s, %(app_bound_key_is_decrypted)s)
                ON CONFLICT (source, username, browser)
                DO UPDATE SET
                    key_masterkey_guid = EXCLUDED.key_masterkey_guid,
                    key_bytes_enc = EXCLUDED.key_bytes_enc,
                    key_bytes_dec = EXCLUDED.key_bytes_dec,
                    key_is_decrypted = EXCLUDED.key_is_decrypted,
                    app_bound_key_enc = EXCLUDED.app_bound_key_enc,
                    app_bound_key_system_masterkey_guid = EXCLUDED.app_bound_key_system_masterkey_guid,
                    app_bound_key_user_masterkey_guid = EXCLUDED.app_bound_key_user_masterkey_guid,
                    app_bound_key_system_dec = EXCLUDED.app_bound_key_system_dec,
                    app_bound_key_user_dec = EXCLUDED.app_bound_key_user_dec,
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

        return serializable_data

    except json.JSONDecodeError as e:
        logger.exception("Failed to parse Local State JSON", error=str(e))
        raise
    except Exception as e:
        logger.exception("Error processing Local State", error=str(e))
        raise


async def retry_decrypt_state_key(state_key_id: int, dpapi_manager: DpapiManager, pg_conn) -> dict:
    """Attempt to decrypt a single state_key record using currently available masterkeys.

    Args:
        state_key_id: The ID of the state_key record to decrypt
        dpapi_manager: DpapiManager instance for decryption
        pg_conn: PostgreSQL connection

    Returns:
        Dict with decryption results: {
            "decrypted_v1": bool,
            "decrypted_abe_stage1": bool,
            "decrypted_abe_stage2": bool
        }
    """
    result = {
        "decrypted_v1": False,
        "decrypted_abe_stage1": False,
        "decrypted_abe_stage2": False,
    }

    # Fetch the state_key record
    with pg_conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, source, username, browser,
                   key_masterkey_guid, key_bytes_enc, key_bytes_dec, key_is_decrypted,
                   app_bound_key_enc, app_bound_key_system_masterkey_guid,
                   app_bound_key_user_masterkey_guid, app_bound_key_system_dec,
                   app_bound_key_user_dec, app_bound_key_dec, app_bound_key_is_decrypted
            FROM chromium.state_keys
            WHERE id = %s
            """,
            (state_key_id,),
        )
        row = cur.fetchone()

        if not row:
            logger.warning("State key not found", state_key_id=state_key_id)
            return result

        (
            record_id,
            source,
            username,
            browser,
            key_masterkey_guid,
            key_bytes_enc,
            key_bytes_dec,
            key_is_decrypted,
            app_bound_key_enc,
            app_bound_key_system_masterkey_guid,
            app_bound_key_user_masterkey_guid,
            app_bound_key_system_dec,
            app_bound_key_user_dec,
            app_bound_key_dec,
            app_bound_key_is_decrypted,
        ) = row

    # Try to decrypt pre-v127 encrypted_key
    if key_bytes_enc and len(key_bytes_enc) > 0 and not key_is_decrypted:
        try:
            # Remove DPAPI header (first 5 bytes)
            if len(key_bytes_enc) >= 5 and key_bytes_enc[:5] == b"DPAPI":
                dpapi_blob_bytes = key_bytes_enc[5:]

                dpapi_blob = Blob.from_bytes(dpapi_blob_bytes)
                try:
                    key_bytes_dec = await dpapi_manager.decrypt_blob(dpapi_blob)
                    if key_bytes_dec:
                        key_is_decrypted = True
                        result["decrypted_v1"] = True
                        logger.debug(
                            "Successfully decrypted v1 state key",
                            state_key_id=state_key_id,
                            masterkey_guid=dpapi_blob.masterkey_guid,
                        )

                        # Update database
                        with pg_conn.cursor() as cur:
                            cur.execute(
                                """
                                UPDATE chromium.state_keys
                                SET key_bytes_dec = %s, key_is_decrypted = %s,
                                    key_masterkey_guid = %s
                                WHERE id = %s
                                """,
                                (key_bytes_dec, key_is_decrypted, str(dpapi_blob.masterkey_guid), state_key_id),
                            )

                except (MasterKeyNotFoundError, MasterKeyNotDecryptedError):
                    # Masterkey still not available, skip silently
                    pass
                except Exception as e:
                    logger.warning("Error decrypting v1 state key", state_key_id=state_key_id, error=str(e))

        except Exception as e:
            logger.warning("Error processing v1 state key", state_key_id=state_key_id, error=str(e))

    # Try to decrypt post-v127 app_bound_encrypted_key
    if app_bound_key_enc and len(app_bound_key_enc) > 0:
        # Stage 1: Decrypt outer layer with SYSTEM masterkey
        if len(app_bound_key_system_dec) == 0:
            try:
                if len(app_bound_key_enc) >= 4 and app_bound_key_enc[:4] == b"APPB":
                    dpapi_portion = app_bound_key_enc[4:]
                    system_blob = Blob.from_bytes(dpapi_portion)
                    try:
                        app_bound_key_system_dec = await dpapi_manager.decrypt_blob(system_blob)
                        if app_bound_key_system_dec:
                            result["decrypted_abe_stage1"] = True
                            logger.debug(
                                "Successfully decrypted ABE stage 1 (SYSTEM key)",
                                state_key_id=state_key_id,
                                system_masterkey_guid=system_blob.masterkey_guid,
                            )

                            # Parse the intermediate blob to get user masterkey GUID
                            try:
                                user_blob = Blob.from_bytes(app_bound_key_system_dec)
                                app_bound_key_user_masterkey_guid = str(user_blob.masterkey_guid)
                            except Exception:
                                app_bound_key_user_masterkey_guid = None

                            # Update database with stage 1 results
                            with pg_conn.cursor() as cur:
                                cur.execute(
                                    """
                                    UPDATE chromium.state_keys
                                    SET app_bound_key_system_dec = %s,
                                        app_bound_key_system_masterkey_guid = %s,
                                        app_bound_key_user_masterkey_guid = %s
                                    WHERE id = %s
                                    """,
                                    (
                                        app_bound_key_system_dec,
                                        str(system_blob.masterkey_guid),
                                        app_bound_key_user_masterkey_guid,
                                        state_key_id,
                                    ),
                                )

                    except (MasterKeyNotFoundError, MasterKeyNotDecryptedError):
                        # SYSTEM masterkey still not available
                        pass
                    except Exception as e:
                        logger.warning("Error decrypting ABE stage 1", state_key_id=state_key_id, error=str(e))

            except Exception as e:
                logger.warning("Error processing ABE stage 1", state_key_id=state_key_id, error=str(e))

        # Stage 2: Decrypt inner layer with USER masterkey and derive final key
        if len(app_bound_key_system_dec) > 0 and not app_bound_key_is_decrypted:
            try:
                user_blob = Blob.from_bytes(app_bound_key_system_dec)
                try:
                    abe_blob_bytes = await dpapi_manager.decrypt_blob(user_blob)
                    if abe_blob_bytes:
                        # Store the intermediate value after USER key decryption
                        app_bound_key_user_dec = abe_blob_bytes

                        # Get chrome_key from database
                        chromekey = _get_chromekey_from_source(source, pg_conn)

                        # Always attempt to parse the ABE blob (works for v2 without chromekey)
                        abe_parsed = parse_abe_blob(abe_blob_bytes, chromekey)

                        if abe_parsed:
                            app_bound_key_dec = derive_abe_key(abe_parsed)
                            if app_bound_key_dec:
                                app_bound_key_is_decrypted = True
                                result["decrypted_abe_stage2"] = True
                                logger.debug(
                                    "Successfully decrypted ABE stage 2 (USER key + ABE derivation)",
                                    state_key_id=state_key_id,
                                    user_masterkey_guid=user_blob.masterkey_guid,
                                    abe_version=abe_parsed.get("version"),
                                )

                                # Update database with final key and intermediate user_dec
                                with pg_conn.cursor() as cur:
                                    cur.execute(
                                        """
                                        UPDATE chromium.state_keys
                                        SET app_bound_key_user_dec = %s,
                                            app_bound_key_dec = %s,
                                            app_bound_key_is_decrypted = %s,
                                            app_bound_key_user_masterkey_guid = %s
                                        WHERE id = %s
                                        """,
                                        (
                                            app_bound_key_user_dec,
                                            app_bound_key_dec,
                                            app_bound_key_is_decrypted,
                                            str(user_blob.masterkey_guid),
                                            state_key_id,
                                        ),
                                    )
                            else:
                                logger.warning("Failed to derive ABE key", state_key_id=state_key_id)
                                # Save the intermediate user_dec value for later retry
                                with pg_conn.cursor() as cur:
                                    cur.execute(
                                        """
                                        UPDATE chromium.state_keys
                                        SET app_bound_key_user_dec = %s,
                                            app_bound_key_user_masterkey_guid = %s
                                        WHERE id = %s
                                        """,
                                        (
                                            app_bound_key_user_dec,
                                            str(user_blob.masterkey_guid),
                                            state_key_id,
                                        ),
                                    )
                        else:
                            # Parsing failed - likely v3 waiting for chromekey
                            if chromekey is None:
                                logger.warning(
                                    "ABE parsing failed, likely v3 waiting for Chrome key",
                                    state_key_id=state_key_id,
                                    source=source,
                                )
                            else:
                                logger.warning("Failed to parse ABE blob", state_key_id=state_key_id)

                            # Save the intermediate user_dec value for later retry
                            with pg_conn.cursor() as cur:
                                cur.execute(
                                    """
                                    UPDATE chromium.state_keys
                                    SET app_bound_key_user_dec = %s,
                                        app_bound_key_user_masterkey_guid = %s
                                    WHERE id = %s
                                    """,
                                    (
                                        app_bound_key_user_dec,
                                        str(user_blob.masterkey_guid),
                                        state_key_id,
                                    ),
                                )

                except (MasterKeyNotFoundError, MasterKeyNotDecryptedError):
                    # USER masterkey still not available
                    pass
                except Exception as e:
                    logger.warning("Error decrypting ABE stage 2", state_key_id=state_key_id, error=str(e))

            except Exception as e:
                logger.warning("Error processing ABE stage 2", state_key_id=state_key_id, error=str(e))

    # If we made any progress, update linked logins and cookies
    if result["decrypted_v1"] or result["decrypted_abe_stage2"]:
        try:
            with pg_conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE chromium.logins
                    SET state_key_id = %s
                    WHERE source = %s AND username = %s AND browser = %s
                    AND state_key_id IS NULL
                    AND encryption_type IN ('key', 'abe')
                    """,
                    (state_key_id, source, username, browser),
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
                    (state_key_id, source, username, browser),
                )
                cookies_updated = cur.rowcount

                if logins_updated > 0 or cookies_updated > 0:
                    logger.info(
                        "Linked state key to existing logins/cookies",
                        state_key_id=state_key_id,
                        logins_updated=logins_updated,
                        cookies_updated=cookies_updated,
                    )

        except Exception as e:
            logger.warning("Error linking logins/cookies to state key", state_key_id=state_key_id, error=str(e))

    # Commit all changes
    pg_conn.commit()

    return result


async def retry_decrypt_state_keys_for_masterkey(
    masterkey_guid: UUID, dpapi_manager: DpapiManager, masterkey_type: str | None = None
) -> dict:
    """Find all state_keys waiting for this masterkey and try to decrypt them.

    Args:
        masterkey_guid: The GUID of the newly available masterkey
        dpapi_manager: DpapiManager instance for decryption
        masterkey_type: Optional masterkey type ('system', 'user', 'unknown') for optimization

    Returns:
        Dict with statistics: {
            "state_keys_attempted": int,
            "state_keys_progressed": int,
            "errors": list
        }
    """
    result = {"state_keys_attempted": 0, "state_keys_progressed": 0, "errors": []}

    conn_str = get_postgres_connection_str()

    try:
        with psycopg.connect(conn_str) as pg_conn:
            # Find all state_keys that might need this masterkey
            with pg_conn.cursor() as cur:
                # Build query based on masterkey type for optimization
                if masterkey_type == "system":
                    # SYSTEM keys only used for v2 ABE stage 1
                    query = """
                        SELECT DISTINCT id FROM chromium.state_keys
                        WHERE app_bound_key_system_masterkey_guid = %s
                        AND length(app_bound_key_system_dec) = 0
                    """
                    cur.execute(query, (str(masterkey_guid),))
                elif masterkey_type == "user":
                    # USER keys used for both v1 and v2 ABE stage 2
                    query = """
                        SELECT DISTINCT id FROM chromium.state_keys
                        WHERE (key_masterkey_guid = %s AND key_is_decrypted = FALSE)
                        OR (app_bound_key_user_masterkey_guid = %s AND app_bound_key_is_decrypted = FALSE)
                    """
                    cur.execute(query, (str(masterkey_guid), str(masterkey_guid)))
                else:
                    # Unknown type - check all possible uses
                    query = """
                        SELECT DISTINCT id FROM chromium.state_keys
                        WHERE (key_masterkey_guid = %s AND key_is_decrypted = FALSE)
                        OR (app_bound_key_system_masterkey_guid = %s AND length(app_bound_key_system_dec) = 0)
                        OR (app_bound_key_user_masterkey_guid = %s AND app_bound_key_is_decrypted = FALSE)
                    """
                    cur.execute(query, (str(masterkey_guid), str(masterkey_guid), str(masterkey_guid)))

                state_key_ids = [row[0] for row in cur.fetchall()]

            logger.debug(
                "Found state keys potentially waiting for masterkey",
                masterkey_guid=masterkey_guid,
                masterkey_type=masterkey_type,
                count=len(state_key_ids),
            )

            # Try to decrypt each state_key
            for state_key_id in state_key_ids:
                result["state_keys_attempted"] += 1
                try:
                    decrypt_result = await retry_decrypt_state_key(state_key_id, dpapi_manager, pg_conn)

                    # Check if any progress was made
                    if (
                        decrypt_result["decrypted_v1"]
                        or decrypt_result["decrypted_abe_stage1"]
                        or decrypt_result["decrypted_abe_stage2"]
                    ):
                        result["state_keys_progressed"] += 1

                except Exception as e:
                    error_msg = f"Error processing state_key {state_key_id}: {str(e)}"
                    logger.warning("Failed to retry decrypt state key", state_key_id=state_key_id, error=str(e))
                    result["errors"].append(error_msg)

            logger.debug(
                "Completed retroactive state_key decryption for masterkey",
                masterkey_guid=masterkey_guid,
                attempted=result["state_keys_attempted"],
                progressed=result["state_keys_progressed"],
                errors=len(result["errors"]),
            )

    except Exception as e:
        error_msg = f"Database error during retroactive decryption: {str(e)}"
        logger.exception("Error in retry_decrypt_state_keys_for_masterkey", masterkey_guid=masterkey_guid, error=str(e))
        result["errors"].append(error_msg)

    return result


async def retry_decrypt_state_keys_for_chromekey(source: str, chromekey: bytes) -> dict:
    """Find all state_keys from a source waiting for chromekey and try to decrypt them.

    This function handles v3 ABE decryption where the USER masterkey has already been
    applied (app_bound_key_user_dec is populated) but the chromekey is needed to
    complete the final derivation.

    Args:
        source: The source identifier (hostname) for the chromekey
        chromekey: The decrypted Chrome key bytes

    Returns:
        Dict with statistics: {
            "state_keys_attempted": int,
            "state_keys_decrypted": int,
            "errors": list
        }
    """
    result = {"state_keys_attempted": 0, "state_keys_decrypted": 0, "errors": []}

    conn_str = get_postgres_connection_str()

    try:
        with psycopg.connect(conn_str) as pg_conn:
            # Find all state_keys from this source that have user_dec but aren't fully decrypted
            with pg_conn.cursor() as cur:
                query = """
                    SELECT id, source, username, browser, app_bound_key_user_dec,
                           app_bound_key_user_masterkey_guid
                    FROM chromium.state_keys
                    WHERE source = %s
                    AND app_bound_key_is_decrypted = FALSE
                    AND app_bound_key_user_dec IS NOT NULL
                    AND length(app_bound_key_user_dec) > 0
                """
                cur.execute(query, (source,))
                state_keys = cur.fetchall()

            logger.debug(
                "Found state keys waiting for chromekey",
                source=source,
                count=len(state_keys),
            )

            # Try to decrypt each state_key with the chromekey
            for row in state_keys:
                state_key_id, source, username, browser, app_bound_key_user_dec, user_masterkey_guid = row
                result["state_keys_attempted"] += 1

                try:
                    # Parse and derive the final ABE key using the chromekey
                    abe_parsed = parse_abe_blob(app_bound_key_user_dec, chromekey)
                    logger.debug(
                        "[retry_decrypt_state_keys_for_chromekey] Parsed ABE blob",
                        state_key_id=state_key_id,
                        abe_parsed=abe_parsed,
                    )

                    if abe_parsed:
                        app_bound_key_dec = derive_abe_key(abe_parsed)
                        logger.debug(
                            "[retry_decrypt_state_keys_for_chromekey] Derived ABE key",
                            state_key_id=state_key_id,
                            success=bool(app_bound_key_dec),
                        )

                        if app_bound_key_dec:
                            # Update database with final decrypted key
                            with pg_conn.cursor() as cur:
                                cur.execute(
                                    """
                                    UPDATE chromium.state_keys
                                    SET app_bound_key_dec = %s,
                                        app_bound_key_is_decrypted = TRUE
                                    WHERE id = %s
                                    """,
                                    (app_bound_key_dec, state_key_id),
                                )

                                # Link to existing logins/cookies
                                cur.execute(
                                    """
                                    UPDATE chromium.logins
                                    SET state_key_id = %s
                                    WHERE source = %s AND username = %s AND browser = %s
                                    AND state_key_id IS NULL
                                    AND encryption_type IN ('key', 'abe')
                                    """,
                                    (state_key_id, source, username, browser),
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
                                    (state_key_id, source, username, browser),
                                )
                                cookies_updated = cur.rowcount

                            pg_conn.commit()
                            result["state_keys_decrypted"] += 1

                            logger.debug(
                                "Successfully decrypted ABE v3 with chromekey",
                                state_key_id=state_key_id,
                                source=source,
                                username=username,
                                browser=browser,
                                abe_version=abe_parsed.get("version"),
                                logins_updated=logins_updated,
                                cookies_updated=cookies_updated,
                            )
                        else:
                            logger.warning(
                                "Failed to derive ABE key with chromekey",
                                state_key_id=state_key_id,
                                source=source,
                            )
                    else:
                        logger.warning(
                            "Failed to parse ABE blob with chromekey",
                            state_key_id=state_key_id,
                            source=source,
                        )

                except Exception as e:
                    error_msg = f"Error processing state_key {state_key_id}: {str(e)}"
                    logger.warning(
                        "Failed to decrypt state key with chromekey",
                        state_key_id=state_key_id,
                        error=str(e),
                    )
                    result["errors"].append(error_msg)

            logger.warning(
                "Completed retroactive state_key decryption for chromekey",
                source=source,
                attempted=result["state_keys_attempted"],
                decrypted=result["state_keys_decrypted"],
                errors=len(result["errors"]),
            )

    except Exception as e:
        error_msg = f"Database error during retroactive chromekey decryption: {str(e)}"
        logger.exception("Error in retry_decrypt_state_keys_for_chromekey", source=source, error=str(e))
        result["errors"].append(error_msg)

    return result

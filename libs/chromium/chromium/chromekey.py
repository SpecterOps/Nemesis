"""Chrome Key and database operations."""

from uuid import UUID

import psycopg
from common.logger import get_logger
from file_enrichment_modules.cng_file.cng_parser import check_bcrypt_key_blob, extract_final_key_material
from nemesis_dpapi import Blob, DpapiManager, MasterKeyNotDecryptedError, MasterKeyNotFoundError

from .helpers import get_postgres_connection_str
from .local_state import retry_decrypt_state_keys_for_chromekey

logger = get_logger(__name__)


async def _retry_state_keys_for_chromekey_after_decrypt(source: str, chromekey: bytes):
    """Helper to retry state key decryption after a chromekey is decrypted.

    Import is done here to avoid circular dependency issues.
    """
    return await retry_decrypt_state_keys_for_chromekey(source, chromekey)


async def retry_decrypt_chrome_key(chrome_key_id: int, dpapi_manager: DpapiManager, pg_conn) -> dict:
    """Attempt to decrypt a single chrome_key record using currently available masterkeys.

    Args:
        chrome_key_id: The ID of the chrome_key record to decrypt
        dpapi_manager: DpapiManager instance for decryption
        pg_conn: PostgreSQL connection

    Returns:
        Dict with decryption results: {
            "decrypted": bool,
            "state_keys_result": dict (optional, if decryption succeeded)
        }
    """
    result = {"decrypted": False}
    cng_key_blob_entropy = b'xT5rZW5qVVbrvpuA\x00'

    # Fetch the chrome_key record
    with pg_conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, source, key_masterkey_guid, key_bytes_enc,
                   key_bytes_dec, key_is_decrypted
            FROM chromium.chrome_keys
            WHERE id = %s
            """,
            (chrome_key_id,),
        )
        row = cur.fetchone()

        if not row:
            logger.warning("Chrome key not found", chrome_key_id=chrome_key_id)
            return result

        (record_id, source, key_masterkey_guid, key_bytes_enc, key_bytes_dec, key_is_decrypted) = row

    # Skip if already decrypted
    if key_is_decrypted:
        return result

    # Try to decrypt the chrome key
    if key_bytes_enc and len(key_bytes_enc) > 0:
        try:
            dpapi_blob = Blob.from_bytes(key_bytes_enc)
            try:
                decrypted_blob = await dpapi_manager.decrypt_blob(dpapi_blob, entropy=cng_key_blob_entropy)
                if decrypted_blob:
                    # Check for BCRYPT_KEY_DATA_BLOB and log details
                    if check_bcrypt_key_blob(decrypted_blob):

                        # Extract the final 32-byte key material
                        key_bytes_dec = extract_final_key_material(decrypted_blob)

                        if key_bytes_dec:
                            key_is_decrypted = True
                            result["decrypted"] = True
                            logger.info(
                                "Successfully decrypted and extracted chrome_key material",
                                chrome_key_id=chrome_key_id,
                                masterkey_guid=dpapi_blob.masterkey_guid,
                            )

                            # Update database
                            with pg_conn.cursor() as cur:
                                cur.execute(
                                    """
                                    UPDATE chromium.chrome_keys
                                    SET key_bytes_dec = %s, key_is_decrypted = %s,
                                        key_masterkey_guid = %s
                                    WHERE id = %s
                                    """,
                                    (key_bytes_dec, key_is_decrypted, dpapi_blob.masterkey_guid, chrome_key_id),
                                )

                            # Commit the chrome_key update before trying state_keys
                            pg_conn.commit()

                            # Now try to decrypt any state_keys waiting for this chromekey
                            try:
                                state_keys_result = await _retry_state_keys_for_chromekey_after_decrypt(source, key_bytes_dec)
                                result["state_keys_result"] = state_keys_result
                                logger.info(
                                    "Completed retroactive state_key decryption for newly decrypted chromekey",
                                    chrome_key_id=chrome_key_id,
                                    source=source,
                                    state_keys_result=state_keys_result,
                                )
                            except Exception as e:
                                logger.warning(
                                    "Error retrying state_keys after chromekey decryption",
                                    chrome_key_id=chrome_key_id,
                                    source=source,
                                    error=str(e),
                                )
                        else:
                            logger.warning(
                                "Failed to extract final key material from decrypted chrome_key",
                                chrome_key_id=chrome_key_id,
                            )

            except (MasterKeyNotFoundError, MasterKeyNotDecryptedError):
                # Masterkey still not available, skip silently
                pass
            except Exception as e:
                logger.warning("Error decrypting chrome_key", chrome_key_id=chrome_key_id, error=str(e))

        except Exception as e:
            logger.warning("Error processing chrome_key", chrome_key_id=chrome_key_id, error=str(e))
    else:
        # Commit even if no decryption happened (for consistency)
        pg_conn.commit()

    return result


async def retry_decrypt_chrome_keys_for_masterkey(
    masterkey_guid: UUID, dpapi_manager: DpapiManager, masterkey_type: str | None = None
) -> dict:
    """Find all chrome_keys waiting for this masterkey and try to decrypt them.

    Args:
        masterkey_guid: The GUID of the newly available masterkey
        dpapi_manager: DpapiManager instance for decryption
        masterkey_type: Optional masterkey type ('system', 'user', 'unknown') for optimization

    Returns:
        Dict with statistics: {
            "chrome_keys_attempted": int,
            "chrome_keys_decrypted": int,
            "errors": list
        }
    """
    result = {"chrome_keys_attempted": 0, "chrome_keys_decrypted": 0, "errors": []}

    # Chrome keys only use SYSTEM masterkeys, so skip if this is a USER key
    if masterkey_type == "user":
        logger.debug(
            "Skipping chrome_key decryption for USER masterkey",
            masterkey_guid=masterkey_guid,
            masterkey_type=masterkey_type,
        )
        return result

    conn_str = get_postgres_connection_str()

    try:
        with psycopg.connect(conn_str) as pg_conn:
            # Find all chrome_keys that might need this masterkey
            with pg_conn.cursor() as cur:
                # SYSTEM keys are used for chrome_keys, but if type is unknown, still try
                query = """
                    SELECT DISTINCT id FROM chromium.chrome_keys
                    WHERE key_masterkey_guid = %s AND key_is_decrypted = FALSE
                """
                cur.execute(query, (masterkey_guid,))

                chrome_key_ids = [row[0] for row in cur.fetchall()]

            logger.debug(
                "Found chrome_keys potentially waiting for masterkey",
                masterkey_guid=masterkey_guid,
                masterkey_type=masterkey_type,
                count=len(chrome_key_ids),
            )

            # Try to decrypt each chrome_key
            for chrome_key_id in chrome_key_ids:
                result["chrome_keys_attempted"] += 1
                try:
                    decrypt_result = await retry_decrypt_chrome_key(chrome_key_id, dpapi_manager, pg_conn)

                    # Check if decryption succeeded
                    if decrypt_result["decrypted"]:
                        result["chrome_keys_decrypted"] += 1

                except Exception as e:
                    error_msg = f"Error processing chrome_key {chrome_key_id}: {str(e)}"
                    logger.warning("Failed to retry decrypt chrome_key", chrome_key_id=chrome_key_id, error=str(e))
                    result["errors"].append(error_msg)

            logger.info(
                "Completed retroactive chrome_key decryption for masterkey",
                masterkey_guid=masterkey_guid,
                attempted=result["chrome_keys_attempted"],
                decrypted=result["chrome_keys_decrypted"],
                errors=len(result["errors"]),
            )

    except Exception as e:
        error_msg = f"Database error during retroactive chrome_key decryption: {str(e)}"
        logger.exception(
            "Error in retry_decrypt_chrome_keys_for_masterkey", masterkey_guid=masterkey_guid, error=str(e)
        )
        result["errors"].append(error_msg)

    return result

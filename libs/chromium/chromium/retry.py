"""Retry decryption logic for Chromium cookies and logins."""

from uuid import UUID

import asyncpg
from common.logger import get_logger
from nemesis_dpapi import Blob, DpapiManager, MasterKeyNotDecryptedError, MasterKeyNotFoundError

from .helpers import decrypt_chrome_string, get_state_key_bytes

logger = get_logger(__name__)


async def retry_decrypt_chromium_data(
    masterkey_guid: UUID, dpapi_manager: DpapiManager, asyncpg_pool: asyncpg.Pool, masterkey_type: str | None = None
) -> dict:
    """Retry decrypting cookies and logins that failed to decrypt previously.

    When a new masterkey becomes available, this function:
    1. Retries DPAPI-encrypted cookies/logins that use this masterkey
    2. Retries key/abe-encrypted cookies/logins (state keys may now be decrypted)

    Args:
        masterkey_guid: The GUID of the newly available masterkey
        dpapi_manager: DpapiManager instance for decryption
        asyncpg_pool: Async Postgres connection pool
        masterkey_type: Optional masterkey type ('system', 'user', 'unknown')

    Returns:
        Dict with statistics: {
            "cookies_attempted": int,
            "cookies_decrypted": int,
            "logins_attempted": int,
            "logins_decrypted": int,
            "errors": list
        }
    """
    result = {
        "cookies_attempted": 0,
        "cookies_decrypted": 0,
        "logins_attempted": 0,
        "logins_decrypted": 0,
        "errors": [],
    }

    try:
        # Retry cookies
        cookies_result = await _retry_decrypt_cookies(masterkey_guid, dpapi_manager, asyncpg_pool)
        result["cookies_attempted"] = cookies_result["attempted"]
        result["cookies_decrypted"] = cookies_result["decrypted"]
        result["errors"].extend(cookies_result["errors"])

        # Retry logins
        logins_result = await _retry_decrypt_logins(masterkey_guid, dpapi_manager, asyncpg_pool)
        result["logins_attempted"] = logins_result["attempted"]
        result["logins_decrypted"] = logins_result["decrypted"]
        result["errors"].extend(logins_result["errors"])

        logger.warning(
            "Completed retroactive chromium data decryption for masterkey",
            masterkey_guid=masterkey_guid,
            cookies_attempted=result["cookies_attempted"],
            cookies_decrypted=result["cookies_decrypted"],
            logins_attempted=result["logins_attempted"],
            logins_decrypted=result["logins_decrypted"],
            errors=len(result["errors"]),
        )

    except Exception as e:
        error_msg = f"Database error during retroactive chromium data decryption: {str(e)}"
        logger.exception("Error in retry_decrypt_chromium_data", masterkey_guid=masterkey_guid, error=str(e))
        result["errors"].append(error_msg)

    return result


async def _retry_decrypt_cookies(masterkey_guid: UUID, dpapi_manager: DpapiManager, asyncpg_pool: asyncpg.Pool) -> dict:
    """Retry decrypting cookies that previously failed.

    Args:
        masterkey_guid: The GUID of the newly available masterkey
        dpapi_manager: DpapiManager instance for decryption
        asyncpg_pool: Async Postgres connection pool

    Returns:
        Dict with {"attempted": int, "decrypted": int, "errors": list}
    """
    result = {"attempted": 0, "decrypted": 0, "errors": []}

    # Find all undecrypted cookies
    # For DPAPI: only those matching this masterkey
    # For key/abe: all undecrypted (state keys may now be available)
    async with asyncpg_pool.acquire() as conn:
        cookies = await conn.fetch(
            """
            SELECT id, encryption_type, masterkey_guid, state_key_id,
                   value_enc, source, username, browser
            FROM chromium.cookies
            WHERE is_decrypted = FALSE
            AND (
                (encryption_type = 'dpapi' AND masterkey_guid = $1)
                OR encryption_type IN ('key', 'abe')
            )
            """,
            str(masterkey_guid)
        )

    logger.debug(
        "Found undecrypted cookies to retry",
        masterkey_guid=masterkey_guid,
        count=len(cookies),
    )

    for cookie in cookies:
        result["attempted"] += 1
        cookie_id = cookie['id']
        encryption_type = cookie['encryption_type']
        cookie_masterkey_guid = cookie['masterkey_guid']
        state_key_id = cookie['state_key_id']
        value_enc = cookie['value_enc']
        source = cookie['source']
        username = cookie['username']
        browser = cookie['browser']

        try:
            value_dec = None
            decrypted = False

            # Try DPAPI decryption
            if encryption_type == "dpapi" and cookie_masterkey_guid == str(masterkey_guid):
                try:
                    value_dec_bytes = await dpapi_manager.decrypt_blob(Blob.from_bytes(value_enc))
                    if value_dec_bytes:
                        value_dec = value_dec_bytes.decode("utf-8", errors="replace")
                        decrypted = True
                        logger.debug("Successfully decrypted cookie with DPAPI", cookie_id=cookie_id)
                except (MasterKeyNotFoundError, MasterKeyNotDecryptedError):
                    # Still not available
                    pass
                except Exception as e:
                    logger.warning("Error decrypting cookie with DPAPI", cookie_id=cookie_id, error=str(e))

            # Try state key decryption (key/abe)
            elif encryption_type in ["key", "abe"]:
                # Try with existing state_key_id if available
                if state_key_id:
                    state_key_bytes = await get_state_key_bytes(state_key_id, encryption_type, asyncpg_pool)
                    if state_key_bytes:
                        try:
                            value_dec_bytes = decrypt_chrome_string(value_enc, state_key_bytes, encryption_type)
                            if value_dec_bytes:
                                # Apply offset handling for cookies
                                if encryption_type == "abe" and len(value_dec_bytes) > 32:
                                    value_dec_bytes = value_dec_bytes[32:]
                                elif encryption_type == "key" and len(value_dec_bytes) > 48:
                                    value_dec_bytes = value_dec_bytes[32:-16]
                                elif encryption_type == "key" and len(value_dec_bytes) > 16:
                                    value_dec_bytes = value_dec_bytes[:-16]

                                value_dec = value_dec_bytes.decode("utf-8", errors="replace")
                                decrypted = True
                                logger.debug(
                                    "Successfully decrypted cookie with state key",
                                    cookie_id=cookie_id,
                                    state_key_id=state_key_id,
                                )
                        except Exception as e:
                            logger.debug(
                                "Failed to decrypt cookie with state key",
                                cookie_id=cookie_id,
                                state_key_id=state_key_id,
                                error=str(e),
                            )

                # If no state_key_id or decryption failed, try to find matching state key
                if not decrypted and username and browser:
                    try:
                        async with asyncpg_pool.acquire() as conn:
                            # Try to find a decrypted state key for this source/username/browser
                            state_key_row = await conn.fetchrow(
                                """
                                SELECT id FROM chromium.state_keys
                                WHERE source = $1 AND username = $2 AND browser = $3
                                AND (
                                    (key_is_decrypted = TRUE AND $4 = 'key')
                                    OR (app_bound_key_is_decrypted = TRUE AND $5 = 'abe')
                                )
                                """,
                                source, username, browser, encryption_type, encryption_type
                            )
                            if state_key_row:
                                new_state_key_id = state_key_row['id']
                                state_key_bytes = await get_state_key_bytes(new_state_key_id, encryption_type, asyncpg_pool)
                                if state_key_bytes:
                                    try:
                                        value_dec_bytes = decrypt_chrome_string(
                                            value_enc, state_key_bytes, encryption_type
                                        )
                                        if value_dec_bytes:
                                            # Apply offset handling
                                            if encryption_type == "abe" and len(value_dec_bytes) > 32:
                                                value_dec_bytes = value_dec_bytes[32:]
                                            elif encryption_type == "key" and len(value_dec_bytes) > 48:
                                                value_dec_bytes = value_dec_bytes[32:-16]
                                            elif encryption_type == "key" and len(value_dec_bytes) > 16:
                                                value_dec_bytes = value_dec_bytes[:-16]

                                            value_dec = value_dec_bytes.decode("utf-8", errors="replace")
                                            decrypted = True
                                            state_key_id = new_state_key_id
                                            logger.debug(
                                                "Successfully decrypted cookie with newly found state key",
                                                cookie_id=cookie_id,
                                                state_key_id=new_state_key_id,
                                            )
                                    except Exception as e:
                                        logger.debug(
                                            "Failed to decrypt cookie with newly found state key",
                                            cookie_id=cookie_id,
                                            error=str(e),
                                        )
                    except Exception as e:
                        logger.debug("Error looking up state key for cookie", cookie_id=cookie_id, error=str(e))

            # Update database if decrypted
            if decrypted and value_dec:
                async with asyncpg_pool.acquire() as conn:
                    await conn.execute(
                        """
                        UPDATE chromium.cookies
                        SET value_dec = $1, is_decrypted = TRUE, state_key_id = $2
                        WHERE id = $3
                        """,
                        value_dec, state_key_id, cookie_id
                    )
                result["decrypted"] += 1

        except Exception as e:
            error_msg = f"Error processing cookie {cookie_id}: {str(e)}"
            logger.warning("Failed to retry decrypt cookie", cookie_id=cookie_id, error=str(e))
            result["errors"].append(error_msg)

    return result


async def _retry_decrypt_logins(masterkey_guid: UUID, dpapi_manager: DpapiManager, asyncpg_pool: asyncpg.Pool) -> dict:
    """Retry decrypting logins that previously failed.

    Args:
        masterkey_guid: The GUID of the newly available masterkey
        dpapi_manager: DpapiManager instance for decryption
        asyncpg_pool: Async Postgres connection pool

    Returns:
        Dict with {"attempted": int, "decrypted": int, "errors": list}
    """
    result = {"attempted": 0, "decrypted": 0, "errors": []}

    # Find all undecrypted logins
    async with asyncpg_pool.acquire() as conn:
        logins = await conn.fetch(
            """
            SELECT id, encryption_type, masterkey_guid, state_key_id,
                   password_value_enc, source, username, browser
            FROM chromium.logins
            WHERE is_decrypted = FALSE
            AND (
                (encryption_type = 'dpapi' AND masterkey_guid = $1)
                OR encryption_type IN ('key', 'abe')
            )
            """,
            str(masterkey_guid)
        )

    logger.debug(
        "Found undecrypted logins to retry",
        masterkey_guid=masterkey_guid,
        count=len(logins),
    )

    for login in logins:
        result["attempted"] += 1
        login_id = login['id']
        encryption_type = login['encryption_type']
        login_masterkey_guid = login['masterkey_guid']
        state_key_id = login['state_key_id']
        password_value_enc = login['password_value_enc']
        source = login['source']
        username = login['username']
        browser = login['browser']

        try:
            password_dec = None
            decrypted = False

            # Try DPAPI decryption
            if encryption_type == "dpapi" and login_masterkey_guid == str(masterkey_guid):
                try:
                    password_dec_bytes = await dpapi_manager.decrypt_blob(Blob.from_bytes(password_value_enc))
                    if password_dec_bytes:
                        password_dec = password_dec_bytes.decode("utf-8", errors="replace")
                        decrypted = True
                        logger.debug("Successfully decrypted login with DPAPI", login_id=login_id)
                except (MasterKeyNotFoundError, MasterKeyNotDecryptedError):
                    # Still not available
                    pass
                except Exception as e:
                    logger.warning("Error decrypting login with DPAPI", login_id=login_id, error=str(e))

            # Try state key decryption (key/abe)
            elif encryption_type in ["key", "abe"]:
                # Try with existing state_key_id if available
                if state_key_id:
                    state_key_bytes = await get_state_key_bytes(state_key_id, encryption_type, asyncpg_pool)
                    if state_key_bytes:
                        try:
                            password_dec_bytes = decrypt_chrome_string(
                                password_value_enc, state_key_bytes, encryption_type
                            )
                            if password_dec_bytes:
                                # Apply offset handling for passwords
                                if encryption_type == "key" and len(password_dec_bytes) > 32:
                                    password_dec_bytes = password_dec_bytes[32:-16]
                                elif encryption_type == "key" and len(password_dec_bytes) > 16:
                                    password_dec_bytes = password_dec_bytes[:-16]
                                # v20 passwords typically don't have offset like cookies

                                password_dec = password_dec_bytes.decode("utf-8", errors="replace")
                                decrypted = True
                                logger.debug(
                                    "Successfully decrypted login with state key",
                                    login_id=login_id,
                                    state_key_id=state_key_id,
                                )
                        except Exception as e:
                            logger.debug(
                                "Failed to decrypt login with state key",
                                login_id=login_id,
                                state_key_id=state_key_id,
                                error=str(e),
                            )

                # If no state_key_id or decryption failed, try to find matching state key
                if not decrypted and source:
                    try:
                        async with asyncpg_pool.acquire() as conn:
                            if username and browser:
                                # Try to find a decrypted state key for this source/username/browser
                                state_key_row = await conn.fetchrow(
                                    """
                                    SELECT id FROM chromium.state_keys
                                    WHERE source = $1 AND username = $2 AND browser = $3
                                    AND (
                                        (key_is_decrypted = TRUE AND $4 = 'key')
                                        OR (app_bound_key_is_decrypted = TRUE AND $5 = 'abe')
                                    )
                                    """,
                                    source, username, browser, encryption_type, encryption_type
                                )
                            else:
                                # if no username/password, just restrict to SOURCE
                                state_key_row = await conn.fetchrow(
                                    """
                                    SELECT id FROM chromium.state_keys
                                    WHERE source = $1
                                    AND (
                                        (key_is_decrypted = TRUE AND $2 = 'key')
                                        OR (app_bound_key_is_decrypted = TRUE AND $3 = 'abe')
                                    )
                                    """,
                                    source, encryption_type, encryption_type
                                )
                            if state_key_row:
                                new_state_key_id = state_key_row['id']
                                state_key_bytes = await get_state_key_bytes(new_state_key_id, encryption_type, asyncpg_pool)
                                if state_key_bytes:
                                    try:
                                        password_dec_bytes = decrypt_chrome_string(
                                            password_value_enc, state_key_bytes, encryption_type
                                        )
                                        if password_dec_bytes:
                                            # Apply offset handling
                                            if encryption_type == "key" and len(password_dec_bytes) > 32:
                                                password_dec_bytes = password_dec_bytes[32:-16]
                                            elif encryption_type == "key" and len(password_dec_bytes) > 16:
                                                password_dec_bytes = password_dec_bytes[:-16]

                                            password_dec = password_dec_bytes.decode("utf-8", errors="replace")
                                            decrypted = True
                                            state_key_id = new_state_key_id
                                            logger.debug(
                                                "Successfully decrypted login with newly found state key",
                                                login_id=login_id,
                                                state_key_id=new_state_key_id,
                                            )
                                    except Exception as e:
                                        logger.debug(
                                            "Failed to decrypt login with newly found state key",
                                            login_id=login_id,
                                            error=str(e),
                                        )
                    except Exception as e:
                        logger.debug("Error looking up state key for login", login_id=login_id, error=str(e))

            # Update database if decrypted
            if decrypted and password_dec:
                async with asyncpg_pool.acquire() as conn:
                    await conn.execute(
                        """
                        UPDATE chromium.logins
                        SET password_value_dec = $1, is_decrypted = TRUE, state_key_id = $2
                        WHERE id = $3
                        """,
                        password_dec, state_key_id, login_id
                    )
                result["decrypted"] += 1

        except Exception as e:
            error_msg = f"Error processing login {login_id}: {str(e)}"
            logger.warning("Failed to retry decrypt login", login_id=login_id, error=str(e))
            result["errors"].append(error_msg)

    return result

"""DPAPI credential submission routes."""

import asyncio
import base64
import logging
import re
import asyncpg
import urllib.parse
from typing import Annotated
from uuid import UUID

from chromium import (
    retry_decrypt_chrome_keys_for_masterkey,
    retry_decrypt_chromium_data,
    retry_decrypt_state_keys_for_masterkey,
)
from common.logger import get_logger
from file_enrichment import global_vars
from common.models2.dpapi import (
    ChromiumAppBoundKeyCredential,
    DomainBackupKeyCredential,
    DpapiCredentialRequest,
    DpapiSystemCredentialRequest,
    MasterKeyGuidPairList,
    NtlmHashCredentialKey,
    PasswordCredentialKey,
    Pbkdf2StrongCredentialKey,
    Sha1CredentialKey,
)
from Crypto.Hash import SHA1
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from nemesis_dpapi import (
    DomainBackupKey,
    DpapiManager,
    DpapiSystemCredential,
    MasterKey,
    MasterKeyType,
    NtlmHash,
    Password,
    Pbkdf2Hash,
    Sha1Hash,
)
from nemesis_dpapi.eventing import (
    DpapiEvent,
    DpapiObserver,
    NewPlaintextMasterKeyEvent,
)
from nemesis_dpapi.masterkey_decryptor import MasterKeyDecryptorService

logging.getLogger("nemesis_dpapi.eventing").setLevel(logging.DEBUG)
logging.getLogger("nemesis_dpapi.manager").setLevel(logging.DEBUG)
logger = get_logger(__name__)


class PlaintextMasterKeyMonitor(DpapiObserver):
    """Observer that monitors for new plaintext masterkeys."""

    def __init__(self, dpapi_manager: DpapiManager):
        """Initialize the monitor with a reference to the DpapiManager."""
        self.dpapi_manager = dpapi_manager

    async def update(self, evnt: DpapiEvent) -> None:
        """Called when a DPAPI event occurs."""
        if isinstance(evnt, NewPlaintextMasterKeyEvent):
            logger.info(
                "New plaintext masterkey detected, checking for state_keys to decrypt",
                event_type=type(evnt).__name__,
                masterkey_guid=evnt.masterkey_guid,
            )

            # Get the masterkey to check its type
            masterkeys = await self.dpapi_manager.get_masterkeys(guid=evnt.masterkey_guid)
            masterkey_type = masterkeys[0].masterkey_type.value if masterkeys else None

            # Try to decrypt chrome_keys with this masterkey
            chrome_key_result = await retry_decrypt_chrome_keys_for_masterkey(
                evnt.masterkey_guid,
                self.dpapi_manager,
                global_vars.asyncpg_pool,
                masterkey_type,
            )

            logger.debug(
                "Completed retroactive chrome_key decryption",
                masterkey_guid=evnt.masterkey_guid,
                masterkey_type=masterkey_type,
                result=chrome_key_result,
            )

            # Then try to decrypt any state keys with this masterkey
            result = await retry_decrypt_state_keys_for_masterkey(
                evnt.masterkey_guid,
                self.dpapi_manager,
                global_vars.asyncpg_pool,
                masterkey_type,
            )

            logger.debug(
                "Completed retroactive state_key decryption",
                masterkey_guid=evnt.masterkey_guid,
                masterkey_type=masterkey_type,
                result=result,
            )

            if result and result["state_keys_progressed"] > 0:
                # Finally, try to decrypt chromium cookies and logins with newly available keys
                chromium_data_result = await retry_decrypt_chromium_data(
                    evnt.masterkey_guid,
                    self.dpapi_manager,
                    global_vars.asyncpg_pool,
                    masterkey_type,
                )

                logger.debug(
                    "Completed retroactive chromium data decryption",
                    masterkey_guid=evnt.masterkey_guid,
                    masterkey_type=masterkey_type,
                    result=chromium_data_result,
                )


def get_event_loop(request: Request):
    return request.app.state.event_loop


AsyncLoopDep = Annotated[asyncio.AbstractEventLoop, Depends(get_event_loop)]


async def get_dpapi_manager(request: Request):
    """Dependency that returns the global DpapiManager instance."""
    manager = request.app.state.dpapi_manager
    if manager is None:
        raise RuntimeError("DpapiManager not initialized")
    return manager


DpapiManagerDep = Annotated[DpapiManager, Depends(get_dpapi_manager)]


async def get_masterkey_decryptor(dpapi_manager: DpapiManagerDep) -> MasterKeyDecryptorService:
    return MasterKeyDecryptorService(dpapi_manager)


MasterKeyDecryptorDep = Annotated[MasterKeyDecryptorService, Depends(get_masterkey_decryptor)]


async def dpapi_background_monitor(dpapi_manager: DpapiManager) -> None:
    logger.info("Starting DPAPI background monitor task")

    monitor = PlaintextMasterKeyMonitor(dpapi_manager)
    logger.info("Subscribing PlaintextMasterKeyMonitor to DPAPI events")
    await dpapi_manager.subscribe(monitor)

    # Add some sample masterkeys for testing
    # for i in range(64):
    #     logger.info(f"Adding sample masterkey {i + 1}/64")

    #     try:
    #         await dpapi_manager.upsert_masterkey(
    #             MasterKey(
    #                 guid=UUID(f"ed93694f-5a6d-46e2-b821-219f2c0ecd{i:02x}"),
    #                 encrypted_key_usercred=bytes.fromhex(
    #                     "02000000978d9c959a6a9685a55270cb4fc103d7401f00000e800000106600004b7ee6c2475c4519f48a68c7bc81acb70c63aa1ded8014fd313a4787cd7e1306191d004f6a61e85524222a18ba71f97e1bd83c12ca4ce95054394f7c33c42bc6fddd26f2109e4afb404ca9fb96c6212cf5fda0243eafda0eabbd28002264f9d707e00996a682c30ca6749fb251c8a4c4182157aed0407560cd5b7d3368b59541a0bc13dc8ee141625961edde82bf693a"
    #                 ),
    #                 encrypted_key_backup=bytes.fromhex(
    #                     "030000000001000090000000b151fa7e2325bf45acba2e15ecf4f1e7e20013019258acb6211540f5f8ed8c28d92dd09193ded077fe346386d06169d8d1a65b7d2ecc3264bca5ebae538efa74f8f4b99ec10fe0228daec5481c9c6132f3b2208e870dd0e0d6ee83450a255f588b5608f71978a66f5b4af640a5ffd456f51a36bd65468b8875eb73197db364417c3c6e599fede47b247f3067c5bff4ddd6c7ef9d8e3837b32c206d19d129fb4f666203fabfeb3356a19ed1c56597896c829a7148bac8cfe4ed40ee85c07436e1a73bdee3a379fec54714020bb069ba5a9e607c6323fcb9766a123772c832981610b5acc2e304fa5fe4789355dadd9f2765439e54d47cd187d66031bd9da07b82a8e17d430d87798bebbea80e0a60ac74132f05f592cec0c0e30e927c08a680740e7b27e7593daa59be3e0663c550f204cbc4e5248583fff4fd8489fb01a78ed17ba0b6857b1c800904666263987c8e7613f68cf44ba8807bddd36fa04932bf66e48663b6cb1c4fa5c1ac4875dccb52e4fc73f3a61b14cb5c764989050c480d70112583c519bcfbc5df83281d4da111a4e192d9b48cc8c7e0a1d0ac73f6df2d90"
    #                 ),
    #             )
    #         )

    #         await dpapi_manager.upsert_masterkey(
    #             MasterKey(
    #                 guid=UUID(f"dd26f81a-4ed9-49fd-8b45-42723d8ae0{i:02x}"),
    #                 encrypted_key_usercred=b'\x02\x00\x00\x00\xbd*N\x8a\x1ff\xc1\xc2\x9d\x97*\xd3%4\xa8\x01@\x1f\x00\x00\x0e\x80\x00\x00\x10f\x00\x00\xa6\xfd\xdb\xe7N+\x89u\xfe\x89l\x07[\xeea\xc5\xae\xe3\x11+5\xab\xc3\x9f\x96\xd8"\x9b<:\xfe\x92\xf9\xc1\xdb\x12B\xed\xcb\x84\xffa\xbc<p\xf9U\xe7=\x99\xb6\xc1\xad\xbc\x1c\x8d%\x8a*\xfdU\xd5S\xc4\x85\xee\xaeu\x15U,\xe7\x80Z\xf7\x84\xb9\xc0.|\xc3\xdc}\xacV\xfa\x8f\xa5\x9fa\xeb\xb7\xf4\xad\x03x\xad\xe2\xf6\xe4V\xdbf+\xa2\xba8D\x1eT,\x07\x1a*`\xaa\x17\x985\xa9\x0e\xb1\xf1o\xa2\x05x\x08s\x197\xb2\xc4\xeb0\xdb+\x1c\xee\x02\xff\xf0R)',
    #             )
    #         )
    #     except Exception as e:
    #         logger.error(f"Error adding sample masterkey {i + 1}/256: {e}")

    logger.info("Entering DPAPI background monitor loop")
    while True:
        try:
            num_masterkeys = await dpapi_manager.get_masterkeys()
            num_dec_masterkeys = len([mk for mk in num_masterkeys if mk.is_decrypted])
            num_enc_masterkeys = len([mk for mk in num_masterkeys if not mk.is_decrypted])
            backupkeys = await dpapi_manager.get_backup_keys()
            num_system_creds = await dpapi_manager.get_system_credentials()
            logger.info(
                "Background DPAPI loop tick",
                total_mks=len(num_masterkeys),
                num_enc_mks=num_enc_masterkeys,
                num_dec_mks=num_dec_masterkeys,
                num_backup_keys=len(backupkeys),
                num_system_creds=len(num_system_creds),
            )
        except Exception as e:
            logger.exception("Error in DPAPI background monitor", error=str(e))

        await asyncio.sleep(5)


# Create the router directly - no prefix to maintain original URLs
dpapi_router = APIRouter(tags=["dpapi"])


@dpapi_router.post("/dpapi/credentials")
async def submit_dpapi_credential(
    dpapi_manager: DpapiManagerDep,
    decryptor: MasterKeyDecryptorDep,
    request: DpapiCredentialRequest = Body(..., description="The DPAPI credential data"),
):
    """Submit DPAPI credential for masterkey decryption."""
    try:
        has_user_sid = hasattr(request, "user_sid")
        logger.info("Received DPAPI credential submission", credential_type=request.type, has_user_sid=has_user_sid)

        try:
            if isinstance(request, DomainBackupKeyCredential):
                result = await _handle_domain_backup_key_credential(dpapi_manager, request)
            elif isinstance(request, MasterKeyGuidPairList):
                result = await _handle_master_key_guid_pairs(dpapi_manager, request)
            elif isinstance(request, DpapiSystemCredentialRequest):
                result = await _handle_dpapi_system_credential(dpapi_manager, request)
            elif isinstance(request, ChromiumAppBoundKeyCredential):
                result = await _handle_chromium_app_bound_key(dpapi_manager, request)
            elif isinstance(
                request, (PasswordCredentialKey, NtlmHashCredentialKey, Sha1CredentialKey, Pbkdf2StrongCredentialKey)
            ):
                result = await _handle_password_based_credential(decryptor, request)
            else:
                raise HTTPException(status_code=400, detail=f"Unsupported credential type: {request.type}")

            logger.info("Successfully processed DPAPI credential", credential_type=request.type, result=result)
            return {
                "status": "success" if result.get("status") == "success" else "partial",
                "message": f"Processed {request.type} credential"
                + (f": {result.get('message', '')}" if result.get("message") else ""),
                "result": result,
            }

        except ValueError as e:
            logger.error("Invalid credential format", credential_type=request.type, error=str(e))
            raise HTTPException(status_code=400, detail=f"Invalid credential format: {str(e)}") from e

        except Exception as e:
            logger.exception("Error processing DPAPI credential", credential_type=request.type, error=str(e))
            raise HTTPException(status_code=500, detail=f"Error processing credential: {str(e)}") from e

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error in DPAPI credential submission", error=str(e))
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}") from e


async def _handle_domain_backup_key_credential(
    dpapi_manager: DpapiManager, backup_key: DomainBackupKeyCredential
) -> dict:
    """Handle domain backup key credential submission."""

    # Decode URL encoded value for string-based credentials
    credential_value = urllib.parse.unquote(backup_key.value)
    pvk_data = base64.b64decode(credential_value, validate=True)
    backup_key_obj = DomainBackupKey(
        guid=UUID(backup_key.guid),  # Use the provided GUID
        key_data=pvk_data,
        domain_controller=backup_key.domain_controller,
    )
    backup_key_id = await dpapi_manager.upsert_domain_backup_key(backup_key_obj)
    return {"status": "success", "type": "domain_backup_key", "id": backup_key_id}


async def _handle_master_key_guid_pairs(dpapi_manager: DpapiManager, request: MasterKeyGuidPairList) -> dict:
    """Handle decrypted master key credential submission."""

    processed_guids = []
    existing_guids = []

    # Process each master key data entry
    for master_key_data in request.value:
        # Extract strongly typed master key data
        masterkey_guid = master_key_data.guid
        masterkey_data = bytes.fromhex(master_key_data.key_hex)

        # Check if masterkey already exists
        existing_masterkeys = await dpapi_manager.get_masterkeys(guid=masterkey_guid)
        if existing_masterkeys and existing_masterkeys[0].is_decrypted:
            logger.info(f"Master key {masterkey_guid} already exists, skipping")
            existing_guids.append(str(masterkey_guid))
            continue

        if len(masterkey_data) == 20:
            masterkey = MasterKey(
                guid=masterkey_guid,
                masterkey_type=MasterKeyType.UNKNOWN,
                plaintext_key_sha1=masterkey_data,
            )
            await dpapi_manager.upsert_masterkey(masterkey)
            processed_guids.append(str(masterkey_guid))
        elif len(masterkey_data) == 64:
            masterkey = MasterKey(
                guid=masterkey_guid,
                masterkey_type=MasterKeyType.UNKNOWN,
                plaintext_key=masterkey_data,
                plaintext_key_sha1=SHA1.new(masterkey_data).digest(),
            )
            await dpapi_manager.upsert_masterkey(masterkey)
            processed_guids.append(str(masterkey_guid))
        else:
            logger.warning(
                f"[_handle_master_key_guid_pairs] len(masterkey_data) is not 20 or 64, not handling: {len(masterkey_data)}"
            )

    return {
        "status": "success",
        "type": "master_key_guid_pair",
        "added": processed_guids,
        "already_exists": existing_guids,
    }


async def _handle_dpapi_system_credential(dpapi_manager: DpapiManager, request: DpapiSystemCredentialRequest) -> dict:
    """Handle DPAPI_SYSTEM LSA secret credential submission."""

    dpapi_system_bytes = bytes.fromhex(request.value)
    dpapi_system_key = DpapiSystemCredential.from_bytes(dpapi_system_bytes)
    await dpapi_manager.upsert_system_credential(dpapi_system_key)

    return {"status": "success", "type": "dpapi_system"}


async def _handle_chromium_app_bound_key(
        dpapi_manager: DpapiManagerDep,
        request: ChromiumAppBoundKeyCredential) -> dict:
    """Handle Chromium App-Bound-Encryption key credential submission."""

    # Parse the key value from either format
    key_value = request.value.strip()

    if "\\x" in key_value:
        # Handle Python escaped format (e.g., \x5f\x1a...)
        cleaned = key_value.strip('"').strip("'")
        key_bytes = cleaned.encode().decode("unicode_escape").encode("latin1")
    else:
        # Handle hex format (64 hex characters)
        key_bytes = bytes.fromhex(key_value)

    # Apply source prefix logic (same as FileUpload.tsx)
    source = request.source.strip()
    # Check if source already has a URI scheme
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', source):
        # No scheme detected, apply host:// prefix by default
        source = f"host://{source}"

    username = request.username.strip()
    browser = request.browser

    # Try to insert with username collision handling
    max_attempts = 10
    is_default_username = username.upper() == "UNKNOWN"

    for attempt in range(max_attempts):
        try_username = username if attempt == 0 else f"{username}{attempt}"

        try:
            async with global_vars.asyncpg_pool.acquire() as conn:
                # Insert into chromium.state_keys
                await conn.execute(
                    """
                    INSERT INTO chromium.state_keys (
                        originating_object_id,
                        agent_id,
                        source,
                        project,
                        username,
                        browser,
                        key_is_decrypted,
                        app_bound_key_dec,
                        app_bound_key_is_decrypted
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    """,
                    None,  # originating_object_id
                    None,  # agent_id
                    source,
                    None,  # project
                    try_username,
                    browser,
                    False,  # key_is_decrypted
                    key_bytes,  # app_bound_key_dec
                    True,  # app_bound_key_is_decrypted
                )

            # Success!
            result = {
                "status": "success",
                "type": "chromium_app_bound_key",
                "source": source,
                "browser": browser,
                "username": try_username,
            }

            if attempt > 0:
                result["message"] = f"Username '{username}' already exists, used '{try_username}' instead"

            logger.info(
                "Successfully inserted Chromium app-bound key",
                source=source,
                browser=browser,
                username=try_username,
                attempts=attempt + 1,
            )

            # Finally, try to decrypt chromium cookies and logins with newly submitted key
            chromium_data_result = await retry_decrypt_chromium_data(
                UUID(int=0),
                dpapi_manager,
                global_vars.asyncpg_pool
            )

            logger.debug(
                "Completed retroactive chromium data decryption with new ABE key",
                result=chromium_data_result,
            )

            return result

        except asyncpg.UniqueViolationError as e:
            # Unique constraint violation on (source, username, browser)
            if not is_default_username:
                # If username is not the default "UNKNOWN", fail immediately
                raise HTTPException(
                    status_code=400,
                    detail=f"A Chromium app-bound key already exists for source '{source}', browser '{browser}', and username '{try_username}'. Please use a different username or source."
                ) from e

            # If username is "UNKNOWN", try incrementing
            if attempt >= max_attempts - 1:
                # Exhausted all attempts
                raise HTTPException(
                    status_code=400,
                    detail=f"Unable to insert Chromium app-bound key after {max_attempts} attempts. Too many entries with username pattern 'UNKNOWN*' for source '{source}' and browser '{browser}'."
                ) from e

            # Continue to next attempt
            logger.debug(
                "Username collision, retrying with incremented username",
                source=source,
                browser=browser,
                username=try_username,
                attempt=attempt + 1,
            )
            continue

        except Exception as e:
            logger.exception(
                "Error inserting Chromium app-bound key",
                source=source,
                browser=browser,
                username=try_username,
                error=str(e),
            )
            raise HTTPException(
                status_code=500,
                detail=f"Database error while inserting Chromium app-bound key: {str(e)}"
            ) from e

    # Should never reach here, but just in case
    raise HTTPException(
        status_code=500,
        detail="Unexpected error during Chromium app-bound key insertion"
    )


async def _handle_password_based_credential(
    decryptor: MasterKeyDecryptorService,
    request: PasswordCredentialKey | NtlmHashCredentialKey | Sha1CredentialKey | Pbkdf2StrongCredentialKey,
):
    if isinstance(request, PasswordCredentialKey):
        c = Password(value=request.value)
    elif isinstance(request, NtlmHashCredentialKey):
        c = NtlmHash(value=bytes.fromhex(request.value))
    elif isinstance(request, Sha1CredentialKey):
        c = Sha1Hash(value=bytes.fromhex(request.value))
    elif isinstance(request, Pbkdf2StrongCredentialKey):
        c = Pbkdf2Hash(value=bytes.fromhex(request.value))
    else:
        raise ValueError(f"Unsupported password-based credential type: {type(request)}")

    result = await decryptor.process_password_based_credential(c, request.user_sid)
    return result

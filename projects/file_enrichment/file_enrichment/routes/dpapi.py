"""DPAPI credential submission routes."""

import asyncio
import base64
import urllib.parse
from functools import lru_cache
from typing import Annotated
from uuid import UUID

from common.logger import get_logger
from common.models2.dpapi import (
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
from dapr.clients import DaprClient
from fastapi import APIRouter, Body, Depends, HTTPException
from nemesis_dpapi import (
    DomainBackupKey,
    DpapiManager,
    DpapiSystemCredential,
    MasterKey,
    NtlmHash,
    Password,
    Pbkdf2Hash,
    Sha1Hash,
)
from nemesis_dpapi.masterkey_decryptor import MasterKeyDecryptorService

logger = get_logger(__name__)

with DaprClient() as client:
    secret = client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_STRING")
    postgres_connection_string = secret.secret["POSTGRES_CONNECTION_STRING"]


# Using lru_cache to create a singleton instance of DpapiManager
@lru_cache
def get_dpapi_manager() -> DpapiManager:
    return DpapiManager(storage_backend=postgres_connection_string)


DpapiManagerDep = Annotated[DpapiManager, Depends(get_dpapi_manager)]


async def dpapi_background_monitor() -> None:
    logger.info("Starting DPAPI background monitor task")
    dpapi_manager = get_dpapi_manager()

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

    while True:
        try:
            num_masterkeys = await dpapi_manager.get_all_masterkeys()
            num_dec_masterkeys = len([mk for mk in num_masterkeys if mk.is_decrypted])
            num_enc_masterkeys = len([mk for mk in num_masterkeys if not mk.is_decrypted])
            backupkeys = await dpapi_manager._backup_key_repo.get_all_backup_keys()
            num_system_creds = await dpapi_manager._dpapi_system_cred_repo.get_all_credentials()
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


# Get database connection string
with DaprClient() as client:
    secret = client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_STRING")
    postgres_connection_string = secret.secret["POSTGRES_CONNECTION_STRING"]

# Create the router directly - no prefix to maintain original URLs
dpapi_router = APIRouter(tags=["dpapi"])


@dpapi_router.post("/dpapi/credentials")
async def submit_dpapi_credential(
    dpapi_manager: DpapiManagerDep,
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
            elif isinstance(
                request, (PasswordCredentialKey, NtlmHashCredentialKey, Sha1CredentialKey, Pbkdf2StrongCredentialKey)
            ):
                result = await _handle_password_based_credential(dpapi_manager, request)
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


async def _handle_domain_backup_key_credential(dpapi_manager: DpapiManager, request: DomainBackupKeyCredential) -> dict:
    """Handle domain backup key credential submission."""

    # Decode URL encoded value for string-based credentials
    credential_value = urllib.parse.unquote(request.value)
    pvk_data = base64.b64decode(credential_value, validate=True)
    backup_key = DomainBackupKey(
        guid=UUID(request.guid),  # Use the provided GUID
        key_data=pvk_data,
    )
    await dpapi_manager.upsert_domain_backup_key(backup_key)
    return {"status": "success", "type": "domain_backup_key"}


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
        existing_masterkey = await dpapi_manager.get_masterkey(masterkey_guid)
        if existing_masterkey is not None and existing_masterkey.is_decrypted:
            logger.info(f"Master key {masterkey_guid} already exists, skipping")
            existing_guids.append(str(masterkey_guid))
            continue

        masterkey = MasterKey(
            guid=masterkey_guid,
            plaintext_key=masterkey_data,
            plaintext_key_sha1=SHA1.new(masterkey_data).digest(),
        )

        await dpapi_manager.upsert_masterkey(masterkey)
        processed_guids.append(str(masterkey_guid))

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
    await dpapi_manager.upsert_dpapi_system_credential(dpapi_system_key)

    return {"status": "success", "type": "dpapi_system"}


async def _handle_password_based_credential(
    dpapi_manager: DpapiManager,
    request: PasswordCredentialKey | NtlmHashCredentialKey | Sha1CredentialKey | Pbkdf2StrongCredentialKey,
):
    decryptor = MasterKeyDecryptorService(dpapi_manager)

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

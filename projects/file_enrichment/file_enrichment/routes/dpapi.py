"""DPAPI credential submission routes."""

import asyncio
import base64
import urllib.parse
from functools import lru_cache
from typing import Annotated
from uuid import UUID

from common.logger import get_logger
from common.models2.dpapi import (
    DecryptedMasterKeyCredential,
    DomainBackupKeyCredential,
    DpapiCredentialRequest,
    DpapiSystemCredentialRequest,
    NtlmHashCredentialKey,
    PasswordCredentialKey,
    Pbkdf2StrongCredentialKey,
    Sha1CredentialKey,
)
from dapr.clients import DaprClient
from fastapi import APIRouter, Body, Depends, HTTPException
from nemesis_dpapi import DomainBackupKey, DpapiManager, DpapiSystemCredential
from nemesis_dpapi.masterkey_decryptor import MasterKeyDecryptorService

logger = get_logger(__name__)


# Using lru_cache to create a singleton instance of DpapiManager
@lru_cache
def get_dpapi_manager() -> DpapiManager:
    return DpapiManager(storage_backend="memory")


DpapiManagerDep = Annotated[DpapiManager, Depends(get_dpapi_manager)]


async def dpapi_background_monitor() -> None:
    dpapi_manager = get_dpapi_manager()
    while True:
        try:
            num_masterkeys = await dpapi_manager.get_all_masterkeys()
            num_dec_masterkeys = len([mk for mk in num_masterkeys if mk.is_decrypted])
            backupkeys = await dpapi_manager._backup_key_repo.get_all_backup_keys()
            logger.info(
                "Background DPAPI manager loop tick",
                num_masterkeys=len(num_masterkeys),
                num_dec_masterkeys=num_dec_masterkeys,
                num_backup_keys=len(backupkeys),
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
            elif isinstance(request, DecryptedMasterKeyCredential):
                result = await _handle_decrypted_master_key_credential(dpapi_manager, request)
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
    pvk_data = base64.b64decode(credential_value)
    backup_key = DomainBackupKey(
        guid=UUID(request.guid),  # Use the provided GUID
        key_data=pvk_data,
    )
    await dpapi_manager.add_domain_backup_key(backup_key)
    return {"status": "success", "type": "domain_backup_key"}


async def _handle_decrypted_master_key_credential(
    dpapi_manager: DpapiManager, request: DecryptedMasterKeyCredential
) -> dict:
    """Handle decrypted master key credential submission."""
    from Crypto.Hash import SHA1
    from nemesis_dpapi.core import MasterKey

    processed_guids = []
    existing_guids = []

    # Process each master key data entry
    for master_key_data in request.value:
        # Extract strongly typed master key data
        masterkey_guid = master_key_data.guid
        masterkey_data = bytes.fromhex(master_key_data.key_hex)

        # Check if masterkey already exists
        existing_masterkey = await dpapi_manager._masterkey_repo.get_masterkey(masterkey_guid)
        if existing_masterkey is not None:
            logger.info(f"Master key {masterkey_guid} already exists, skipping")
            existing_guids.append(str(masterkey_guid))
            continue

        # Create a MasterKey with the decrypted data and add it
        masterkey = MasterKey(
            guid=masterkey_guid,
            plaintext_key=masterkey_data,
            plaintext_key_sha1=SHA1.new(masterkey_data).digest(),
        )

        # Add directly to the repository
        await dpapi_manager._masterkey_repo.add_masterkey(masterkey)
        processed_guids.append(str(masterkey_guid))

    return {
        "status": "success",
        "type": "dec_master_key",
        "added": processed_guids,
        "already_exists": existing_guids,
    }


async def _handle_dpapi_system_credential(dpapi_manager: DpapiManager, request: DpapiSystemCredentialRequest) -> dict:
    """Handle DPAPI_SYSTEM LSA secret credential submission."""

    dpapi_system_bytes = bytes.fromhex(request.value)
    dpapi_system_key = DpapiSystemCredential.from_bytes(dpapi_system_bytes)
    await dpapi_manager.add_dpapi_system_credential(dpapi_system_key)

    return {"status": "success", "type": "decrypted_masterkeys"}


async def _handle_password_based_credential(
    dpapi_manager: DpapiManager,
    request: PasswordCredentialKey | NtlmHashCredentialKey | Sha1CredentialKey | Pbkdf2StrongCredentialKey,
):
    from nemesis_dpapi.crypto import NtlmHash, Password, Pbkdf2Hash, Sha1Hash

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

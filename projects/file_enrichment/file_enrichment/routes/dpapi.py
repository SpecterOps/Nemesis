"""DPAPI credential submission routes."""

import binascii
import urllib.parse
from uuid import UUID

from common.logger import get_logger
from common.models2.dpapi import (
    CredKeyCredential,
    DecryptedMasterKeyCredential,
    DomainBackupKeyCredential,
    DpapiCredentialRequest,
    NtlmHashCredential,
    PasswordCredential,
)
from dapr.clients import DaprClient
from fastapi import APIRouter, Body, HTTPException
from nemesis_dpapi import (
    CredKey,
    CredKeyHashType,
    DomainBackupKey,
    DpapiCrypto,
    DpapiManager,
    MasterKeyEncryptionKey,
    MasterKeyFilter,
)

logger = get_logger(__name__)

# Get database connection string
with DaprClient() as client:
    secret = client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_STRING")
    postgres_connection_string = secret.secret["POSTGRES_CONNECTION_STRING"]

# Create the router directly - no prefix to maintain original URLs
router = APIRouter(tags=["dpapi"])


@router.post("/dpapi/credentials")
async def submit_dpapi_credential(
    request: DpapiCredentialRequest = Body(..., description="The DPAPI credential data"),
):
    """Submit DPAPI credential for masterkey decryption."""
    try:
        has_user_sid = hasattr(request, "user_sid")
        logger.info("Received DPAPI credential submission", credential_type=request.type, has_user_sid=has_user_sid)

        # async with DpapiManager(postgres_connection_string) as dpapi_manager:
        async with DpapiManager(storage_backend="memory") as dpapi_manager:
            try:
                if isinstance(request, DomainBackupKeyCredential):
                    result = await _handle_domain_backup_key_credential(dpapi_manager, request)
                elif isinstance(request, DecryptedMasterKeyCredential):
                    result = await _handle_decrypted_master_key_credential(dpapi_manager, request)
                elif isinstance(request, (PasswordCredential, NtlmHashCredential, CredKeyCredential)):
                    result = await _handle_string_based_credential(dpapi_manager, request)
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
    import base64

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

    # Extract strongly typed master key data
    masterkey_guid = request.value.guid
    masterkey_data = binascii.unhexlify(request.value.key_hex)

    # Create a MasterKey with the decrypted data and add it
    masterkey = MasterKey(
        guid=masterkey_guid,
        plaintext_key=masterkey_data,
        plaintext_key_sha1=SHA1.new(masterkey_data).digest(),
    )

    # Add directly to the repository
    await dpapi_manager._masterkey_repo.add_masterkey(masterkey)
    return {"status": "success", "type": "dec_master_key", "guid": str(masterkey_guid)}


async def _handle_string_based_credential(
    dpapi_manager: DpapiManager, request: PasswordCredential | NtlmHashCredential | CredKeyCredential
) -> dict:
    """Handle password, NTLM hash, and cred key credential submissions."""

    if isinstance(request, PasswordCredential):
        creds_to_try = [
            CredKey.from_password(request.value, CredKeyHashType.PBKDF2, request.user_sid),
            CredKey.from_password(request.value, CredKeyHashType.SHA1),
            CredKey.from_password(request.value, CredKeyHashType.NTLM),
        ]
    elif isinstance(request, NtlmHashCredential):
        hash_bytes = bytes.fromhex(request.value)
        creds_to_try = [
            CredKey.from_ntlm(hash_bytes, CredKeyHashType.PBKDF2, request.user_sid),
            CredKey.from_ntlm(hash_bytes, CredKeyHashType.NTLM),
        ]
    elif isinstance(request, CredKeyCredential):
        hash_bytes = bytes.fromhex(request.value)
        creds_to_try = [
            CredKey.from_sha1(hash_bytes),
        ]
    else:
        raise ValueError(f"Unsupported credential type: {request.type}")

    encrypted_masterkeys = await dpapi_manager.get_all_masterkeys(filter_by=MasterKeyFilter.ENCRYPTED_ONLY)

    for masterkey in encrypted_masterkeys:
        if not masterkey.encrypted_key_usercred:
            continue

        masterkey_bytes = masterkey.encrypted_key_usercred

        for cred in creds_to_try:
            mk_key = MasterKeyEncryptionKey.from_cred_key(cred, request.user_sid)

            mk = DpapiCrypto.decrypt_masterkey_with_mk_key(masterkey_bytes, mk_key)
            await dpapi_manager._masterkey_repo.add_masterkey(mk)

    return {"status": "success", "type": request.type}

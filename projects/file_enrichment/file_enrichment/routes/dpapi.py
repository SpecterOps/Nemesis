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
from nemesis_dpapi import DpapiManager
from nemesis_dpapi.core import DomainBackupKey

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

        # Decode URL encoded value
        credential_value = urllib.parse.unquote(request.value)

        async with DpapiManager(postgres_connection_string) as dpapi_manager:
            try:
                if isinstance(request, DomainBackupKeyCredential):
                    # Parse domain backup key (base64 encoded PVK)
                    import base64

                    pvk_data = base64.b64decode(credential_value)
                    backup_key = DomainBackupKey(
                        guid=UUID(int=0),  # Will be determined by the key itself
                        key_data=pvk_data,
                    )
                    await dpapi_manager.add_domain_backup_key(backup_key)
                    result = {"status": "success", "type": "domain_backup_key"}

                elif isinstance(request, DecryptedMasterKeyCredential):
                    # Parse decrypted master key format: {guid}:key_hex
                    if ":" not in credential_value:
                        raise HTTPException(
                            status_code=400, detail="Decrypted master key must be in format '{guid}:key_hex'"
                        )

                    guid_str, key_hex = credential_value.split(":", 1)
                    guid_str = guid_str.strip("{}")
                    masterkey_guid = UUID(guid_str)
                    masterkey_data = binascii.unhexlify(key_hex)

                    # Create a MasterKey with the decrypted data and add it
                    from Crypto.Hash import SHA1
                    from nemesis_dpapi.core import MasterKey

                    masterkey = MasterKey(
                        guid=masterkey_guid,
                        plaintext_key=masterkey_data,
                        plaintext_key_sha1=SHA1.new(masterkey_data).digest(),
                    )

                    # Add directly to the repository
                    await dpapi_manager._masterkey_repo.add_masterkey(masterkey)
                    result = {"status": "success", "type": "dec_master_key", "guid": str(masterkey_guid)}

                elif isinstance(request, (PasswordCredential, NtlmHashCredential, CredKeyCredential)):
                    # These credential types require interaction with existing masterkeys
                    # Since the current DPAPI manager API doesn't directly support adding user credentials,
                    # we'll return a message indicating this functionality needs to be implemented
                    # in the DPAPI enrichment module itself
                    result = {
                        "status": "not_implemented",
                        "message": f"Credential type '{request.type}' processing is not yet implemented in the API. "
                        "This functionality should be handled by the DPAPI enrichment module during file processing.",
                        "type": request.type,
                    }

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

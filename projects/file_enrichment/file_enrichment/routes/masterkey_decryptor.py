import asyncio
from typing import Union

from common.logger import get_logger
from common.models2.dpapi import CredKeyCredential, NtlmHashCredential, PasswordCredential
from nemesis_dpapi import CredKey, CredKeyHashType, DpapiCrypto, DpapiManager, MasterKeyEncryptionKey, MasterKeyFilter

logger = get_logger(__name__)


class MasterKeyDecryptor:
    """Handles DPAPI master key decryption with background task processing."""

    def __init__(self, dpapi_manager: DpapiManager):
        self.dpapi_manager = dpapi_manager
        self._background_tasks = set()

    async def handle_password_based_credential(
        self, request: Union[PasswordCredential, NtlmHashCredential, CredKeyCredential]
    ) -> dict:
        """Handle password, NTLM hash, and cred key credential submissions."""

        mk_keys_to_try = self._generate_masterkey_encryption_keys(request)

        task = asyncio.create_task(self._decrypt_masterkeys_background(mk_keys_to_try, request.type))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

        return {"status": "success", "type": request.type, "message": "Decryption task started"}

    async def _decrypt_masterkeys_background(
        self, mk_keys_to_try: list[MasterKeyEncryptionKey], credential_type: str
    ) -> None:
        """Perform master key decryption attempts in background."""
        try:
            logger.info(f"Starting background decryption for credential type: {credential_type}")

            # Get encrypted master keys
            encrypted_masterkeys = await self.dpapi_manager.get_all_masterkeys(filter_by=MasterKeyFilter.ENCRYPTED_ONLY)

            decrypted_count = 0
            for masterkey in encrypted_masterkeys:
                if not masterkey.encrypted_key_usercred:
                    continue

                for mk_key in mk_keys_to_try:
                    try:
                        mk = DpapiCrypto.decrypt_masterkey_with_mk_key(masterkey.encrypted_key_usercred, mk_key)
                        await self.dpapi_manager._masterkey_repo.add_masterkey(mk)
                        decrypted_count += 1
                        logger.info(f"Successfully decrypted master key with {credential_type}")
                    except Exception as e:
                        # Continue trying other credentials on failure
                        logger.debug(f"Failed to decrypt master key: {e}")
                        continue

            # TODO: Notify the user that new master keys have been decrypted
            logger.info(f"Background decryption completed. Decrypted {decrypted_count} master keys")

        except Exception as e:
            logger.error(f"Error in background decryption task: {e}")

    def _generate_masterkey_encryption_keys(
        self, request: Union[PasswordCredential, NtlmHashCredential, CredKeyCredential]
    ) -> list[MasterKeyEncryptionKey]:
        """Generate MasterKeyEncryptionKey objects based on the credential type."""
        cred_keys = []

        if isinstance(request, PasswordCredential):
            cred_keys = [
                CredKey.from_password(request.value, CredKeyHashType.PBKDF2, request.user_sid),
                CredKey.from_password(request.value, CredKeyHashType.SHA1),
                CredKey.from_password(request.value, CredKeyHashType.NTLM),
            ]
        elif isinstance(request, NtlmHashCredential):
            hash_bytes = bytes.fromhex(request.value)
            cred_keys = [
                CredKey.from_ntlm(hash_bytes, CredKeyHashType.PBKDF2, request.user_sid),
                CredKey.from_ntlm(hash_bytes, CredKeyHashType.NTLM),
            ]
        elif isinstance(request, CredKeyCredential):
            hash_bytes = bytes.fromhex(request.value)
            cred_keys = [
                CredKey.from_sha1(hash_bytes),
            ]
        else:
            raise ValueError(f"Unsupported credential type: {request.type}")

        return [MasterKeyEncryptionKey.from_cred_key(cred, request.user_sid) for cred in cred_keys]

    async def shutdown(self):
        """Cancel all background tasks on shutdown."""
        if self._background_tasks:
            logger.info(f"Cancelling {len(self._background_tasks)} background tasks")
            for task in self._background_tasks:
                task.cancel()
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
            self._background_tasks.clear()

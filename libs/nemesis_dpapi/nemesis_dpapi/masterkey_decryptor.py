import asyncio
from time import perf_counter

from common.logger import get_logger

from .core import UserAccountType
from .exceptions import MasterKeyDecryptionError
from .keys import CredKey, CredKeyHashType, MasterKeyEncryptionKey, NtlmHash, Password, Pbkdf2Hash, Sha1Hash
from .manager import DpapiManager, MasterKeyFilter
from .types import Sid

logger = get_logger(__name__)


class MasterKeyDecryptorService:
    """Handles DPAPI master key decryption with background task processing."""

    def __init__(self, dpapi_manager: DpapiManager):
        self.dpapi_manager = dpapi_manager
        self._background_tasks = set()

    async def process_password_based_credential(
        self,
        credential: Password | NtlmHash | Sha1Hash | Pbkdf2Hash,
        account_sid: Sid,
    ) -> dict:
        """Handle password, NTLM hash, and cred key credential submissions."""

        mk_keys_to_try = self._generate_mk_encryption_keys(credential, account_sid)

        task = asyncio.create_task(self._decrypt_masterkeys_background(mk_keys_to_try, type(credential)))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

        return {
            "status": "success",
            "type": type(credential).__name__,
            "message": "Decryption task started",
        }

    async def _decrypt_masterkeys_background(
        self, mk_keys_to_try: list[MasterKeyEncryptionKey], credential_type: type
    ) -> None:
        """Perform master key decryption attempts in background."""
        start_time = perf_counter()
        try:
            logger.info(f"Starting background decryption for credential type: {credential_type.__name__}")

            encrypted_masterkeys = await self.dpapi_manager.get_all_masterkeys(
                filter_by=MasterKeyFilter.ENCRYPTED_ONLY,
                user_account_type=[UserAccountType.USER],
            )

            decrypted_count = 0

            logger.info(f"Attempting to decrypt {len(encrypted_masterkeys)} encrypted master keys")
            for masterkey in encrypted_masterkeys:
                if not masterkey.encrypted_key_usercred:
                    continue

                for mk_key in mk_keys_to_try:
                    try:
                        plaintext_mk = masterkey.decrypt(mk_key)
                        await self.dpapi_manager.upsert_masterkey(plaintext_mk)
                        decrypted_count += 1
                        logger.info(
                            f"Successfully decrypted master key {masterkey.guid} with {credential_type.__name__}"
                        )
                        break  # We decrypted it, no need to try other keys
                    except MasterKeyDecryptionError as e:
                        logger.debug(f"Failed to decrypt master key: {e}")
                        continue

            # TODO: Notify the user that new master keys have been decrypted
            elapsed_time = perf_counter() - start_time
            logger.info(
                f"Background decryption completed. Decrypted {decrypted_count}/({len(encrypted_masterkeys)}) master keys in {elapsed_time:.2f} seconds"
            )

        except Exception as e:
            elapsed_time = perf_counter() - start_time
            logger.error(
                f"Error in background masterkey decryption task. Cred type: {credential_type.__name__}. Error: {e}. Elapsed time: {elapsed_time:.2f} seconds"
            )

    def _generate_mk_encryption_keys(
        self,
        cred: Password | NtlmHash | Sha1Hash | Pbkdf2Hash,
        account_sid: Sid,
    ) -> list[MasterKeyEncryptionKey]:
        """Generate MasterKeyEncryptionKey objects based on the credential type."""
        cred_keys = []

        if isinstance(cred, Password):
            cred_keys = [
                CredKey.from_password(cred.value, CredKeyHashType.PBKDF2, account_sid),
                CredKey.from_password(cred.value, CredKeyHashType.SHA1),
                CredKey.from_password(cred.value, CredKeyHashType.NTLM),
            ]
        elif isinstance(cred, NtlmHash):
            cred_keys = [
                CredKey.from_ntlm(cred.value, CredKeyHashType.PBKDF2, account_sid),
                CredKey.from_ntlm(cred.value, CredKeyHashType.NTLM),
            ]
        elif isinstance(cred, Sha1Hash):
            cred_keys = [
                CredKey.from_sha1(cred.value),
            ]
        elif isinstance(cred, Pbkdf2Hash):
            cred_keys = [
                CredKey.from_pbkdf2(cred.value),
            ]
        else:
            raise ValueError(f"Unsupported credential type: {cred.type}")

        return [MasterKeyEncryptionKey.from_cred_key(cred, account_sid) for cred in cred_keys]

    async def shutdown(self):
        """Cancel all background tasks on shutdown."""
        if self._background_tasks:
            logger.info(f"Cancelling {len(self._background_tasks)} background tasks")
            for task in self._background_tasks:
                task.cancel()
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
            self._background_tasks.clear()

"""Auto-decryption observer for DPAPI manager."""

import asyncio
import time
from logging import getLogger
from typing import TYPE_CHECKING
from uuid import UUID

from nemesis_dpapi.exceptions import MasterKeyDecryptionError
from nemesis_dpapi.keys import MasterKeyEncryptionKey
from nemesis_dpapi.repositories import MasterKeyFilter

from .core import BackupKeyRecoveryBlob, MasterKey, MasterKeyFile, MasterKeyPolicy
from .eventing import (
    DpapiEvent,
    DpapiObserver,
    NewDomainBackupKeyEvent,
    NewDpapiSystemCredentialEvent,
    NewEncryptedMasterKeyEvent,
)
from .keys import DpapiSystemCredential

if TYPE_CHECKING:
    from .manager import DpapiManager


logger = getLogger(__name__)


class AutoDecryptionObserver(DpapiObserver):
    """Automatically decrypts encrypted masterkeys with domain backup keys.

    This class monitors DPAPI events related to new domain backup keys and encrypted masterkeys.
    When new domain backup keys are added, it attempts to decrypt any encrypted masterkeys
    using the new backup key. When new encrypted masterkeys are added, it attempts to decrypt
    them using existing backup keys.
    """

    def __init__(self, dpapi_manager: "DpapiManager"):
        """Initialize the observer with a reference to the DPAPI manager."""
        self.dpapi_manager = dpapi_manager
        self._background_tasks: set[asyncio.Task] = set()

    async def update(self, event: DpapiEvent) -> None:
        """Handle DPAPI events, specifically new domain backup keys, encrypted masterkeys, and new credentials."""
        if isinstance(event, NewDomainBackupKeyEvent):
            self._create_task(self._handle_new_backup_key(event))
        elif isinstance(event, NewEncryptedMasterKeyEvent):
            await self._handle_new_encrypted_masterkey(event)
        elif isinstance(event, NewDpapiSystemCredentialEvent):
            self._create_task(await self._handle_new_sytem_credential(event))

    def _create_task(self, coroutine) -> asyncio.Task:
        """Creates a background task and maintains a reference until its completion

        The purpose of this is to maintain reference to the task so that the garbage collector
        does not prematurely collect and destroy it.
        """
        task = asyncio.create_task(coroutine)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

        return task

    async def _handle_new_backup_key(self, event: NewDomainBackupKeyEvent) -> None:
        """Handle a new domain backup key by decrypting existing encrypted masterkeys."""

        logger.debug(f"New domain backup key added: {event.backup_key_guid}, attempting decryption...")

        start_time = time.perf_counter()
        await self._attempt_masterkey_decryption_with_backup_key(event.backup_key_guid)
        end_time = time.perf_counter()

        logger.debug(f"_attempt_masterkey_decryption_with_backup_key took {end_time - start_time:.4f} seconds")

    async def _handle_new_encrypted_masterkey(self, event: NewEncryptedMasterKeyEvent) -> None:
        """Attempt to decrypt a new masterkey using existing domain backup keys."""

        masterkey = await self.dpapi_manager.get_masterkey(event.masterkey_guid)

        if not masterkey:
            raise ValueError(f"New masterkey {event.masterkey_guid} not found in the DB!")

        if masterkey.is_decrypted:
            return  # Already decrypted

        # We have an encrypted masterkey, try and decrypt with:
        # - Available domain backup keys
        # - Available DPAPI_SYSTEM credentials
        # - (TODO) Available user credentials

        tasks = [
            self._create_task(self._decrypt_with_backup_keys(masterkey)),
            self._create_task(self._decrypt_with_system_credentials(masterkey)),
            # self._create_task(self._decrypt_with_user_credentials(masterkey)),  # TODO
        ]

        result = await asyncio.gather(*tasks, return_exceptions=True)

    async def _handle_new_sytem_credential(self, event: NewDpapiSystemCredentialEvent) -> None:
        """Handle a new DPAPI_SYSTEM credential by attempting to decrypt existing encrypted masterkeys."""

        logger.debug("New DPAPI_SYSTEM credential added. Attempting decryption...")

        start_time = time.perf_counter()
        await self._attempt_masterkey_decryption_with_system_credential(event.credential)
        end_time = time.perf_counter()

        logger.debug(f"_attempt_masterkey_decryption_with_system_credential took {end_time - start_time:.4f} seconds")

    async def _attempt_masterkey_decryption_with_system_credential(
        self, credential: DpapiSystemCredential, encrypted_masterkeys: list[MasterKey] | None = None
    ) -> None:
        """Attempt to decrypt all encrypted masterkeys using the new DPAPI system credentials."""
        start_time = time.perf_counter()

        logger.debug("Attempting to decrypt masterkeys with new DPAPI_SYSTEM credential")

        if encrypted_masterkeys is None:
            # TODO: Filter out User masterkeys
            encrypted_masterkeys = await self.dpapi_manager.get_all_masterkeys(filter_by=MasterKeyFilter.ENCRYPTED_ONLY)

        if len(encrypted_masterkeys) == 0:
            return

        decrypted_count = 0
        for encrypted_mk in encrypted_masterkeys:
            try:
                if not encrypted_mk.encrypted_key_usercred:
                    continue

                # Try the machine key first, then the user key
                for i in range(2):
                    if i == 0:
                        mk_key = MasterKeyEncryptionKey.from_dpapi_system_cred(credential.machine_key)
                    else:
                        mk_key = MasterKeyEncryptionKey.from_dpapi_system_cred(credential.user_key)

                    try:
                        plaintext_mk = encrypted_mk.decrypt(mk_key)
                        decrypted_count += 1
                    except MasterKeyDecryptionError:
                        continue

                    print(f"Successfully decrypted masterkey {encrypted_mk.guid} with DPAPI_SYSTEM credential")
                    await self.dpapi_manager.upsert_masterkey(plaintext_mk)
                    break  # Decrypted successfully, no need to try other key
            except Exception as e:
                logger.error(
                    f"Error decrypting masterkey with DPAPI_SYSTEM credential. MasterKey UUID: {encrypted_mk.guid}: {e}"
                )
                continue

        end_time = time.perf_counter()
        logger.debug(f"_attempt_masterkey_decryption_with_system_credential took {end_time - start_time:.4f} seconds")

    async def _attempt_masterkey_decryption_with_backup_key(
        self, backup_key_guid: UUID, encrypted_masterkeys: list[MasterKey] | None = None
    ) -> None:
        """Attempt to decrypt masterkeys using a backup key."""

        try:
            if encrypted_masterkeys is None:
                # TODO: Filter out SYSTEM masterkeys
                encrypted_masterkeys = await self.dpapi_manager.get_all_masterkeys(
                    filter_by=MasterKeyFilter.ENCRYPTED_ONLY
                )

            if len(encrypted_masterkeys) == 0:
                return

            new_backup_key = await self.dpapi_manager._backup_key_repo.get_backup_key(backup_key_guid)

            if not new_backup_key:
                return

            # Try to decrypt each encrypted masterkey with the new backup key
            for enc_masterkey in encrypted_masterkeys:
                if enc_masterkey.is_decrypted:
                    continue

                if enc_masterkey.encrypted_key_backup is None:
                    continue

                # Parse the encrypted backup key bytes into a BackupKeyRecoveryBlob
                try:
                    backup_key_blob = BackupKeyRecoveryBlob.parse(enc_masterkey.encrypted_key_backup)
                except Exception:
                    # Skip if we can't parse the backup key blob
                    continue

                masterkey_file = MasterKeyFile(
                    version=0,
                    modified=False,
                    file_path=None,
                    masterkey_guid=enc_masterkey.guid,
                    policy=MasterKeyPolicy.NONE,
                    domain_backup_key=backup_key_blob,
                    raw_bytes=b"",  # Not needed for decryption
                )

                try:
                    result = masterkey_file.decrypt(new_backup_key)
                except (MasterKeyDecryptionError, ValueError):
                    # Skip masterkeys that can't be decrypted (wrong key, local backup key, etc.)
                    continue

                if result:
                    print(
                        f"Successfully decrypted masterkey {enc_masterkey.guid} with new backup key {new_backup_key.guid}"
                    )
                    new_mk = MasterKey(
                        guid=enc_masterkey.guid,
                        encrypted_key_usercred=enc_masterkey.encrypted_key_usercred,
                        encrypted_key_backup=enc_masterkey.encrypted_key_backup,
                        plaintext_key=result.plaintext_key,
                        plaintext_key_sha1=result.plaintext_key_sha1,
                        backup_key_guid=result.backup_key_guid,
                    )

                    await self.dpapi_manager._masterkey_repo.upsert_masterkey(new_mk)

        except Exception as e:
            logger.error(f"Auto-decrypt _attempt_masterkey_decryption_with_backup_key error: {e}")

    async def _decrypt_with_backup_keys(self, masterkey: MasterKey) -> None:
        """Attempt to decrypt a masterkey using all available backup keys."""
        start_time = time.perf_counter()
        if masterkey.encrypted_key_backup is None:
            return  # Cannot decrypt if there's backup key data

        backup_keys = await self.dpapi_manager._backup_key_repo.get_all_backup_keys()
        if not backup_keys:
            return

        # Try to decrypt the masterkey with each backup key
        for backup_key in backup_keys:
            try:
                masterkey_file = MasterKeyFile(
                    version=0,
                    modified=False,
                    file_path=None,
                    masterkey_guid=masterkey.guid,
                    policy=MasterKeyPolicy.NONE,
                    domain_backup_key=masterkey.encrypted_key_backup,
                )

                result = masterkey_file.decrypt(backup_key)
            except Exception:
                logger.debug(f"Failed to decrypt masterkey {masterkey.guid} with backup key {backup_key.guid}")
                continue

            if result:
                new_mk = MasterKey(
                    guid=masterkey.guid,
                    encrypted_key_usercred=masterkey.encrypted_key_usercred,
                    encrypted_key_backup=masterkey.encrypted_key_backup,
                    plaintext_key=result.plaintext_key,
                    plaintext_key_sha1=result.plaintext_key_sha1,
                    backup_key_guid=result.backup_key_guid,
                )
                print(f"Successfully decrypted masterkey {masterkey.guid} with backup key {backup_key.guid}")
                await self.dpapi_manager._masterkey_repo.upsert_masterkey(new_mk)
                break

        end_time = time.perf_counter()
        logger.debug(f"_attempt_masterkey_decryption took {end_time - start_time:.4f} seconds")

    async def _decrypt_with_system_credentials(self, masterkey: MasterKey) -> None:
        """Attempt to decrypt a masterkey using all available DPAPI_SYSTEM credentials."""
        start_time = time.perf_counter()
        if masterkey.encrypted_key_usercred is None:
            return  # Cannot decrypt if there's no user credential data

        system_credentials = await self.dpapi_manager._dpapi_system_cred_repo.get_all_credentials()
        if not system_credentials:
            return

        # Try to decrypt the masterkey with each system credential
        for credential in system_credentials:
            await self._attempt_masterkey_decryption_with_system_credential(credential, [masterkey])

        end_time = time.perf_counter()
        logger.debug(f"_decrypt_with_system_credentials took {end_time - start_time:.4f} seconds")

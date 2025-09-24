"""Auto-decryption observer for DPAPI manager."""

import asyncio
import time
from logging import getLogger
from typing import TYPE_CHECKING
from uuid import UUID

from nemesis_dpapi.crypto import MasterKeyEncryptionKey
from nemesis_dpapi.exceptions import MasterKeyDecryptionError
from nemesis_dpapi.repositories import MasterKeyFilter

from .core import DpapiSystemCredential, MasterKey, MasterKeyFile, MasterKeyPolicy
from .eventing import (
    DpapiEvent,
    DpapiObserver,
    NewDomainBackupKeyEvent,
    NewDpapiSystemCredentialEvent,
    NewEncryptedMasterKeyEvent,
)

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

    def update(self, event: DpapiEvent) -> None:
        """Handle DPAPI events, specifically new domain backup keys, encrypted masterkeys, and new credentials."""
        if isinstance(event, NewDomainBackupKeyEvent):
            self._create_task(self._attempt_masterkey_decryption_with_backup_key(event.backup_key_guid))
        elif isinstance(event, NewEncryptedMasterKeyEvent):
            self._create_task(self._attempt_new_masterkey_decryption(event.masterkey_guid))
        elif isinstance(event, NewDpapiSystemCredentialEvent):
            self._create_task(self._attempt_masterkey_decryption_with_system_credential(event.credential))

    def _create_task(self, coroutine) -> None:
        """Creates a background task and maintains a reference until its completion

        The purpose of this is to maintain reference to the task so that the garbage collector
        does not prematurely collect and destroy it.
        """
        task = asyncio.create_task(coroutine)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def _attempt_masterkey_decryption_with_system_credential(self, credential: DpapiSystemCredential) -> None:
        """Attempt to decrypt all encrypted masterkeys using the new DPAPI system credentials."""
        start_time = time.perf_counter()

        print("Attempting to decrypt masterkeys with new DPAPI_SYSTEM credential")
        encrypted_masterkeys = await self.dpapi_manager.get_all_masterkeys(filter_by=MasterKeyFilter.ENCRYPTED_ONLY)

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

                    await self.dpapi_manager.upsert_masterkey(plaintext_mk)
                    break  # Decrypted successfully, no need to try other key
            except Exception as e:
                logger.error(
                    f"Error decrypting masterkey with DPAPI_SYSTEM credential. MasterKey UUID: {encrypted_mk.guid}: {e}"
                )
                continue

        end_time = time.perf_counter()
        print(f"_attempt_masterkey_decryption_with_system_credential took {end_time - start_time:.4f} seconds")

    async def _attempt_masterkey_decryption_with_backup_key(self, backup_key_guid: UUID) -> None:
        """Attempt to decrypt all masterkeys using the new backup key."""
        start_time = time.perf_counter()
        try:
            masterkeys = await self.dpapi_manager.get_all_masterkeys()
            encrypted_count = len([mk for mk in masterkeys if not mk.is_decrypted])

            if encrypted_count == 0:
                return

            # Get all backup keys (including the new one)
            backup_keys = await self.dpapi_manager._backup_key_repo.get_all_backup_keys()
            new_backup_key = next((bk for bk in backup_keys if bk.guid == backup_key_guid), None)

            if not new_backup_key:
                return

            # Try to decrypt each encrypted masterkey with the new backup key
            for masterkey in masterkeys:
                if masterkey.is_decrypted:
                    continue

                if masterkey.encrypted_key_backup is None:
                    continue

                masterkey_file = MasterKeyFile(
                    version=0,
                    modified=False,
                    file_path=None,
                    masterkey_guid=masterkey.guid,
                    policy=MasterKeyPolicy.NONE,
                    domain_backup_key=masterkey.encrypted_key_backup,
                )

                try:
                    result = new_backup_key.decrypt_masterkey_file(masterkey_file)
                except MasterKeyDecryptionError:
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

                    await self.dpapi_manager._masterkey_repo.upsert_masterkey(new_mk)

        except Exception as e:
            logger.error(f"Auto-decrypt error: {e}")
        finally:
            end_time = time.perf_counter()
            print(f"_attempt_masterkey_decryption_with_backup_key took {end_time - start_time:.4f} seconds")

    async def _attempt_new_masterkey_decryption(self, masterkey_guid: UUID) -> None:
        """Attempt to decrypt a new masterkey using existing domain backup keys."""
        start_time = time.perf_counter()

        masterkey = await self.dpapi_manager.get_masterkey(masterkey_guid)

        if not masterkey:
            raise ValueError(f"New masterkey {masterkey_guid} not found in the DB!")

        if masterkey.is_decrypted:
            return  # Already decrypted

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

                result = backup_key.decrypt_masterkey_file(masterkey_file)
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
                await self.dpapi_manager._masterkey_repo.upsert_masterkey(new_mk)
                break

        end_time = time.perf_counter()
        print(f"_attempt_masterkey_decryption took {end_time - start_time:.4f} seconds")

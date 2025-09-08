"""Auto-decryption observer for DPAPI manager."""

import asyncio
from logging import getLogger
from typing import TYPE_CHECKING
from uuid import UUID

from nemesis_dpapi.exceptions import MasterKeyDecryptionError

from .core import MasterKey, MasterKeyFile, MasterKeyPolicy
from .eventing import DpapiEvent, DpapiObserver, NewDomainBackupKeyEvent, NewEncryptedMasterKeyEvent

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
        """Handle DPAPI events, specifically new domain backup keys and encrypted masterkeys."""
        if isinstance(event, NewDomainBackupKeyEvent):
            self._create_task(self._attempt_masterkey_decryption_with_backup_key(event.backup_key_guid))
        elif isinstance(event, NewEncryptedMasterKeyEvent):
            self._create_task(self._attempt_masterkey_decryption(event.masterkey_guid))

    def _create_task(self, coroutine) -> None:
        """Creates a background task and maintains a reference until its completion

        The purpose of this is to maintain reference to the task so that the garbage collector
        does not prematurely collect and destroy it."""
        task = asyncio.create_task(coroutine)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def _attempt_masterkey_decryption_with_backup_key(self, backup_key_guid: UUID) -> None:
        """Attempt to decrypt all masterkeys using the new backup key."""
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
                    # No backup key data to use
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

                    await self.dpapi_manager._masterkey_repo.update_masterkey(new_mk)

        except Exception as e:
            logger.error(f"Auto-decrypt error: {e}")

    async def _attempt_masterkey_decryption(self, masterkey_guid: UUID) -> None:
        """Attempt to decrypt a new masterkey using existing domain backup keys."""

        masterkey = await self.dpapi_manager.get_masterkey(masterkey_guid)
        if not masterkey or masterkey.is_decrypted:
            return  # Masterkey not found or already decrypted

        if masterkey.encrypted_key_backup is None:
            return  # Cannot decrypt without backup key data

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
                await self.dpapi_manager._masterkey_repo.update_masterkey(new_mk)
                return

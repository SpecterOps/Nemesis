"""Auto-decryption observer for DPAPI manager."""

import asyncio
from typing import TYPE_CHECKING
from uuid import UUID

from .core import MasterKeyFile, MasterKeyPolicy
from .eventing import DpapiEvent, DpapiObserver, NewDomainBackupKeyEvent, NewEncryptedMasterKeyEvent

if TYPE_CHECKING:
    from .manager import DpapiManager


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
            # Schedule decryption attempt using the new backup key
            task = asyncio.create_task(self._attempt_masterkey_decryption_with_backup_key(event.backup_key_guid))
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)
        elif isinstance(event, NewEncryptedMasterKeyEvent):
            # Schedule decryption attempt for the new masterkey using existing backup keys
            task = asyncio.create_task(self._attempt_new_masterkey_decryption(event.masterkey_guid))
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)

    async def _attempt_masterkey_decryption_with_backup_key(self, backup_key_guid: UUID) -> None:
        """Attempt to decrypt all masterkeys using the new backup key."""
        try:
            # Get all masterkeys
            masterkeys = await self.dpapi_manager.get_all_masterkeys()
            encrypted_count = len([mk for mk in masterkeys if not mk.is_decrypted])

            if encrypted_count == 0:
                return  # All masterkeys already decrypted

            # Get all backup keys (including the new one)
            backup_keys = await self.dpapi_manager._backup_key_repo.get_all_backup_keys()
            new_backup_key = next((bk for bk in backup_keys if bk.guid == backup_key_guid), None)

            if not new_backup_key:
                return  # Could not find backup key

            # Try to decrypt each encrypted masterkey with the new backup key
            for masterkey in masterkeys:
                if masterkey.is_decrypted:
                    continue

                try:
                    # Check if encrypted_key_backup exists before attempting decryption
                    if masterkey.encrypted_key_backup is None:
                        continue

                    # Create a MasterKeyFile object for the domain backup key decrypt method
                    masterkey_file = MasterKeyFile(
                        version=0,
                        modified=False,
                        file_path=None,
                        masterkey_guid=masterkey.guid,
                        policy=MasterKeyPolicy.NONE,
                        domain_backup_key=masterkey.encrypted_key_backup,
                    )

                    # Attempt decryption using the backup key
                    result = new_backup_key.decrypt_masterkey_file(masterkey_file)

                    if result:
                        # Update the masterkey with decrypted data from the result MasterKey
                        masterkey.plaintext_key = result.plaintext_key
                        masterkey.plaintext_key_sha1 = result.plaintext_key_sha1
                        masterkey.backup_key_guid = result.backup_key_guid
                        await self.dpapi_manager._masterkey_repo.update_masterkey(masterkey)

                except Exception:
                    # Continue with other masterkeys if one fails
                    # For debugging - you can uncomment this line to see errors
                    # print(f"Auto-decrypt error: {e}")
                    continue

        except Exception:
            # Silently handle any errors during auto-decryption
            pass

    async def _attempt_new_masterkey_decryption(self, masterkey_guid: UUID) -> None:
        """Attempt to decrypt a new masterkey using existing domain backup keys."""
        try:
            # Get the specific masterkey
            masterkey = await self.dpapi_manager.get_masterkey(masterkey_guid)
            if not masterkey or masterkey.is_decrypted:
                return  # Masterkey not found or already decrypted

            # Check if encrypted_key_backup exists
            if masterkey.encrypted_key_backup is None:
                return  # Cannot decrypt without backup key data

            # Get all existing backup keys
            backup_keys = await self.dpapi_manager._backup_key_repo.get_all_backup_keys()
            if not backup_keys:
                return  # No backup keys available

            # Try to decrypt the masterkey with each backup key
            for backup_key in backup_keys:
                try:
                    # Create a MasterKeyFile object for the domain backup key decrypt method
                    masterkey_file = MasterKeyFile(
                        version=0,
                        modified=False,
                        file_path=None,
                        masterkey_guid=masterkey.guid,
                        policy=MasterKeyPolicy.NONE,
                        domain_backup_key=masterkey.encrypted_key_backup,
                    )

                    # Attempt decryption using the backup key
                    result = backup_key.decrypt_masterkey_file(masterkey_file)

                    if result:
                        # Update the masterkey with decrypted data from the result MasterKey
                        masterkey.plaintext_key = result.plaintext_key
                        masterkey.plaintext_key_sha1 = result.plaintext_key_sha1
                        masterkey.backup_key_guid = result.backup_key_guid
                        await self.dpapi_manager._masterkey_repo.update_masterkey(masterkey)
                        return  # Successfully decrypted, stop trying other keys

                except Exception:
                    # Continue with other backup keys if one fails
                    continue

        except Exception:
            # Silently handle any errors during auto-decryption
            pass

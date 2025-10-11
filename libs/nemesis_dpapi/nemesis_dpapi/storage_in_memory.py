"""Storage backend implementations."""

from uuid import UUID

from .core import MasterKey, MasterKeyType
from .exceptions import StorageError
from .keys import DomainBackupKey, DpapiSystemCredential
from .repositories import EncryptionFilter


class InMemoryMasterKeyRepository:
    """In-memory storage for masterkeys."""

    def __init__(self) -> None:
        self._masterkeys: dict[UUID, MasterKey] = {}

    async def upsert_masterkey(self, masterkey: MasterKey) -> None:
        """Add or update a masterkey in storage."""
        self._masterkeys[masterkey.guid] = masterkey

    async def get_masterkeys(
        self,
        guid: UUID | None = None,
        encryption_filter: EncryptionFilter = EncryptionFilter.ALL,
        backup_key_guid: UUID | None = None,
        masterkey_type: list[MasterKeyType] | None = None,
    ) -> list[MasterKey]:
        """Retrieve masterkey(s) with optional filtering.

        Args:
            guid: Optional specific masterkey GUID to retrieve. If provided, returns a list with one MasterKey or empty list.
            encryption_filter: Filter by decryption status (default: ALL). Ignored if guid is provided.
            backup_key_guid: Filter by backup key GUID (default: None for all). Ignored if guid is provided.
            masterkey_type: Filter by user account types (default: None for all). Ignored if guid is provided.

        Returns:
            A list of MasterKeys (empty list if no matches)
        """
        # If guid is provided, return single masterkey as a list
        if guid is not None:
            mk = self._masterkeys.get(guid)
            return [mk] if mk is not None else []

        # Otherwise, return filtered list
        masterkeys = list(self._masterkeys.values())

        # Filter by decryption status
        if encryption_filter == EncryptionFilter.ENCRYPTED_ONLY:
            masterkeys = [mk for mk in masterkeys if not mk.is_decrypted]
        elif encryption_filter == EncryptionFilter.DECRYPTED_ONLY:
            masterkeys = [mk for mk in masterkeys if mk.is_decrypted]

        # Filter by backup key GUID
        if backup_key_guid is not None:
            masterkeys = [mk for mk in masterkeys if mk.backup_key_guid == backup_key_guid]

        # Filter by user account type
        if masterkey_type is not None and len(masterkey_type) > 0:
            masterkeys = [mk for mk in masterkeys if mk.masterkey_type in masterkey_type]

        return masterkeys

    async def delete_masterkey(self, guid: UUID) -> None:
        """Delete a masterkey by GUID."""
        if guid not in self._masterkeys:
            raise StorageError(f"Masterkey {guid} not found")
        del self._masterkeys[guid]


class InMemoryDomainBackupKeyRepository:
    """In-memory storage for domain backup keys."""

    def __init__(self) -> None:
        self._backup_keys: dict[UUID, DomainBackupKey] = {}

    async def upsert_backup_key(self, key: DomainBackupKey) -> None:
        """Add or update a domain backup key in storage."""
        self._backup_keys[key.guid] = key

    async def get_backup_keys(self, guid: UUID | None = None) -> list[DomainBackupKey]:
        """Retrieve backup key(s).

        Args:
            guid: Optional specific backup key GUID to retrieve. If provided, returns a list with one key or empty list.

        Returns:
            A list of DomainBackupKey objects (empty list if no matches)
        """
        if guid is not None:
            key = self._backup_keys.get(guid)
            return [key] if key is not None else []

        return list(self._backup_keys.values())

    async def delete_backup_key(self, guid: UUID) -> None:
        """Delete a backup key by GUID."""
        if guid not in self._backup_keys:
            raise StorageError(f"Domain backup key {guid} not found")
        del self._backup_keys[guid]


class InMemoryDpapiSystemCredentialRepository:
    """In-memory storage for DPAPI system credentials."""

    def __init__(self) -> None:
        self._credentials: list[DpapiSystemCredential] = []

    async def upsert_credential(self, cred: DpapiSystemCredential) -> None:
        """Add or update a DPAPI system credential in storage."""
        for i, existing_cred in enumerate(self._credentials):
            if existing_cred.user_key == cred.user_key and existing_cred.machine_key == cred.machine_key:
                self._credentials[i] = cred
                return
        self._credentials.append(cred)

    async def get_all_credentials(self) -> list[DpapiSystemCredential]:
        """Retrieve all DPAPI system credentials."""
        return list(self._credentials)

    async def delete_all_credentials(self) -> None:
        """Delete all DPAPI system credentials."""
        self._credentials.clear()

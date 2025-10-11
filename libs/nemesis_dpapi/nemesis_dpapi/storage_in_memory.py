"""Storage backend implementations."""

from uuid import UUID

from .core import MasterKey, UserAccountType
from .exceptions import StorageError
from .keys import DomainBackupKey, DpapiSystemCredential
from .repositories import MasterKeyFilter


class InMemoryMasterKeyRepository:
    """In-memory storage for masterkeys."""

    def __init__(self) -> None:
        self._masterkeys: dict[UUID, MasterKey] = {}

    async def upsert_masterkey(self, masterkey: MasterKey) -> None:
        """Add or update a masterkey in storage."""
        self._masterkeys[masterkey.guid] = masterkey

    async def get_masterkey(self, guid: UUID, user_account_type: UserAccountType | None = None) -> MasterKey | None:
        """Retrieve a masterkey by GUID.

        Args:
            guid: Masterkey GUID to retrieve
            user_account_type: Optional filter by user account type
        """
        masterkey = self._masterkeys.get(guid)
        if masterkey is None:
            return None

        # Apply user account type filter if specified
        if user_account_type is not None and masterkey.user_account_type != user_account_type:
            return None

        return masterkey

    async def get_all_masterkeys(
        self,
        filter_by: MasterKeyFilter = MasterKeyFilter.ALL,
        backup_key_guid: UUID | None = None,
        user_account_type: list[UserAccountType] | None = None,
    ) -> list[MasterKey]:
        """Retrieve masterkeys with optional filtering.

        Args:
            filter_by: Filter by decryption status (default: ALL)
            backup_key_guid: Filter by backup key GUID (default: None for all)
            user_account_type: Filter by user account types (default: None for all)
        """
        masterkeys = list(self._masterkeys.values())

        # Filter by decryption status
        if filter_by == MasterKeyFilter.ENCRYPTED_ONLY:
            masterkeys = [mk for mk in masterkeys if not mk.is_decrypted]
        elif filter_by == MasterKeyFilter.DECRYPTED_ONLY:
            masterkeys = [mk for mk in masterkeys if mk.is_decrypted]

        # Filter by backup key GUID
        if backup_key_guid is not None:
            masterkeys = [mk for mk in masterkeys if mk.backup_key_guid == backup_key_guid]

        # Filter by user account type
        if user_account_type is not None and len(user_account_type) > 0:
            masterkeys = [mk for mk in masterkeys if mk.user_account_type in user_account_type]

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

    async def get_backup_key(self, guid: UUID) -> DomainBackupKey | None:
        """Retrieve a backup key by GUID."""
        return self._backup_keys.get(guid)

    async def get_all_backup_keys(self) -> list[DomainBackupKey]:
        """Retrieve all backup keys."""
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

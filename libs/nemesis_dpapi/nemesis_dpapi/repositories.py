"""Repository interfaces and implementations for DPAPI storage."""

from enum import Enum
from typing import Protocol
from uuid import UUID

from .core import MasterKey, UserAccountType
from .keys import DomainBackupKey, DpapiSystemCredential


class MasterKeyFilter(Enum):
    """Filter options for masterkey queries."""

    ALL = "all"
    ENCRYPTED_ONLY = "encrypted_only"
    DECRYPTED_ONLY = "decrypted_only"


class MasterKeyRepository(Protocol):
    """Protocol for masterkey storage operations."""

    async def upsert_masterkey(self, masterkey: MasterKey) -> None:
        """Add or update a masterkey in storage."""
        ...

    async def get_masterkey(self, guid: UUID, user_account_type: UserAccountType | None = None) -> MasterKey | None:
        """Retrieve a masterkey by GUID.

        Args:
            guid: Masterkey GUID to retrieve
            user_account_type: Optional filter by user account type
        """
        ...

    async def get_all_masterkeys(
        self,
        filter_by: MasterKeyFilter = MasterKeyFilter.ALL,
        backup_key_guid: UUID | None = None,
        user_account_type: UserAccountType | None = None,
    ) -> list[MasterKey]:
        """Retrieve masterkeys with optional filtering.

        Args:
            filter_by: Filter by decryption status (default: ALL)
            backup_key_guid: Filter by backup key GUID (default: None for all)
            user_account_type: Filter by user account type (default: None for all)
        """
        ...

    async def delete_masterkey(self, guid: UUID) -> None:
        """Delete a masterkey by GUID."""
        ...


class DomainBackupKeyRepository(Protocol):
    """Protocol for domain backup key storage operations."""

    async def upsert_backup_key(self, key: DomainBackupKey) -> None:
        """Add or update a domain backup key in storage."""
        ...

    async def get_backup_key(self, guid: UUID) -> DomainBackupKey | None:
        """Retrieve a backup key by GUID."""
        ...

    async def get_all_backup_keys(self) -> list[DomainBackupKey]:
        """Retrieve all backup keys."""
        ...

    async def delete_backup_key(self, guid: UUID) -> None:
        """Delete a backup key by GUID."""
        ...


class DpapiSystemCredentialRepository(Protocol):
    """Protocol for DPAPI system credential storage operations."""

    async def upsert_credential(self, cred: DpapiSystemCredential) -> None:
        """Add or update a DPAPI system credential in storage."""
        ...

    async def get_all_credentials(self) -> list[DpapiSystemCredential]:
        """Retrieve all DPAPI system credentials."""
        ...

    async def delete_all_credentials(self) -> None:
        """Delete all DPAPI system credentials."""
        ...

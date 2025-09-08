"""Repository interfaces and implementations for DPAPI storage."""

from enum import Enum
from typing import Protocol
from uuid import UUID

from .core import DomainBackupKey, DpapiSystemCredential, MasterKey


class MasterKeyFilter(Enum):
    """Filter options for masterkey queries."""

    ALL = "all"
    ENCRYPTED_ONLY = "encrypted_only"
    DECRYPTED_ONLY = "decrypted_only"


class MasterKeyRepository(Protocol):
    """Protocol for masterkey storage operations."""

    async def add_masterkey(self, masterkey: MasterKey) -> None:
        """Add a masterkey to storage."""
        ...

    async def get_masterkey(self, guid: UUID) -> MasterKey | None:
        """Retrieve a masterkey by GUID."""
        ...

    async def get_all_masterkeys(
        self, filter_by: MasterKeyFilter = MasterKeyFilter.ALL, backup_key_guid: UUID | None = None
    ) -> list[MasterKey]:
        """Retrieve masterkeys with optional filtering.

        Args:
            filter_by: Filter by decryption status (default: ALL)
            backup_key_guid: Filter by backup key GUID (default: None for all)
        """
        ...

    async def update_masterkey(self, masterkey: MasterKey) -> None:
        """Update an existing masterkey."""
        ...

    async def delete_masterkey(self, guid: UUID) -> None:
        """Delete a masterkey by GUID."""
        ...


class DomainBackupKeyRepository(Protocol):
    """Protocol for domain backup key storage operations."""

    async def add_backup_key(self, key: DomainBackupKey) -> None:
        """Add a domain backup key to storage."""
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

    async def add_credential(self, cred: DpapiSystemCredential) -> None:
        """Add a DPAPI system credential to storage."""
        ...

    async def get_all_credentials(self) -> list[DpapiSystemCredential]:
        """Retrieve all DPAPI system credentials."""
        ...

    async def delete_all_credentials(self) -> None:
        """Delete all DPAPI system credentials."""
        ...

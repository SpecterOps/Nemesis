"""Repository interfaces and implementations for DPAPI storage."""

from enum import Enum
from typing import Protocol
from uuid import UUID

from .core import MasterKey, MasterKeyType
from .keys import DomainBackupKey, DpapiSystemCredential


class EncryptionFilter(Enum):
    """Encryption filter options for masterkey queries."""

    ALL = "all"  # Return all masterkeys
    ENCRYPTED_ONLY = "encrypted_only"  # Return only encrypted masterkeys
    DECRYPTED_ONLY = "decrypted_only"  # Return only decrypted masterkeys


class MasterKeyRepository(Protocol):
    """Protocol for masterkey storage operations."""

    async def upsert_masterkey(self, masterkey: MasterKey, *, project: str) -> None:
        """Add or update a masterkey in a project's storage."""
        ...

    async def get_masterkeys(
        self,
        guid: UUID | None = None,
        *,
        project: str,
        encryption_filter: EncryptionFilter = EncryptionFilter.ALL,
        backup_key_guid: UUID | None = None,
        masterkey_type: list[MasterKeyType] | None = None,
    ) -> list[MasterKey]:
        """Retrieve a project's masterkey(s) with optional filtering.

        Args:
            project: Only masterkeys stored for this project are returned.
            guid: Optional specific masterkey GUID to retrieve. If provided, returns a list with one MasterKey or empty list.
            encryption_filter: Filter by decryption status (default: ALL). Ignored if guid is provided.
            backup_key_guid: Filter by backup key GUID (default: None for all). Ignored if guid is provided.
            masterkey_type: Filter by user account types (default: None for all). Ignored if guid is provided.

        Returns:
            A list of MasterKeys (empty list if no matches)
        """
        ...

    async def delete_masterkey(self, guid: UUID, *, project: str) -> None:
        """Delete a project's masterkey by GUID."""
        ...


class DomainBackupKeyRepository(Protocol):
    """Protocol for domain backup key storage operations."""

    async def upsert_backup_key(self, key: DomainBackupKey, *, project: str) -> int:
        """Add or update a domain backup key in a project's storage."""
        ...

    async def get_backup_keys(self, guid: UUID | None = None, *, project: str) -> list[DomainBackupKey]:
        """Retrieve a project's backup key(s).

        Args:
            guid: Optional specific backup key GUID to retrieve. If provided, returns a list with one key or empty list.

        Returns:
            A list of DomainBackupKey objects (empty list if no matches)
        """
        ...

    async def delete_backup_key(self, guid: UUID, *, project: str) -> None:
        """Delete a project's backup key by GUID."""
        ...


class DpapiSystemCredentialRepository(Protocol):
    """Protocol for DPAPI system credential storage operations."""

    async def upsert_credential(self, cred: DpapiSystemCredential, *, project: str) -> None:
        """Add or update a DPAPI system credential in a project's storage."""
        ...

    async def get_all_credentials(self, *, project: str) -> list[DpapiSystemCredential]:
        """Retrieve all of a project's DPAPI system credentials."""
        ...

    async def delete_all_credentials(self, *, project: str) -> None:
        """Delete all of a project's DPAPI system credentials."""
        ...

"""Null DPAPI manager implementation."""

from typing import Any, Self
from uuid import UUID

from .core import Blob, MasterKey, MasterKeyType
from .exceptions import MasterKeyNotFoundError
from .keys import DomainBackupKey, DpapiSystemCredential
from .protocols import DpapiManagerProtocol
from .repositories import EncryptionFilter


class NullDpapiManager(DpapiManagerProtocol):
    """Null object implementation of DPAPI manager that does nothing when methods are invoked."""

    async def __aenter__(self) -> Self:
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        pass

    async def upsert_masterkey(self, masterkey: MasterKey) -> None:
        """Add or update a masterkey (does nothing)."""
        pass

    async def upsert_domain_backup_key(self, backup_key: DomainBackupKey) -> int:
        """Add or update a domain backup key (does nothing)."""
        return 0

    async def upsert_system_credential(self, cred: DpapiSystemCredential) -> None:
        """Add or update a DPAPI system credential (does nothing)."""
        pass

    async def decrypt_blob(self, blob: Blob) -> bytes:
        """Decrypt a DPAPI blob (always fails)."""
        raise MasterKeyNotFoundError(blob.masterkey_guid)

    async def get_masterkeys(
        self,
        guid: UUID | None = None,
        encryption_filter: EncryptionFilter = EncryptionFilter.ALL,
        backup_key_guid: UUID | None = None,
        masterkey_type: list[MasterKeyType] | None = None,
    ) -> list[MasterKey]:
        """Retrieve masterkey(s) with optional filtering (always returns empty list)."""
        return []

    async def get_system_credentials(self, guid: UUID | None = None) -> list[DpapiSystemCredential]:
        """Retrieve DPAPI system credential(s) (always returns empty list)."""
        return []

    async def get_backup_keys(self, guid: UUID | None = None) -> list[DomainBackupKey]:
        """Retrieve domain backup key(s) (always returns empty list)."""
        return []

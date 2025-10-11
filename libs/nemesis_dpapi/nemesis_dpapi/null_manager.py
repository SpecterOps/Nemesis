"""Null DPAPI manager implementation."""

from typing import Any
from uuid import UUID

from .core import Blob, MasterKey, MasterKeyType
from .exceptions import MasterKeyNotFoundError
from .keys import DomainBackupKey, DpapiSystemCredential
from .protocols import DpapiManagerProtocol
from .repositories import MasterKeyFilter


class NullDpapiManager(DpapiManagerProtocol):
    """Null object implementation of DPAPI manager that does nothing when methods are invoked."""

    async def __aenter__(self) -> "NullDpapiManager":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        pass

    async def upsert_masterkey(self, masterkey: MasterKey) -> None:
        """Add or update a masterkey (does nothing)."""
        pass

    async def upsert_domain_backup_key(self, backup_key: DomainBackupKey) -> None:
        """Add or update a domain backup key (does nothing)."""
        pass

    async def upsert_dpapi_system_credential(self, cred: DpapiSystemCredential) -> None:
        """Add or update a DPAPI system credential (does nothing)."""
        pass

    async def decrypt_blob(self, blob: Blob) -> bytes:
        """Decrypt a DPAPI blob (always fails)."""
        raise MasterKeyNotFoundError(blob.masterkey_guid)

    async def get_masterkey(self, guid: UUID) -> MasterKey | None:
        """Retrieve a masterkey by GUID (always returns None)."""
        return None

    async def get_all_masterkeys(
        self,
        filter_by: MasterKeyFilter = MasterKeyFilter.ALL,
        backup_key_guid: UUID | None = None,
        masterkey_type: list[MasterKeyType] | None = None,
    ) -> list[MasterKey]:
        """Retrieve masterkeys with optional filtering (always returns empty list)."""
        return []

    async def close(self) -> None:
        """Close the manager and cleanup resources (does nothing)."""
        pass

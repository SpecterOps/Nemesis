"""Protocol definitions for DPAPI components."""

from typing import Protocol, runtime_checkable
from uuid import UUID

from .core import Blob, DomainBackupKey, DpapiSystemCredential, MasterKey
from .repositories import MasterKeyFilter


@runtime_checkable
class DpapiManagerProtocol(Protocol):
    """Protocol defining the interface for DPAPI managers."""

    async def __aenter__(self):
        """Async context manager entry."""
        ...

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        ...

    async def upsert_masterkey(self, masterkey: MasterKey) -> None:
        """Add or update a masterkey (encrypted or plaintext)."""
        ...

    async def upsert_domain_backup_key(self, backup_key: DomainBackupKey) -> None:
        """Add or update a domain backup key."""
        ...

    async def upsert_dpapi_system_credential(self, cred: DpapiSystemCredential) -> None:
        """Add or update a DPAPI system credential."""
        ...

    async def decrypt_blob(self, blob: Blob) -> bytes:
        """Decrypt a DPAPI blob using available masterkeys."""
        ...

    async def get_masterkey(self, guid: UUID) -> MasterKey | None:
        """Retrieve a masterkey by GUID."""
        ...

    async def get_all_masterkeys(
        self,
        filter_by: MasterKeyFilter = MasterKeyFilter.ALL,
        backup_key_guid: UUID | None = None,
    ) -> list[MasterKey]:
        """Retrieve masterkeys with optional filtering."""
        ...

    async def close(self) -> None:
        """Close the manager and cleanup resources."""
        ...
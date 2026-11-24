"""Protocol definitions for DPAPI components."""

from typing import Protocol, Self, runtime_checkable
from uuid import UUID

from .core import Blob, MasterKey, MasterKeyType
from .keys import DomainBackupKey, DpapiSystemCredential
from .repositories import EncryptionFilter


@runtime_checkable
class DpapiManagerProtocol(Protocol):
    """Protocol defining the interface for DPAPI managers.

    All key material is scoped to a project: every operation takes a required ``project`` and never reads, writes or
    decrypts with another project's keys.
    """

    async def __aenter__(self) -> Self:
        """Async context manager entry."""
        ...

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        ...

    async def upsert_masterkey(self, masterkey: MasterKey, *, project: str) -> None:
        """Add or update a project's masterkey (encrypted or plaintext)."""
        ...

    async def upsert_domain_backup_key(self, backup_key: DomainBackupKey, *, project: str) -> int:
        """Add or update a project's domain backup key."""
        ...

    async def upsert_system_credential(self, cred: DpapiSystemCredential, *, project: str) -> None:
        """Add or update a project's DPAPI system credential."""
        ...

    async def decrypt_blob(self, blob: Blob, entropy: bytes | None = None, *, project: str) -> bytes:
        """Decrypt a DPAPI blob using the project's masterkeys."""
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
            guid: Optional specific masterkey GUID to retrieve. If provided, returns a list with one MasterKey or empty list.
            project: Only this project's masterkeys are returned.
            encryption_filter: Filter by decryption status (default: ALL). Ignored if guid is provided.
            backup_key_guid: Filter by backup key GUID (default: None for all). Ignored if guid is provided.
            masterkey_type: Filter by user account types (default: None for all). Ignored if guid is provided.

        Returns:
            A list of MasterKeys (empty list if no matches)
        """
        ...

    async def get_system_credentials(self, *, project: str) -> list[DpapiSystemCredential]:
        """Retrieve a project's DPAPI system credential(s)."""
        ...

    async def get_backup_keys(self, guid: UUID | None = None, *, project: str) -> list[DomainBackupKey]:
        """Retrieve a project's domain backup key(s)."""
        ...

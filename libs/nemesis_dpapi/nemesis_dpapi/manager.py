"""Main DPAPI manager class."""

from typing import TYPE_CHECKING
from uuid import UUID

import asyncpg
from Crypto.Hash import SHA1

from .auto_decrypt import AutoDecryptionObserver
from .core import Blob, DomainBackupKey, DpapiSystemCredential, MasterKey
from .crypto import DpapiCrypto
from .eventing import (
    NewDomainBackupKeyEvent,
    NewDpapiSystemCredentialEvent,
    NewEncryptedMasterKeyEvent,
    NewPlaintextMasterKeyEvent,
    Publisher,
)
from .exceptions import (
    DpapiBlobDecryptionError,
    MasterKeyNotDecryptedError,
    MasterKeyNotFoundError,
)
from .storage_in_memory import (
    InMemoryDomainBackupKeyRepository,
    InMemoryDpapiSystemCredentialRepository,
    InMemoryMasterKeyRepository,
)
from .storage_postgres import (
    PostgresDomainBackupKeyRepository,
    PostgresDpapiSystemCredentialRepository,
    PostgresMasterKeyRepository,
    create_tables,
)

if TYPE_CHECKING:
    from .repositories import (
        DomainBackupKeyRepository,
        DpapiSystemCredentialRepository,
        MasterKeyRepository,
    )

from .repositories import MasterKeyFilter


# TODO: Make thread safe
class DpapiManager(Publisher):
    """Main DPAPI manager for handling masterkeys, backup keys, and blob decryption."""

    def __init__(
        self, storage_backend: str = "memory", auto_decrypt: bool = True
    ) -> None:
        """Initialize DPAPI manager with specified storage backend.

        Args:
            storage_backend: Either "memory" for in-memory storage or a PostgreSQL
                           connection string for database storage.
            auto_decrypt: Enable automatic masterkey decryption as new domain backup keys are added.
        """
        super().__init__()
        self._storage_backend = storage_backend
        self._crypto = DpapiCrypto()
        self._initialized = False
        self._auto_decrypt = auto_decrypt

        # Storage-related fields
        self._masterkey_repo: MasterKeyRepository
        self._backup_key_repo: DomainBackupKeyRepository
        self._dpapi_system_cred_repo: DpapiSystemCredentialRepository
        self._pg_pool: asyncpg.Pool | None = None

        # Set up auto-decryption if enabled
        if self._auto_decrypt:
            self._auto_decrypt_observer = AutoDecryptionObserver(self)
            self.subscribe(self._auto_decrypt_observer)

    async def _initialize_storage(self) -> None:
        """Initialize storage repositories based on backend type."""
        if self._storage_backend == "memory":
            self._masterkey_repo = InMemoryMasterKeyRepository()
            self._backup_key_repo = InMemoryDomainBackupKeyRepository()
            self._dpapi_system_cred_repo = InMemoryDpapiSystemCredentialRepository()
        elif self._storage_backend.startswith("postgres://"):
            # Initialize PostgreSQL connection pool
            pool = await asyncpg.create_pool(self._storage_backend)
            if pool is None:
                raise ValueError("Failed to create PostgreSQL connection pool")
            self._pg_pool = pool
            await create_tables(self._pg_pool)

            self._masterkey_repo = PostgresMasterKeyRepository(self._pg_pool)
            self._backup_key_repo = PostgresDomainBackupKeyRepository(self._pg_pool)
            self._dpapi_system_cred_repo = PostgresDpapiSystemCredentialRepository(
                self._pg_pool
            )
        else:
            raise ValueError(f"Unsupported storage backend: {self._storage_backend}")

        self._initialized = True

    async def __aenter__(self):
        """Async context manager entry."""
        await self._initialize_storage()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._pg_pool:
            await self._pg_pool.close()

    async def upsert_masterkey(
        self,
        masterkey: MasterKey,
    ) -> None:
        """Add or update a masterkey (encrypted or plaintext).

        Args:
            masterkey: MasterKey object to add or update
        """
        if not self._initialized:
            await self._initialize_storage()

        calculated_sha1 = None
        if masterkey.plaintext_key and not masterkey.plaintext_key_sha1:
            calculated_sha1 = SHA1.new(masterkey.plaintext_key).digest()
            new_masterkey = masterkey.model_copy(
                update={"plaintext_key_sha1": calculated_sha1},
            )
        else:
            new_masterkey = masterkey

        await self._masterkey_repo.upsert_masterkey(new_masterkey)

        # Publish appropriate event based on what was added
        if new_masterkey.plaintext_key or new_masterkey.plaintext_key_sha1:
            self.publish(NewPlaintextMasterKeyEvent(masterkey_guid=new_masterkey.guid))
        elif new_masterkey.encrypted_key_usercred or new_masterkey.encrypted_key_backup:
            self.publish(NewEncryptedMasterKeyEvent(masterkey_guid=new_masterkey.guid))

    async def upsert_domain_backup_key(self, backup_key: DomainBackupKey) -> None:
        """Add or update a domain backup key and decrypt all compatible masterkeys.

        Args:
            backup_key: Domain backup key to add or update
        """

        if not self._initialized:
            await self._initialize_storage()

        await self._backup_key_repo.upsert_backup_key(backup_key)

        self.publish(NewDomainBackupKeyEvent(backup_key_guid=backup_key.guid))

    async def upsert_dpapi_system_credential(self, cred: DpapiSystemCredential) -> None:
        """Add or update a DPAPI system credential.

        Args:
            cred: DPAPI system credential to add or update
        """
        if not self._initialized:
            await self._initialize_storage()

        await self._dpapi_system_cred_repo.upsert_credential(cred)
        self.publish(NewDpapiSystemCredentialEvent(credential=cred))

    async def decrypt_blob(self, blob: Blob) -> bytes:
        """Decrypt a DPAPI blob using available masterkeys.

        Args:
            blob: DPAPI blob to decrypt

        Returns:
            Decrypted blob data

        Raises:
            MasterKeyNotFoundError: If required masterkey is not available
            MasterKeyNotDecryptedError: If masterkey exists but is not decrypted
            DPAPIBlobDecryptionError: If blob decryption fails
        """
        if not self._initialized:
            await self._initialize_storage()

        # Find the required masterkey
        masterkey = await self._masterkey_repo.get_masterkey(blob.masterkey_guid)
        if not masterkey:
            raise MasterKeyNotFoundError(blob.masterkey_guid)

        if not masterkey.is_decrypted:
            raise MasterKeyNotDecryptedError(blob.masterkey_guid)

        # Decrypt the blob
        try:
            if masterkey.plaintext_key is None:
                raise MasterKeyNotDecryptedError(blob.masterkey_guid)

            return self._crypto.decrypt_blob(blob.raw_bytes, masterkey.plaintext_key)
        except Exception as e:
            raise DpapiBlobDecryptionError(str(e)) from e

    async def get_masterkey(self, guid: UUID) -> MasterKey | None:
        """Retrieve a masterkey by GUID."""
        if not self._initialized:
            await self._initialize_storage()
        return await self._masterkey_repo.get_masterkey(guid)

    async def get_all_masterkeys(
        self,
        filter_by: MasterKeyFilter = MasterKeyFilter.ALL,
        backup_key_guid: UUID | None = None,
    ) -> list[MasterKey]:
        """Retrieve masterkeys with optional filtering.

        Args:
            filter_by: Filter by decryption status (default: ALL)
            backup_key_guid: Filter by backup key GUID (default: None for all)
        """
        if not self._initialized:
            await self._initialize_storage()
        return await self._masterkey_repo.get_all_masterkeys(filter_by, backup_key_guid)

    async def close(self) -> None:
        """Close the manager and cleanup resources."""
        if self._pg_pool:
            await self._pg_pool.close()

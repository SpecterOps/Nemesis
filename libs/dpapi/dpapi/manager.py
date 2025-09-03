"""Main DPAPI manager class."""

from typing import TYPE_CHECKING
from uuid import UUID

import asyncpg

from .auto_decrypt import AutoDecryptionObserver
from .core import Blob, DomainBackupKey, MasterKey
from .crypto import DpapiCrypto
from .eventing import NewDomainBackupKeyEvent, NewEncryptedMasterKeyEvent, Publisher
from .exceptions import DpapiBlobDecryptionError, MasterKeyNotDecryptedError, MasterKeyNotFoundError
from .storage_in_memory import InMemoryDomainBackupKeyRepository, InMemoryMasterKeyRepository
from .storage_postgres import PostgresDomainBackupKeyRepository, PostgresMasterKeyRepository, create_tables

if TYPE_CHECKING:
    from .repositories import DomainBackupKeyRepository, MasterKeyRepository


class DpapiManager(Publisher):
    """Main DPAPI manager for handling masterkeys, backup keys, and blob decryption."""

    def __init__(self, storage_backend: str = "memory", auto_decrypt: bool = True) -> None:
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
        elif self._storage_backend.startswith("postgres://"):
            # Initialize PostgreSQL connection pool
            pool = await asyncpg.create_pool(self._storage_backend)
            if pool is None:
                raise ValueError("Failed to create PostgreSQL connection pool")
            self._pg_pool = pool
            await create_tables(self._pg_pool)

            self._masterkey_repo = PostgresMasterKeyRepository(self._pg_pool)
            self._backup_key_repo = PostgresDomainBackupKeyRepository(self._pg_pool)
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

    async def add_encrypted_masterkey(
        self,
        guid: UUID,
        encrypted_key_usercred: bytes,
        encrypted_key_backup: bytes,
    ) -> None:
        """Add an encrypted masterkey and attempt decryption if possible.

        Args:
            guid: Unique identifier for the masterkey (the masterkey GUID)
            encrypted_key_usercred: Masterkey data encrypted with the user's cred
            encrypted_key_backup: Masterkey data encrypted with the domain backup key
        """

        masterkey = MasterKey(
            guid=guid,
            encrypted_key_usercred=encrypted_key_usercred,
            encrypted_key_backup=encrypted_key_backup,
        )
        await self._masterkey_repo.add_masterkey(masterkey)

        self.publish(NewEncryptedMasterKeyEvent(masterkey_guid=guid))

    async def add_domain_backup_key(self, backup_key: DomainBackupKey) -> None:
        """Add a domain backup key and decrypt all compatible masterkeys.

        Args:
            backup_key: Domain backup key to add
        """
        if not self._initialized:
            await self._initialize_storage()

        await self._backup_key_repo.add_backup_key(backup_key)

        self.publish(NewDomainBackupKeyEvent(backup_key_guid=backup_key.guid))

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
            return self._crypto.decrypt_blob(blob.encrypted_data, masterkey.plaintext_key)
        except Exception as e:
            raise DpapiBlobDecryptionError(str(e)) from e

    async def get_masterkey(self, guid: UUID) -> MasterKey | None:
        """Retrieve a masterkey by GUID."""
        if not self._initialized:
            await self._initialize_storage()
        return await self._masterkey_repo.get_masterkey(guid)

    async def get_all_masterkeys(self) -> list[MasterKey]:
        """Retrieve all masterkeys."""
        if not self._initialized:
            await self._initialize_storage()
        return await self._masterkey_repo.get_all_masterkeys()

    async def get_decrypted_masterkeys(self) -> list[MasterKey]:
        """Retrieve all decrypted masterkeys."""
        if not self._initialized:
            await self._initialize_storage()
        all_keys = await self.get_all_masterkeys()
        return [key for key in all_keys if key.is_decrypted]

    async def close(self) -> None:
        """Close the manager and cleanup resources."""
        if self._pg_pool:
            await self._pg_pool.close()

"""Main DPAPI manager class."""

from typing import TYPE_CHECKING, Self
from uuid import UUID

import asyncpg

from .auto_decrypt import AutoDecryptionObserver
from .core import Blob, MasterKey, MasterKeyType
from .eventing import (
    DaprDpapiEventPublisher,
    DpapiObserver,
    InMemoryPublisher,
    NewDomainBackupKeyEvent,
    NewDpapiSystemCredentialEvent,
    NewEncryptedMasterKeyEvent,
    NewPlaintextMasterKeyEvent,
)
from .exceptions import MasterKeyNotDecryptedError, MasterKeyNotFoundError, WriteOnceViolationError
from .keys import DomainBackupKey, DpapiSystemCredential
from .storage_in_memory import (
    InMemoryDomainBackupKeyRepository,
    InMemoryDpapiSystemCredentialRepository,
    InMemoryMasterKeyRepository,
)
from .storage_postgres import (
    PostgresDomainBackupKeyRepository,
    PostgresDpapiSystemCredentialRepository,
    PostgresMasterKeyRepository,
)
from .validation import check_write_once_conflicts, validate_and_calculate_sha1, validate_no_empty_string

if TYPE_CHECKING:
    from .repositories import (
        DomainBackupKeyRepository,
        DpapiSystemCredentialRepository,
        MasterKeyRepository,
    )

from .protocols import DpapiManagerProtocol
from .repositories import EncryptionFilter


class DpapiManager(DpapiManagerProtocol):
    """Main DPAPI manager for handling masterkeys, backup keys, and blob decryption."""

    def __init__(
        self,
        storage_backend: str = "memory",
        auto_decrypt: bool = True,
        publisher: DaprDpapiEventPublisher | None = None,
    ) -> None:
        """Initialize DPAPI manager with specified storage backend.

        Args:
            storage_backend: Either "memory" for in-memory storage or a PostgreSQL
                           connection string for database storage.
            auto_decrypt: Enable automatic masterkey decryption as new domain backup keys are added.
        """
        super().__init__()
        self._storage_backend = storage_backend
        self._initialized = False
        self._auto_decrypt = auto_decrypt

        # Storage-related fields
        self._masterkey_repo: MasterKeyRepository
        self._backup_key_repo: DomainBackupKeyRepository
        self._dpapi_system_cred_repo: DpapiSystemCredentialRepository
        self._pg_pool: asyncpg.Pool | None = None

        if publisher is None:
            self._publisher = InMemoryPublisher()
        else:
            self._publisher = publisher

        # Auto-decryption observer will be set up during async initialization
        self._auto_decrypt_observer: AutoDecryptionObserver | None = None

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

            self._masterkey_repo = PostgresMasterKeyRepository(self._pg_pool)
            self._backup_key_repo = PostgresDomainBackupKeyRepository(self._pg_pool)
            self._dpapi_system_cred_repo = PostgresDpapiSystemCredentialRepository(self._pg_pool)
        else:
            raise ValueError(f"Unsupported storage backend: {self._storage_backend}")

        # Set up auto-decryption observer after storage is initialized
        if self._auto_decrypt and self._auto_decrypt_observer is None:
            self._auto_decrypt_observer = AutoDecryptionObserver(self)
            await self._publisher.register_subscriber(self._auto_decrypt_observer)

        self._initialized = True

    async def __aenter__(self) -> Self:
        """Async context manager entry."""
        await self._initialize_storage()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        if self._pg_pool:
            await self._pg_pool.close()

    async def subscribe(self, observer: DpapiObserver) -> None:
        """Subscribe an observer to DPAPI events.

        Args:
            observer: Observer implementing the update(event) method
        """
        await self._publisher.register_subscriber(observer)

    async def upsert_masterkey(
        self,
        masterkey: MasterKey,
    ) -> None:
        """Add or update a masterkey (encrypted or plaintext).

        This method enforces write-once semantics: once a field is set to a non-NULL value,
        it cannot be changed to a different value. Fields can only be written once.

        Args:
            masterkey: MasterKey object to add or update

        Raises:
            ValueError: If plaintext_key and plaintext_key_sha1 don't match
            WriteOnceViolationError: If attempting to modify fields that already have values
        """
        if not self._initialized:
            await self._initialize_storage()

        # Validate and calculate SHA1 hash
        # This ensures integrity: if plaintext_key is provided, SHA1 is calculated and verified
        validated_sha1 = validate_and_calculate_sha1(
            masterkey.plaintext_key,
            masterkey.plaintext_key_sha1,
        )

        # Create updated masterkey with validated SHA1 if it changed
        if validated_sha1 != masterkey.plaintext_key_sha1:
            new_masterkey = masterkey.model_copy(
                update={"plaintext_key_sha1": validated_sha1},
            )
        else:
            new_masterkey = masterkey

        # Check write-once constraints against existing record
        existing_list = await self._masterkey_repo.get_masterkeys(guid=new_masterkey.guid)
        if existing_list:
            existing = existing_list[0]
            conflicts = check_write_once_conflicts(
                existing,
                new_masterkey,
                fields=[
                    "encrypted_key_usercred",
                    "encrypted_key_backup",
                    "plaintext_key",
                    "plaintext_key_sha1",
                    "backup_key_guid",
                    "masterkey_type",
                ],
            )
            if conflicts:
                raise WriteOnceViolationError("masterkey", str(new_masterkey.guid), conflicts)

        # Call repository to perform the upsert (repository layer also enforces write-once at SQL level)
        await self._masterkey_repo.upsert_masterkey(new_masterkey)

        # Publish appropriate event based on what was added
        if new_masterkey.plaintext_key or new_masterkey.plaintext_key_sha1:
            await self._publisher.publish_event(NewPlaintextMasterKeyEvent(masterkey_guid=new_masterkey.guid))
        elif new_masterkey.encrypted_key_usercred or new_masterkey.encrypted_key_backup:
            await self._publisher.publish_event(NewEncryptedMasterKeyEvent(masterkey_guid=new_masterkey.guid))

    async def get_masterkeys(
        self,
        guid: UUID | None = None,
        encryption_filter: EncryptionFilter = EncryptionFilter.ALL,
        backup_key_guid: UUID | None = None,
        masterkey_type: list[MasterKeyType] | None = None,
    ) -> list[MasterKey]:
        """Retrieve masterkey(s) with optional filtering.

        Args:
            guid: Optional specific masterkey GUID to retrieve. If provided, returns a list with one MasterKey or empty list.
            encryption_filter: Filter by decryption status (default: ALL). Ignored if guid is provided.
            backup_key_guid: Filter by backup key GUID (default: None for all). Ignored if guid is provided.
            masterkey_type: Filter by user account types (default: None for all). Ignored if guid is provided.

        Returns:
            A list of MasterKeys (empty list if no matches)
        """
        if not self._initialized:
            await self._initialize_storage()
        return await self._masterkey_repo.get_masterkeys(guid, encryption_filter, backup_key_guid, masterkey_type)

    async def upsert_domain_backup_key(self, backup_key: DomainBackupKey) -> int:
        """Add or update a domain backup key and decrypt all compatible masterkeys.

        This method enforces write-once semantics: once a field is set to a non-NULL value,
        it cannot be changed to a different value. Fields can only be written once.

        Args:
            backup_key: Domain backup key to add or update

        Returns:
            The ID of the inserted or updated backup key

        Raises:
            ValueError: If domain_controller is an empty string
            WriteOnceViolationError: If attempting to modify fields that already have values
        """

        if not self._initialized:
            await self._initialize_storage()

        # Validate that domain_controller is not an empty string (NULL or non-empty only)
        validate_no_empty_string(backup_key.domain_controller, "domain_controller")

        # Check write-once constraints against existing record
        existing_list = await self._backup_key_repo.get_backup_keys(guid=backup_key.guid)
        if existing_list:
            existing = existing_list[0]
            conflicts = check_write_once_conflicts(
                existing,
                backup_key,
                fields=["key_data", "domain_controller"],
            )
            if conflicts:
                raise WriteOnceViolationError("backup_key", str(backup_key.guid), conflicts)

        # Call repository to perform the upsert (repository layer also enforces write-once at SQL level)
        backup_key_id = await self._backup_key_repo.upsert_backup_key(backup_key)

        await self._publisher.publish_event(NewDomainBackupKeyEvent(backup_key_guid=backup_key.guid))

        return backup_key_id

    async def get_backup_keys(self, guid: UUID | None = None) -> list[DomainBackupKey]:
        """Retrieve domain backup key(s).

        Args:
            guid: Optional specific backup key GUID to retrieve. If provided, returns a list with one key or empty list.

        Returns:
            A list of DomainBackupKey objects (empty list if no matches)
        """
        if not self._initialized:
            await self._initialize_storage()

        return await self._backup_key_repo.get_backup_keys(guid)

    async def upsert_system_credential(self, cred: DpapiSystemCredential) -> None:
        """Add or update a DPAPI system credential.

        Args:
            cred: DPAPI system credential to add or update
        """
        if not self._initialized:
            await self._initialize_storage()

        await self._dpapi_system_cred_repo.upsert_credential(cred)
        await self._publisher.publish_event(NewDpapiSystemCredentialEvent(credential=cred))

    async def get_system_credentials(self, guid: UUID | None = None) -> list[DpapiSystemCredential]:
        """Retrieve DPAPI system credential(s).

        Args:
            guid: Optional specific credential GUID to retrieve. If provided, returns a list with one credential or empty list.

        Returns:
            A list of DpapiSystemCredential objects (empty list if no matches)
        """
        if not self._initialized:
            await self._initialize_storage()

        if guid is not None:
            credential = await self._dpapi_system_cred_repo.get_credential(guid)
            return [credential] if credential else []

        return await self._dpapi_system_cred_repo.get_all_credentials()

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
        masterkeys = await self._masterkey_repo.get_masterkeys(guid=blob.masterkey_guid)
        if not masterkeys:
            raise MasterKeyNotFoundError(blob.masterkey_guid)

        masterkey = masterkeys[0]
        if not masterkey.is_decrypted:
            raise MasterKeyNotDecryptedError(blob.masterkey_guid)

        return blob.decrypt(masterkey)

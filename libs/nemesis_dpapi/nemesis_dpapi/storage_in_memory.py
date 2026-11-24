"""Storage backend implementations.

Every repository is scoped to a project: entries are keyed by (project, ...) and reads only see the caller's project.
"""

from uuid import UUID

from .core import MasterKey, MasterKeyType
from .exceptions import StorageError, WriteOnceViolationError
from .keys import DomainBackupKey, DpapiSystemCredential
from .repositories import EncryptionFilter
from .validation import check_write_once_conflicts


class InMemoryMasterKeyRepository:
    """In-memory storage for masterkeys."""

    def __init__(self) -> None:
        self._masterkeys: dict[tuple[str, UUID], MasterKey] = {}

    async def upsert_masterkey(self, masterkey: MasterKey, *, project: str) -> None:
        """Add or update a project's masterkey with write-once semantics.

        Write-once enforcement: Fields can only be set once. Once a field has a non-NULL value,
        it cannot be changed to a different value (including NULL).

        Raises:
            WriteOnceViolationError: If attempting to modify fields that already have values
        """
        key = (project, masterkey.guid)
        if key in self._masterkeys:
            existing = self._masterkeys[key]

            # Check write-once constraints - ensure consistency with PostgreSQL implementation
            conflicts = check_write_once_conflicts(
                existing,
                masterkey,
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
                raise WriteOnceViolationError("masterkey", str(masterkey.guid), conflicts)

        # Insert or update (only reached if no conflicts)
        self._masterkeys[key] = masterkey

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
            project: Only masterkeys stored for this project are returned.
            encryption_filter: Filter by decryption status (default: ALL). Ignored if guid is provided.
            backup_key_guid: Filter by backup key GUID (default: None for all). Ignored if guid is provided.
            masterkey_type: Filter by user account types (default: None for all). Ignored if guid is provided.

        Returns:
            A list of MasterKeys (empty list if no matches)
        """
        # If guid is provided, return single masterkey as a list
        if guid is not None:
            mk = self._masterkeys.get((project, guid))
            return [mk] if mk is not None else []

        # Otherwise, return filtered list
        masterkeys = [mk for (mk_project, _), mk in self._masterkeys.items() if mk_project == project]

        # Filter by decryption status
        if encryption_filter == EncryptionFilter.ENCRYPTED_ONLY:
            masterkeys = [mk for mk in masterkeys if not mk.is_decrypted]
        elif encryption_filter == EncryptionFilter.DECRYPTED_ONLY:
            masterkeys = [mk for mk in masterkeys if mk.is_decrypted]

        # Filter by backup key GUID
        if backup_key_guid is not None:
            masterkeys = [mk for mk in masterkeys if mk.backup_key_guid == backup_key_guid]

        # Filter by user account type
        if masterkey_type is not None and len(masterkey_type) > 0:
            masterkeys = [mk for mk in masterkeys if mk.masterkey_type in masterkey_type]

        return masterkeys

    async def delete_masterkey(self, guid: UUID, *, project: str) -> None:
        """Delete a project's masterkey by GUID."""
        if (project, guid) not in self._masterkeys:
            raise StorageError(f"Masterkey {guid} not found in project {project!r}")
        del self._masterkeys[(project, guid)]


class InMemoryDomainBackupKeyRepository:
    """In-memory storage for domain backup keys."""

    def __init__(self) -> None:
        self._backup_keys: dict[tuple[str, UUID], DomainBackupKey] = {}
        self._backup_key_ids: dict[tuple[str, UUID], int] = {}
        self._next_id: int = 1

    async def upsert_backup_key(self, key: DomainBackupKey, *, project: str) -> int:
        """Add or update a project's domain backup key with write-once semantics.

        Write-once enforcement: Fields can only be set once. Once a field has a non-NULL value,
        it cannot be changed to a different value (including NULL).

        Returns:
            The ID of the inserted or updated backup key

        Raises:
            WriteOnceViolationError: If attempting to modify fields that already have values
        """
        store_key = (project, key.guid)
        if store_key in self._backup_keys:
            existing = self._backup_keys[store_key]

            # Check write-once constraints - ensure consistency with PostgreSQL implementation
            conflicts = check_write_once_conflicts(
                existing,
                key,
                fields=["key_data", "domain_controller"],
            )

            if conflicts:
                raise WriteOnceViolationError("backup_key", str(key.guid), conflicts)

            # Update existing key, return existing ID
            self._backup_keys[store_key] = key
            return self._backup_key_ids[store_key]

        # Insert new key with new ID
        key_id = self._next_id
        self._next_id += 1
        self._backup_keys[store_key] = key
        self._backup_key_ids[store_key] = key_id
        return key_id

    async def get_backup_keys(self, guid: UUID | None = None, *, project: str) -> list[DomainBackupKey]:
        """Retrieve a project's backup key(s).

        Args:
            guid: Optional specific backup key GUID to retrieve. If provided, returns a list with one key or empty list.
            project: Only backup keys stored for this project are returned.

        Returns:
            A list of DomainBackupKey objects (empty list if no matches)
        """
        if guid is not None:
            key = self._backup_keys.get((project, guid))
            return [key] if key is not None else []

        return [key for (key_project, _), key in self._backup_keys.items() if key_project == project]

    async def delete_backup_key(self, guid: UUID, *, project: str) -> None:
        """Delete a project's backup key by GUID."""
        if (project, guid) not in self._backup_keys:
            raise StorageError(f"Domain backup key {guid} not found in project {project!r}")
        del self._backup_keys[(project, guid)]


class InMemoryDpapiSystemCredentialRepository:
    """In-memory storage for DPAPI system credentials."""

    def __init__(self) -> None:
        self._credentials: dict[str, list[DpapiSystemCredential]] = {}

    async def upsert_credential(self, cred: DpapiSystemCredential, *, project: str) -> None:
        """Add or update a project's DPAPI system credential."""
        credentials = self._credentials.setdefault(project, [])
        for i, existing_cred in enumerate(credentials):
            if existing_cred.user_key == cred.user_key and existing_cred.machine_key == cred.machine_key:
                credentials[i] = cred
                return
        credentials.append(cred)

    async def get_all_credentials(self, *, project: str) -> list[DpapiSystemCredential]:
        """Retrieve all of a project's DPAPI system credentials."""
        return list(self._credentials.get(project, []))

    async def delete_all_credentials(self, *, project: str) -> None:
        """Delete all of a project's DPAPI system credentials."""
        self._credentials.pop(project, None)

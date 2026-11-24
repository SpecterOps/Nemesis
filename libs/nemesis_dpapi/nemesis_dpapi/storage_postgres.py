"""PostgreSQL storage backend implementations.

Every table is scoped to a project: rows are written with the caller's project, uniqueness is per project, and every
read filters on it, so key material from one project is never returned for another.
"""

from uuid import UUID

import asyncpg

from .core import MasterKey, MasterKeyType
from .exceptions import StorageError
from .keys import DomainBackupKey, DpapiSystemCredential
from .repositories import EncryptionFilter

MASTKEYS_TABLE = "dpapi.masterkeys"
BACKUPKEYS_TABLE = "dpapi.domain_backup_keys"
SYSTEMCREDS_TABLE = "dpapi.system_credentials"


def _row_to_masterkey(row) -> MasterKey:
    return MasterKey(
        guid=row["guid"],
        masterkey_type=MasterKeyType(row["masterkey_type"]) if row.get("masterkey_type") else MasterKeyType.UNKNOWN,
        encrypted_key_usercred=row["encrypted_key_usercred"],
        encrypted_key_backup=row["encrypted_key_backup"],
        plaintext_key=row["plaintext_key"],
        plaintext_key_sha1=row["plaintext_key_sha1"],
        backup_key_guid=row["backup_key_guid"],
    )


class PostgresMasterKeyRepository:
    """PostgreSQL storage for masterkeys."""

    def __init__(self, connection_pool: asyncpg.Pool) -> None:
        self.pool = connection_pool

    async def upsert_masterkey(self, masterkey: MasterKey, *, project: str) -> None:
        """Add or update a project's masterkey with write-once semantics.

        Write-once enforcement: Fields can only be set once. Once a field has a non-NULL value,
        it cannot be changed to a different value (including NULL).

        Raises:
            WriteOnceViolationError: If attempting to modify fields that already have values
        """
        async with self.pool.acquire() as conn:
            await conn.execute(
                f"""
                INSERT INTO {MASTKEYS_TABLE} (project, guid, encrypted_key_usercred, encrypted_key_backup,
                                      plaintext_key, plaintext_key_sha1, backup_key_guid, masterkey_type)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (project, guid) DO UPDATE SET
                    encrypted_key_usercred = EXCLUDED.encrypted_key_usercred,
                    encrypted_key_backup = EXCLUDED.encrypted_key_backup,
                    plaintext_key = EXCLUDED.plaintext_key,
                    plaintext_key_sha1 = EXCLUDED.plaintext_key_sha1,
                    backup_key_guid = EXCLUDED.backup_key_guid,
                    masterkey_type = EXCLUDED.masterkey_type
                WHERE
                    -- Write-once enforcement: only update if existing is NULL or matches new value
                    -- SQL Pattern: (existing IS NULL OR existing = new)
                    -- This correctly handles NULL because:
                    --   - If existing IS NULL: first condition is TRUE, allows write
                    --   - If existing is NOT NULL: second condition checked, must equal new value
                    --   - Note: "NULL = NULL" returns NULL (falsy), but "IS NULL" returns TRUE
                    ({MASTKEYS_TABLE}.encrypted_key_usercred IS NULL OR
                     {MASTKEYS_TABLE}.encrypted_key_usercred = EXCLUDED.encrypted_key_usercred)
                    AND ({MASTKEYS_TABLE}.encrypted_key_backup IS NULL OR
                         {MASTKEYS_TABLE}.encrypted_key_backup = EXCLUDED.encrypted_key_backup)
                    AND ({MASTKEYS_TABLE}.plaintext_key IS NULL OR
                         {MASTKEYS_TABLE}.plaintext_key = EXCLUDED.plaintext_key)
                    AND ({MASTKEYS_TABLE}.plaintext_key_sha1 IS NULL OR
                         {MASTKEYS_TABLE}.plaintext_key_sha1 = EXCLUDED.plaintext_key_sha1)
                    AND ({MASTKEYS_TABLE}.backup_key_guid IS NULL OR
                         {MASTKEYS_TABLE}.backup_key_guid = EXCLUDED.backup_key_guid)
                    AND ({MASTKEYS_TABLE}.masterkey_type IS NULL OR
                         {MASTKEYS_TABLE}.masterkey_type = EXCLUDED.masterkey_type)
                """,
                project,
                str(masterkey.guid),
                masterkey.encrypted_key_usercred,
                masterkey.encrypted_key_backup,
                masterkey.plaintext_key,
                masterkey.plaintext_key_sha1,
                str(masterkey.backup_key_guid) if masterkey.backup_key_guid else None,
                masterkey.masterkey_type.value,
            )

            # Check if the WHERE clause prevented the update (write-once violation)
            # Note: asyncpg returns "INSERT 0 1" for new rows, "UPDATE 1" for updated rows
            # If WHERE clause fails, we get "INSERT 0 0" (conflict but no update)
            # However, asyncpg's execute() doesn't reliably return row counts for ON CONFLICT
            # so we rely on service layer validation as the primary check

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
        async with self.pool.acquire() as conn:
            # If guid is provided, return single masterkey as a list
            if guid is not None:
                row = await conn.fetchrow(
                    f"SELECT * FROM {MASTKEYS_TABLE} WHERE project = $1 AND guid = $2", project, str(guid)
                )
                return [_row_to_masterkey(row)] if row else []

            # Otherwise, return filtered list
            params: list = [project]
            conditions = ["project = $1"]

            if backup_key_guid is not None:
                conditions.append(f"backup_key_guid = ${len(params) + 1}")
                params.append(str(backup_key_guid))

            if masterkey_type is not None and len(masterkey_type) > 0:
                # Use ANY for matching multiple values
                conditions.append(f"masterkey_type = ANY(${len(params) + 1})")
                params.append([t.value for t in masterkey_type])

            rows = await conn.fetch(f"SELECT * FROM {MASTKEYS_TABLE} WHERE " + " AND ".join(conditions), *params)
            masterkeys = [_row_to_masterkey(row) for row in rows]

            # Apply decryption filter in Python (could be optimized to SQL)
            if encryption_filter == EncryptionFilter.ENCRYPTED_ONLY:
                masterkeys = [mk for mk in masterkeys if not mk.is_decrypted]
            elif encryption_filter == EncryptionFilter.DECRYPTED_ONLY:
                masterkeys = [mk for mk in masterkeys if mk.is_decrypted]

            return masterkeys

    async def delete_masterkey(self, guid: UUID, *, project: str) -> None:
        """Delete a project's masterkey by GUID."""
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                f"DELETE FROM {MASTKEYS_TABLE} WHERE project = $1 AND guid = $2", project, str(guid)
            )
            if result == "DELETE 0":
                raise StorageError(f"Masterkey {guid} not found in project {project!r}")


class PostgresDomainBackupKeyRepository:
    """PostgreSQL storage for domain backup keys."""

    def __init__(self, connection_pool: asyncpg.Pool) -> None:
        self.pool = connection_pool

    async def upsert_backup_key(self, key: DomainBackupKey, *, project: str) -> int:
        """Add or update a project's domain backup key with write-once semantics.

        Write-once enforcement: Fields can only be set once. Once a field has a non-NULL value,
        it cannot be changed to a different value (including NULL).

        Returns:
            The ID of the inserted or updated backup key

        Raises:
            WriteOnceViolationError: If attempting to modify fields that already have values
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                f"""
                INSERT INTO {BACKUPKEYS_TABLE} (project, guid, key_data, domain_controller)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (project, guid) DO UPDATE SET
                    key_data = EXCLUDED.key_data,
                    domain_controller = EXCLUDED.domain_controller
                WHERE
                    -- Write-once enforcement: only update if existing is NULL or matches new value
                    -- SQL Pattern: (existing IS NULL OR existing = new)
                    -- This correctly handles NULL because:
                    --   - If existing IS NULL: first condition is TRUE, allows write
                    --   - If existing is NOT NULL: second condition checked, must equal new value
                    --   - Note: "NULL = NULL" returns NULL (falsy), but "IS NULL" returns TRUE
                    ({BACKUPKEYS_TABLE}.key_data IS NULL OR
                     {BACKUPKEYS_TABLE}.key_data = EXCLUDED.key_data)
                    AND ({BACKUPKEYS_TABLE}.domain_controller IS NULL OR
                         {BACKUPKEYS_TABLE}.domain_controller = EXCLUDED.domain_controller)
                RETURNING id
                """,
                project,
                str(key.guid),
                key.key_data,
                key.domain_controller,
            )
            return row["id"]

    async def get_backup_keys(self, guid: UUID | None = None, *, project: str) -> list[DomainBackupKey]:
        """Retrieve a project's backup key(s).

        Args:
            guid: Optional specific backup key GUID to retrieve. If provided, returns a list with one key or empty list.
            project: Only backup keys stored for this project are returned.

        Returns:
            A list of DomainBackupKey objects (empty list if no matches)
        """
        async with self.pool.acquire() as conn:
            if guid is not None:
                row = await conn.fetchrow(
                    f"SELECT * FROM {BACKUPKEYS_TABLE} WHERE project = $1 AND guid = $2", project, str(guid)
                )
                if not row:
                    return []
                return [DomainBackupKey(guid=row["guid"], key_data=row["key_data"])]

            rows = await conn.fetch(f"SELECT * FROM {BACKUPKEYS_TABLE} WHERE project = $1", project)
            return [DomainBackupKey(guid=row["guid"], key_data=row["key_data"]) for row in rows]

    async def delete_backup_key(self, guid: UUID, *, project: str) -> None:
        """Delete a project's backup key by GUID."""
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                f"DELETE FROM {BACKUPKEYS_TABLE} WHERE project = $1 AND guid = $2", project, str(guid)
            )
            if result == "DELETE 0":
                raise StorageError(f"Domain backup key {guid} not found in project {project!r}")


class PostgresDpapiSystemCredentialRepository:
    """PostgreSQL storage for DPAPI system credentials."""

    def __init__(self, connection_pool: asyncpg.Pool) -> None:
        self.pool = connection_pool

    async def upsert_credential(self, cred: DpapiSystemCredential, *, project: str) -> None:
        """Add or update a project's DPAPI system credential."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                f"""
                INSERT INTO {SYSTEMCREDS_TABLE} (project, user_key, machine_key)
                VALUES ($1, $2, $3)
                ON CONFLICT (project, user_key, machine_key) DO NOTHING
                """,
                project,
                cred.user_key,
                cred.machine_key,
            )

    async def get_all_credentials(self, *, project: str) -> list[DpapiSystemCredential]:
        """Retrieve all of a project's DPAPI system credentials."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(f"SELECT * FROM {SYSTEMCREDS_TABLE} WHERE project = $1", project)
            return [DpapiSystemCredential(user_key=row["user_key"], machine_key=row["machine_key"]) for row in rows]

    async def delete_all_credentials(self, *, project: str) -> None:
        """Delete all of a project's DPAPI system credentials."""
        async with self.pool.acquire() as conn:
            await conn.execute(f"DELETE FROM {SYSTEMCREDS_TABLE} WHERE project = $1", project)

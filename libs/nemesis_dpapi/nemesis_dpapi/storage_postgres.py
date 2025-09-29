"""PostgreSQL storage backend implementations."""

from uuid import UUID

import asyncpg

from .core import MasterKey
from .exceptions import StorageError
from .keys import DomainBackupKey, DpapiSystemCredential
from .repositories import MasterKeyFilter

MASTKEYS_TABLE = "dpapi.masterkeys"
BACKUPKEYS_TABLE = "dpapi.domain_backup_keys"
SYSTEMCREDS_TABLE = "dpapi.system_credentials"


class PostgresMasterKeyRepository:
    """PostgreSQL storage for masterkeys."""

    def __init__(self, connection_pool: asyncpg.Pool) -> None:
        self.pool = connection_pool

    async def upsert_masterkey(self, masterkey: MasterKey) -> None:
        """Add or update a masterkey in storage."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                f"""
                INSERT INTO {MASTKEYS_TABLE} (guid, encrypted_key_usercred, encrypted_key_backup,
                                      plaintext_key, plaintext_key_sha1, backup_key_guid)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (guid) DO UPDATE SET
                    encrypted_key_usercred = EXCLUDED.encrypted_key_usercred,
                    encrypted_key_backup = EXCLUDED.encrypted_key_backup,
                    plaintext_key = EXCLUDED.plaintext_key,
                    plaintext_key_sha1 = EXCLUDED.plaintext_key_sha1,
                    backup_key_guid = EXCLUDED.backup_key_guid
                """,
                str(masterkey.guid),
                masterkey.encrypted_key_usercred,
                masterkey.encrypted_key_backup,
                masterkey.plaintext_key,
                masterkey.plaintext_key_sha1,
                str(masterkey.backup_key_guid) if masterkey.backup_key_guid else None,
            )

    async def get_masterkey(self, guid: UUID) -> MasterKey | None:
        """Retrieve a masterkey by GUID."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(f"SELECT * FROM {MASTKEYS_TABLE} WHERE guid = $1", str(guid))
            if not row:
                return None

            return MasterKey(
                guid=UUID(row["guid"]),
                encrypted_key_usercred=row["encrypted_key_usercred"],
                encrypted_key_backup=row["encrypted_key_backup"],
                plaintext_key=row["plaintext_key"],
                plaintext_key_sha1=row["plaintext_key_sha1"],
                backup_key_guid=UUID(row["backup_key_guid"]) if row["backup_key_guid"] else None,
            )

    async def get_all_masterkeys(
        self, filter_by: MasterKeyFilter = MasterKeyFilter.ALL, backup_key_guid: UUID | None = None
    ) -> list[MasterKey]:
        """Retrieve masterkeys with optional filtering."""
        async with self.pool.acquire() as conn:
            # Build query based on filters
            query = f"SELECT * FROM {MASTKEYS_TABLE}"
            params = []
            conditions = []

            if backup_key_guid is not None:
                conditions.append("backup_key_guid = $1")
                params.append(str(backup_key_guid))

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            rows = await conn.fetch(query, *params)
            masterkeys = [
                MasterKey(
                    guid=UUID(row["guid"]),
                    encrypted_key_usercred=row["encrypted_key_usercred"],
                    encrypted_key_backup=row["encrypted_key_backup"],
                    plaintext_key=row["plaintext_key"],
                    plaintext_key_sha1=row["plaintext_key_sha1"],
                    backup_key_guid=UUID(row["backup_key_guid"]) if row["backup_key_guid"] else None,
                )
                for row in rows
            ]

            # Apply decryption filter in Python (could be optimized to SQL)
            if filter_by == MasterKeyFilter.ENCRYPTED_ONLY:
                masterkeys = [mk for mk in masterkeys if not mk.is_decrypted]
            elif filter_by == MasterKeyFilter.DECRYPTED_ONLY:
                masterkeys = [mk for mk in masterkeys if mk.is_decrypted]

            return masterkeys

    async def delete_masterkey(self, guid: UUID) -> None:
        """Delete a masterkey by GUID."""
        async with self.pool.acquire() as conn:
            result = await conn.execute(f"DELETE FROM {MASTKEYS_TABLE} WHERE guid = $1", str(guid))
            if result == "DELETE 0":
                raise StorageError(f"Masterkey {guid} not found")


class PostgresDomainBackupKeyRepository:
    """PostgreSQL storage for domain backup keys."""

    def __init__(self, connection_pool: asyncpg.Pool) -> None:
        self.pool = connection_pool

    async def upsert_backup_key(self, key: DomainBackupKey) -> None:
        """Add or update a domain backup key in storage."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                f"""
                INSERT INTO {BACKUPKEYS_TABLE} (guid, key_data)
                VALUES ($1, $2)
                ON CONFLICT (guid) DO UPDATE SET
                    key_data = EXCLUDED.key_data
                """,
                str(key.guid),
                key.key_data,
            )

    async def get_backup_key(self, guid: UUID) -> DomainBackupKey | None:
        """Retrieve a backup key by GUID."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(f"SELECT * FROM {BACKUPKEYS_TABLE} WHERE guid = $1", str(guid))
            if not row:
                return None

            return DomainBackupKey(guid=UUID(row["guid"]), key_data=row["key_data"])

    async def get_all_backup_keys(self) -> list[DomainBackupKey]:
        """Retrieve all backup keys."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(f"SELECT * FROM {BACKUPKEYS_TABLE}")
            return [DomainBackupKey(guid=UUID(row["guid"]), key_data=row["key_data"]) for row in rows]

    async def delete_backup_key(self, guid: UUID) -> None:
        """Delete a backup key by GUID."""
        async with self.pool.acquire() as conn:
            result = await conn.execute(f"DELETE FROM {BACKUPKEYS_TABLE} WHERE guid = $1", str(guid))
            if result == "DELETE 0":
                raise StorageError(f"Domain backup key {guid} not found")


class PostgresDpapiSystemCredentialRepository:
    """PostgreSQL storage for DPAPI system credentials."""

    def __init__(self, connection_pool: asyncpg.Pool) -> None:
        self.pool = connection_pool

    async def upsert_credential(self, cred: DpapiSystemCredential) -> None:
        """Add or update a DPAPI system credential in storage."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                f"""
                INSERT INTO {SYSTEMCREDS_TABLE} (user_key, machine_key)
                VALUES ($1, $2)
                ON CONFLICT (user_key, machine_key) DO NOTHING
                """,
                cred.user_key,
                cred.machine_key,
            )

    async def get_all_credentials(self) -> list[DpapiSystemCredential]:
        """Retrieve all DPAPI system credentials."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(f"SELECT * FROM {SYSTEMCREDS_TABLE}")
            return [DpapiSystemCredential(user_key=row["user_key"], machine_key=row["machine_key"]) for row in rows]

    async def delete_all_credentials(self) -> None:
        """Delete all DPAPI system credentials."""
        async with self.pool.acquire() as conn:
            await conn.execute(f"DELETE FROM {SYSTEMCREDS_TABLE}")

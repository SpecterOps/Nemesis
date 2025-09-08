"""PostgreSQL storage backend implementations."""

from uuid import UUID

import asyncpg

from .core import DomainBackupKey, DpapiSystemCredential, MasterKey
from .exceptions import StorageError
from .repositories import MasterKeyFilter


class PostgresMasterKeyRepository:
    """PostgreSQL storage for masterkeys."""

    def __init__(self, connection_pool: asyncpg.Pool) -> None:
        self.pool = connection_pool

    async def add_masterkey(self, masterkey: MasterKey) -> None:
        """Add a masterkey to storage."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO masterkeys (guid, encrypted_key_usercred, encrypted_key_backup,
                                      plaintext_key, plaintext_key_sha1, backup_key_guid)
                VALUES ($1, $2, $3, $4, $5, $6)
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
            row = await conn.fetchrow("SELECT * FROM masterkeys WHERE guid = $1", str(guid))
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
            query = "SELECT * FROM masterkeys"
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

    async def update_masterkey(self, masterkey: MasterKey) -> None:
        """Update an existing masterkey."""
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                """
                UPDATE masterkeys
                SET encrypted_key_usercred = $2, encrypted_key_backup = $3,
                    plaintext_key = $4, plaintext_key_sha1 = $5, backup_key_guid = $6
                WHERE guid = $1
                """,
                str(masterkey.guid),
                masterkey.encrypted_key_usercred,
                masterkey.encrypted_key_backup,
                masterkey.plaintext_key,
                masterkey.plaintext_key_sha1,
                str(masterkey.backup_key_guid) if masterkey.backup_key_guid else None,
            )
            if result == "UPDATE 0":
                raise StorageError(f"Masterkey {masterkey.guid} not found")

    async def delete_masterkey(self, guid: UUID) -> None:
        """Delete a masterkey by GUID."""
        async with self.pool.acquire() as conn:
            result = await conn.execute("DELETE FROM masterkeys WHERE guid = $1", str(guid))
            if result == "DELETE 0":
                raise StorageError(f"Masterkey {guid} not found")


class PostgresDomainBackupKeyRepository:
    """PostgreSQL storage for domain backup keys."""

    def __init__(self, connection_pool: asyncpg.Pool) -> None:
        self.pool = connection_pool

    async def add_backup_key(self, key: DomainBackupKey) -> None:
        """Add a domain backup key to storage."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO domain_backup_keys (guid, key_data) VALUES ($1, $2)", str(key.guid), key.key_data
            )

    async def get_backup_key(self, guid: UUID) -> DomainBackupKey | None:
        """Retrieve a backup key by GUID."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM domain_backup_keys WHERE guid = $1", str(guid))
            if not row:
                return None

            return DomainBackupKey(guid=UUID(row["guid"]), key_data=row["key_data"])

    async def get_all_backup_keys(self) -> list[DomainBackupKey]:
        """Retrieve all backup keys."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM domain_backup_keys")
            return [DomainBackupKey(guid=UUID(row["guid"]), key_data=row["key_data"]) for row in rows]

    async def delete_backup_key(self, guid: UUID) -> None:
        """Delete a backup key by GUID."""
        async with self.pool.acquire() as conn:
            result = await conn.execute("DELETE FROM domain_backup_keys WHERE guid = $1", str(guid))
            if result == "DELETE 0":
                raise StorageError(f"Domain backup key {guid} not found")


class PostgresDpapiSystemCredentialRepository:
    """PostgreSQL storage for DPAPI system credentials."""

    def __init__(self, connection_pool: asyncpg.Pool) -> None:
        self.pool = connection_pool

    async def add_credential(self, cred: DpapiSystemCredential) -> None:
        """Add a DPAPI system credential to storage."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO dpapi_system_credentials (user_key, machine_key) VALUES ($1, $2)",
                cred.user_key,
                cred.machine_key,
            )

    async def get_all_credentials(self) -> list[DpapiSystemCredential]:
        """Retrieve all DPAPI system credentials."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM dpapi_system_credentials")
            return [DpapiSystemCredential(user_key=row["user_key"], machine_key=row["machine_key"]) for row in rows]

    async def delete_all_credentials(self) -> None:
        """Delete all DPAPI system credentials."""
        async with self.pool.acquire() as conn:
            await conn.execute("DELETE FROM dpapi_system_credentials")


async def create_tables(connection_pool: asyncpg.Pool) -> None:
    """Create database tables for DPAPI storage."""
    async with connection_pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS masterkeys (
                guid TEXT PRIMARY KEY,
                encrypted_key_usercred BYTEA,
                encrypted_key_backup BYTEA,
                plaintext_key BYTEA,
                plaintext_key_sha1 BYTEA,
                backup_key_guid TEXT
            )
        """)

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS domain_backup_keys (
                guid TEXT PRIMARY KEY,
                key_data BYTEA NOT NULL,
                domain_controller TEXT
            )
        """)

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS dpapi_system_credentials (
                id SERIAL PRIMARY KEY,
                user_key BYTEA NOT NULL,
                machine_key BYTEA NOT NULL
            )
        """)

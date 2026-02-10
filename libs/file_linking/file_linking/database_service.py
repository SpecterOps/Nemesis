"""
Database service layer for file linking system.

Handles all database operations for file_listings and file_linkings tables.
"""

from enum import StrEnum

import asyncpg
from common.logger import get_logger

logger = get_logger(__name__)


class FileListingStatus(StrEnum):
    NEEDS_TO_BE_COLLECTED = "needs_to_be_collected"
    NOT_EXISTS = "not_exists"
    COLLECTED = "collected"
    NOT_WANTED = "not_wanted"


class FileLinkingDatabaseService:
    """Service for managing file listings and linkings in the database."""

    def __init__(self, connection_pool: asyncpg.Pool):
        self.pool = connection_pool

    async def add_file_listing(
        self, source: str, path: str, status: FileListingStatus, object_id: str | None = None, conn=None
    ) -> bool:
        """
        Add or update entry in file_listings table.

        Args:
            source: Source identifier (e.g., agent_id/source)
            path: File path
            status: Current collection status
            object_id: UUID if file is already collected
            conn: Optional database connection to use (for transactions)

        Returns:
            bool: True if successful, False otherwise
        """
        if source and path:
            try:
                # Use single upsert query for better performance
                # UPDATE only executes on actual conflicts, not on every call
                upsert_query = """
                    INSERT INTO file_listings (source, path, object_id, status)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (source, path_lower)
                    DO UPDATE SET
                        object_id = CASE
                            WHEN file_listings.status = 'collected' THEN file_listings.object_id
                            ELSE EXCLUDED.object_id
                        END,
                        status = CASE
                            WHEN file_listings.status = 'collected' THEN file_listings.status
                            ELSE EXCLUDED.status
                        END,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE file_listings.status != 'collected' OR EXCLUDED.status = 'collected'
                """

                if conn:
                    # Use provided connection (part of transaction)
                    await conn.execute(upsert_query, source, path, object_id, status.value)
                else:
                    # Acquire new connection
                    async with self.pool.acquire() as conn:
                        await conn.execute(upsert_query, source, path, object_id, status.value)

                logger.debug(
                    "Added/updated file listing",
                    source=source,
                    path=path,
                    status=status.value,
                    object_id=object_id,
                )
                return True

            except Exception as e:
                logger.exception(
                    "Error adding file listing", source=source, path=path, status=status.value, error=str(e)
                )
                return False

        return False

    async def add_file_linking(
        self, source: str, file_path_1: str, file_path_2: str, link_type: str | None = None, conn=None
    ) -> bool:
        """
        Add relationship between two files in file_linkings table.

        Args:
            source: Source identifier
            file_path_1: First file path
            file_path_2: Second file path (linked to first)
            link_type: Type of relationship (optional)
            conn: Optional database connection to use (for transactions)

        Returns:
            bool: True if successful, False otherwise
        """
        if source and file_path_1 and file_path_2:
            try:
                # Use single upsert query for better performance
                # UPDATE only executes on actual conflicts, not on every call
                upsert_query = """
                    INSERT INTO file_linkings (source, file_path_1, file_path_2, link_type)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (source, file_path_1, file_path_2)
                    DO UPDATE SET
                        link_type = EXCLUDED.link_type,
                        updated_at = CURRENT_TIMESTAMP
                """

                if conn:
                    # Use provided connection (part of transaction)
                    await conn.execute(upsert_query, source, file_path_1, file_path_2, link_type)
                else:
                    # Acquire new connection
                    async with self.pool.acquire() as conn:
                        await conn.execute(upsert_query, source, file_path_1, file_path_2, link_type)

                logger.debug(
                    "Added file linking",
                    source=source,
                    file_path_1=file_path_1,
                    file_path_2=file_path_2,
                    link_type=link_type,
                )
                return True

            except Exception as e:
                logger.exception(
                    "Error adding file linking",
                    source=source,
                    file_path_1=file_path_1,
                    file_path_2=file_path_2,
                    error=str(e),
                )
                return False

        return False

    async def get_placeholder_entries(self, source: str) -> list[dict]:
        """
        Query entries containing any known placeholders for a given source.

        Dynamically reads the PLACEHOLDERS registry to build the query.

        Args:
            source: Source identifier

        Returns:
            List of dicts with 'table_name' and 'path' keys

        Example:
            [
                {'table_name': 'file_listings', 'path': '/C:/Users/<WINDOWS_USERNAME>/...'},
                {'table_name': 'file_linkings', 'path': '/C:/Users/<WINDOWS_SECURITY_IDENTIFIER>/...'}
            ]
        """
        try:
            # Import PLACEHOLDERS dynamically to avoid circular dependency
            from .placeholder_resolver import PLACEHOLDERS

            if not PLACEHOLDERS:
                return []

            # Build LIKE conditions from PLACEHOLDERS array for each table
            placeholder_conditions_listings = " OR ".join(
                [f"file_listings.path LIKE '%{p.name}%'" for p in PLACEHOLDERS]
            )
            placeholder_conditions_linkings = " OR ".join(
                [f"file_linkings.file_path_2 LIKE '%{p.name}%'" for p in PLACEHOLDERS]
            )

            query = f"""
                SELECT 'file_listings' as table_name, path
                FROM file_listings
                WHERE source = $1 AND ({placeholder_conditions_listings})
                UNION
                SELECT 'file_linkings' as table_name, file_path_2 as path
                FROM file_linkings
                WHERE source = $1 AND ({placeholder_conditions_linkings})
            """

            # Use asyncpg for async operations
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(query, source)
                results = [{"table_name": row["table_name"], "path": row["path"]} for row in rows]

                logger.debug(
                    "Queried placeholder entries",
                    source=source,
                    count=len(results),
                )
                return results

        except Exception as e:
            logger.exception("Error querying placeholder entries", source=source, error=str(e))
            return []

    async def get_collected_files(self, source: str) -> list[str]:
        """
        Get all file paths that have been collected for a given source.

        Used for backward resolution to check if a real file exists
        before inserting a placeholder path.

        Args:
            source: Source identifier

        Returns:
            List of file paths with status='collected'
        """
        try:
            query = """
                SELECT DISTINCT path
                FROM file_listings
                WHERE source = $1
                AND status = 'collected'
                AND object_id IS NOT NULL
            """

            async with self.pool.acquire() as conn:
                rows = await conn.fetch(query, source)
                paths = [row["path"] for row in rows]

                logger.debug(
                    "Queried collected files",
                    source=source,
                    count=len(paths),
                )
                return paths

        except Exception as e:
            logger.exception("Error querying collected files", source=source, error=str(e))
            return []

    async def update_file_listing_path(self, source: str, old_path: str, new_path: str, conn=None) -> bool:
        """
        Update path in file_listings table.

        Used to replace placeholder paths with resolved real paths.

        Args:
            source: Source identifier
            old_path: Current path (with placeholders)
            new_path: New path (resolved)
            conn: Optional database connection to use (for transactions)

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            query = """
                UPDATE file_listings
                SET path = $3, updated_at = CURRENT_TIMESTAMP
                WHERE source = $1 AND LOWER(path) = LOWER($2)
            """

            if conn:
                # Use provided connection (part of transaction)
                result = await conn.execute(query, source, old_path, new_path)
            else:
                # Acquire new connection
                async with self.pool.acquire() as conn:
                    result = await conn.execute(query, source, old_path, new_path)

            logger.info(
                "Updated file listing path",
                source=source,
                old_path=old_path,
                new_path=new_path,
                result=result,
            )
            return True

        except Exception as e:
            logger.exception(
                "Error updating file listing path",
                source=source,
                old_path=old_path,
                new_path=new_path,
                error=str(e),
            )
            return False

    async def update_file_linking_path(self, source: str, old_path: str, new_path: str, conn=None) -> bool:
        """
        Update file_path_2 in file_linkings table.

        Used to replace placeholder paths with resolved real paths.

        Args:
            source: Source identifier
            old_path: Current path (with placeholders)
            new_path: New path (resolved)
            conn: Optional database connection to use (for transactions)

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            query = """
                UPDATE file_linkings
                SET file_path_2 = $3, updated_at = CURRENT_TIMESTAMP
                WHERE source = $1 AND LOWER(file_path_2) = LOWER($2)
            """

            if conn:
                # Use provided connection (part of transaction)
                result = await conn.execute(query, source, old_path, new_path)
            else:
                # Acquire new connection
                async with self.pool.acquire() as conn:
                    result = await conn.execute(query, source, old_path, new_path)

            logger.info(
                "Updated file linking path",
                source=source,
                old_path=old_path,
                new_path=new_path,
                result=result,
            )
            return True

        except Exception as e:
            logger.exception(
                "Error updating file linking path",
                source=source,
                old_path=old_path,
                new_path=new_path,
                error=str(e),
            )
            return False

"""
Database service layer for file linking system.

Handles all database operations for file_listings and file_linkings tables.
"""

from enum import Enum
from typing import Any

import psycopg
import structlog

logger = structlog.get_logger(module=__name__)


def _normalize_file_path(path: str) -> str:
    """Normalize file path to use forward slashes for consistent storage."""
    return path.replace("\\", "/")


class FileListingStatus(str, Enum):
    NEEDS_TO_BE_COLLECTED = "needs_to_be_collected"
    NOT_EXISTS = "not_exists"
    COLLECTED = "collected"
    NOT_WANTED = "not_wanted"


class FileLinkingDatabaseService:
    """Service for managing file listings and linkings in the database."""

    def __init__(self, postgres_connection_string: str):
        self.connection_string = postgres_connection_string

    def add_file_listing(self, source: str, path: str, status: FileListingStatus, object_id: str | None = None) -> bool:
        """
        Add or update entry in file_listings table.

        Args:
            source: Source identifier (e.g., agent_id/source)
            path: File path
            status: Current collection status
            object_id: UUID if file is already collected

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with psycopg.connect(self.connection_string) as conn:
                with conn.cursor() as cur:
                    query = """
                        INSERT INTO file_listings (source, path, object_id, status)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (source, path_lower) DO UPDATE SET
                            object_id = EXCLUDED.object_id,
                            status = EXCLUDED.status,
                            updated_at = CURRENT_TIMESTAMP
                    """

                    cur.execute(query, (source, _normalize_file_path(path), object_id, status.value))
                    conn.commit()

                    logger.debug(
                        "Added/updated file listing", source=source, path=path, status=status.value, object_id=object_id
                    )
                    return True

        except Exception as e:
            logger.exception("Error adding file listing", source=source, path=path, status=status.value, error=str(e))
            return False

    def add_file_linking(self, source: str, file_path_1: str, file_path_2: str, link_type: str | None = None) -> bool:
        """
        Add relationship between two files in file_linkings table.

        Args:
            source: Source identifier
            file_path_1: First file path
            file_path_2: Second file path (linked to first)
            link_type: Type of relationship (optional)

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with psycopg.connect(self.connection_string) as conn:
                with conn.cursor() as cur:
                    query = """
                        INSERT INTO file_linkings (source, file_path_1, file_path_2, link_type)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (source, file_path_1, file_path_2) DO UPDATE SET
                            link_type = EXCLUDED.link_type,
                            updated_at = CURRENT_TIMESTAMP
                    """

                    cur.execute(
                        query, (source, _normalize_file_path(file_path_1), _normalize_file_path(file_path_2), link_type)
                    )
                    conn.commit()

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

    def update_listing_status(
        self, source: str, path: str, new_status: FileListingStatus, object_id: str | None = None
    ) -> bool:
        """
        Update status of existing file listing.

        Args:
            source: Source identifier
            path: File path
            new_status: New status to set
            object_id: UUID if file was collected

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with psycopg.connect(self.connection_string) as conn:
                with conn.cursor() as cur:
                    query = """
                        UPDATE file_listings
                        SET status = %s, object_id = %s, updated_at = CURRENT_TIMESTAMP
                        WHERE source = %s AND path_lower = LOWER(%s)
                    """

                    cur.execute(query, (new_status.value, object_id, source, _normalize_file_path(path)))
                    conn.commit()

                    if cur.rowcount > 0:
                        logger.debug(
                            "Updated file listing status",
                            source=source,
                            path=path,
                            new_status=new_status.value,
                            object_id=object_id,
                        )
                        return True
                    else:
                        logger.warning("No file listing found to update", source=source, path=path)
                        return False

        except Exception as e:
            logger.exception(
                "Error updating file listing status",
                source=source,
                path=path,
                new_status=new_status.value,
                error=str(e),
            )
            return False

    def get_file_listings_by_source(self, source: str) -> list[dict[str, Any]]:
        """
        Get all file listings for a specific source.

        Args:
            source: Source identifier

        Returns:
            List of file listing records
        """
        try:
            with psycopg.connect(self.connection_string) as conn:
                with conn.cursor() as cur:
                    query = """
                        SELECT listing_id, source, path, object_id, status, created_at, updated_at
                        FROM file_listings
                        WHERE source = %s
                        ORDER BY created_at DESC
                    """

                    cur.execute(query, (source,))
                    rows = cur.fetchall()

                    columns = [desc[0] for desc in cur.description]
                    return [dict(zip(columns, row)) for row in rows]

        except Exception as e:
            logger.exception("Error getting file listings by source", source=source, error=str(e))
            return []

    def get_linked_files(self, source: str, file_path: str) -> list[dict[str, Any]]:
        """
        Get all files linked to a specific file path.

        Args:
            source: Source identifier
            file_path: File path to find links for

        Returns:
            List of linked file records
        """
        try:
            with psycopg.connect(self.connection_string) as conn:
                with conn.cursor() as cur:
                    query = """
                        SELECT linking_id, source, file_path_1, file_path_2, link_type, created_at
                        FROM file_linkings
                        WHERE source = %s AND (file_path_1 = %s OR file_path_2 = %s)
                        ORDER BY created_at DESC
                    """

                    cur.execute(query, (source, _normalize_file_path(file_path), _normalize_file_path(file_path)))
                    rows = cur.fetchall()

                    columns = [desc[0] for desc in cur.description]
                    return [dict(zip(columns, row)) for row in rows]

        except Exception as e:
            logger.exception("Error getting linked files", source=source, file_path=file_path, error=str(e))
            return []

    def bulk_add_linkings(self, linkings: list[dict[str, Any]]) -> int:
        """
        Add multiple file linkings in a single transaction.

        Args:
            linkings: List of linking dictionaries with keys:
                     source, file_path_1, file_path_2, link_type

        Returns:
            int: Number of linkings successfully added
        """
        if not linkings:
            return 0

        try:
            with psycopg.connect(self.connection_string) as conn:
                with conn.cursor() as cur:
                    query = """
                        INSERT INTO file_linkings (source, file_path_1, file_path_2, link_type)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (source, file_path_1, file_path_2) DO UPDATE SET
                            link_type = EXCLUDED.link_type,
                            updated_at = CURRENT_TIMESTAMP
                    """

                    values = []
                    for linking in linkings:
                        values.append(
                            (
                                linking["source"],
                                _normalize_file_path(linking["file_path_1"]),
                                _normalize_file_path(linking["file_path_2"]),
                                linking.get("link_type"),
                            )
                        )

                    cur.executemany(query, values)
                    conn.commit()

                    logger.debug("Bulk added file linkings", count=len(linkings))
                    return len(linkings)

        except Exception as e:
            logger.exception("Error bulk adding file linkings", count=len(linkings), error=str(e))
            return 0

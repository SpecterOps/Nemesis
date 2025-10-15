"""
Database service layer for file linking system.

Handles all database operations for file_listings and file_linkings tables.
"""

from enum import Enum

import psycopg
from common.logger import get_logger

logger = get_logger(__name__)


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
        if source and path:
            try:
                with psycopg.connect(self.connection_string) as conn:
                    with conn.cursor() as cur:
                        query = """
                            INSERT INTO file_listings (source, path, object_id, status)
                            VALUES (%s, %s, %s, %s)
                            ON CONFLICT (source, path_lower) DO UPDATE SET
                                object_id = CASE
                                    WHEN file_listings.status = 'collected' THEN file_listings.object_id
                                    ELSE EXCLUDED.object_id
                                END,
                                status = CASE
                                    WHEN file_listings.status = 'collected' THEN file_listings.status
                                    ELSE EXCLUDED.status
                                END,
                                updated_at = CURRENT_TIMESTAMP
                        """

                        cur.execute(query, (source, path, object_id, status.value))
                        conn.commit()

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
            finally:
                conn.close()

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
        if source and file_path_1 and file_path_2:
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
                            query,
                            (source, file_path_1, file_path_2, link_type),
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

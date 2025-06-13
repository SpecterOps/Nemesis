import logging
from typing import Optional

import plyvel

logger = logging.getLogger(__name__)


class Database:
    """A wrapper around LevelDB providing Redis-like functionality.

    This class abstracts the database operations and provides a simpler interface
    for storing and retrieving data. It includes proper error handling and logging.
    """

    def __init__(self, path: str):
        """Initialize the database connection.

        Args:
            path: Path to the LevelDB database
        """
        self.db = plyvel.DB(path, create_if_missing=True)

    def get(self, key: str) -> Optional[int]:
        """Get an integer value from the database.

        Args:
            key: The key to retrieve

        Returns:
            The integer value if found, None otherwise
        """
        try:
            value = self.db.get(str(key).encode("utf-8"))
            return int(value.decode("utf-8")) if value else None
        except Exception as e:
            logger.error(f"Error getting key {key}: {e}")
            return None

    def mset(self, mapping: dict[str, int]) -> None:
        """Set multiple key-value pairs atomically.

        Args:
            mapping: Dictionary of key-value pairs to set
        """
        try:
            with self.db.write_batch() as batch:
                for key, value in mapping.items():
                    batch.put(str(key).encode("utf-8"), str(value).encode("utf-8"))
        except Exception as e:
            logger.error(f"Error setting values: {e}")

    def delete(self, key: str) -> None:
        """Delete a key from the database.

        Args:
            key: The key to delete
        """
        try:
            self.db.delete(str(key).encode("utf-8"))
        except Exception as e:
            logger.error(f"Error deleting key {key}: {e}")

    def close(self) -> None:
        """Close the database connection."""
        self.db.close()

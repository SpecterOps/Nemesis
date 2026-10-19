import logging

import plyvel

logger = logging.getLogger(__name__)


class DatabaseError(RuntimeError):
    """A LevelDB operation failed; progress must stop rather than be skipped."""


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

    def get(self, key: str) -> int | None:
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

    def get_strict(self, key: str) -> bytes | None:
        """Read raw bytes and propagate storage errors to the supervisor."""
        try:
            return self.db.get(str(key).encode("utf-8"))
        except Exception as exc:
            raise DatabaseError(f"LevelDB read failed for key {key!r}") from exc

    def write_batch(self, puts: dict[str, str | bytes], deletes: list[str] | None = None) -> None:
        """Atomically apply string/byte values and deletions, raising on failure."""
        try:
            with self.db.write_batch(transaction=True, sync=True) as batch:
                for key, value in puts.items():
                    encoded = value.encode("utf-8") if isinstance(value, str) else value
                    batch.put(str(key).encode("utf-8"), encoded)
                for key in deletes or []:
                    batch.delete(str(key).encode("utf-8"))
        except Exception as exc:
            raise DatabaseError("LevelDB atomic write failed") from exc

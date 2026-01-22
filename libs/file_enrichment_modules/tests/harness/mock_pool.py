"""Mock asyncpg pool implementation for standalone testing."""

from datetime import UTC, datetime
from typing import Any


class MockRecord(dict):
    """Mock asyncpg.Record that behaves like both a dict and supports attribute access."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as err:
            raise AttributeError(f"Record has no attribute '{name}'") from err


class MockAsyncpgPool:
    """Mock implementation of asyncpg.Pool for testing without PostgreSQL.

    Provides the same interface as asyncpg.Pool but returns pre-registered
    data for file_enriched queries.

    Usage:
        pool = MockAsyncpgPool()

        # Register file_enriched data that will be returned for queries
        pool.register_file_enriched("uuid-1234", {
            "object_id": "uuid-1234",
            "file_name": "test.exe",
            "magic_type": "PE32 executable",
            ...
        })

        # Now queries for this object_id will return the registered data
        row = await pool.fetchrow("SELECT ... WHERE object_id = $1", "uuid-1234")
    """

    def __init__(self):
        """Initialize the mock pool."""
        self._file_enriched_data: dict[str, dict[str, Any]] = {}
        self._execute_log: list[tuple[str, tuple]] = []

    def register_file_enriched(self, object_id: str, data: dict[str, Any]) -> None:
        """Register file_enriched data to be returned for queries.

        Args:
            object_id: The object_id that triggers this data
            data: Dict containing files_enriched column values
        """
        # Ensure required fields have defaults
        defaults = {
            "object_id": object_id,
            "agent_id": "test-agent",
            "source": "test-source",
            "project": "test-project",
            "timestamp": datetime.now(UTC),
            "expiration": datetime.now(UTC),
            "path": "/test/path",
            "file_name": "test_file",
            "extension": None,
            "size": 0,
            "magic_type": "data",
            "mime_type": "application/octet-stream",
            "is_plaintext": False,
            "is_container": False,
            "originating_object_id": None,
            "originating_container_id": None,
            "nesting_level": None,
            "file_creation_time": None,
            "file_access_time": None,
            "file_modification_time": None,
            "security_info": None,
            "hashes": {"md5": "d41d8cd98f00b204e9800998ecf8427e", "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        }
        merged = {**defaults, **data}
        self._file_enriched_data[object_id] = merged

    async def fetchrow(self, query: str, *args) -> MockRecord | None:
        """Fetch a single row (mock implementation).

        For files_enriched queries, returns registered data.
        Otherwise returns None.

        Args:
            query: SQL query string
            *args: Query parameters

        Returns:
            MockRecord if data found, None otherwise
        """
        self._execute_log.append((query, args))

        # Check if this is a files_enriched query
        if "files_enriched" in query.lower() and args:
            object_id = str(args[0])
            if object_id in self._file_enriched_data:
                return MockRecord(self._file_enriched_data[object_id])
        return None

    async def fetch(self, query: str, *args) -> list[MockRecord]:
        """Fetch multiple rows (mock implementation).

        Args:
            query: SQL query string
            *args: Query parameters

        Returns:
            List of MockRecord objects
        """
        self._execute_log.append((query, args))

        # For files_enriched queries, return matching records
        if "files_enriched" in query.lower() and args:
            object_id = str(args[0])
            if object_id in self._file_enriched_data:
                return [MockRecord(self._file_enriched_data[object_id])]
        return []

    async def execute(self, query: str, *args) -> str:
        """Execute a query without returning results.

        Args:
            query: SQL query string
            *args: Query parameters

        Returns:
            Status string (always "OK" for mock)
        """
        self._execute_log.append((query, args))
        return "OK"

    async def executemany(self, query: str, args_list: list[tuple]) -> None:
        """Execute a query multiple times with different parameters.

        Args:
            query: SQL query string
            args_list: List of parameter tuples
        """
        for args in args_list:
            self._execute_log.append((query, args))

    def get_execute_log(self) -> list[tuple[str, tuple]]:
        """Get the log of all executed queries (for assertions).

        Returns:
            List of (query, args) tuples
        """
        return self._execute_log.copy()

    def clear_execute_log(self) -> None:
        """Clear the execute log."""
        self._execute_log.clear()

    def clear(self) -> None:
        """Clear all registered data and logs."""
        self._file_enriched_data.clear()
        self._execute_log.clear()

    async def close(self) -> None:
        """Close the pool (no-op for mock)."""
        pass

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        pass

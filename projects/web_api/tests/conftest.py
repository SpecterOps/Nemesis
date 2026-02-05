"""Shared test fixtures for web_api tests.

Patches are applied at module level to prevent web_api.main from connecting
to real services (Dapr, MinIO, PostgreSQL) during import.
"""

from contextlib import asynccontextmanager
from unittest.mock import MagicMock, patch

import pytest

# --- Module-level patches ---
# These must be applied BEFORE web_api.main is imported, because it
# instantiates StorageMinio() and LargeContainerProcessor() at module scope,
# both of which use DaprClient to fetch secrets.


def _fake_get_secret(store_name, key):
    """Return a mock secret response where secret[key] = 'test'."""
    mock_resp = MagicMock()
    mock_resp.secret = {key: "test"}
    return mock_resp


_mock_dapr_client = MagicMock()
_mock_dapr_client.__enter__ = MagicMock(return_value=_mock_dapr_client)
_mock_dapr_client.__exit__ = MagicMock(return_value=False)
_mock_dapr_client.get_secret = _fake_get_secret

_mock_minio_client = MagicMock()
_mock_minio_client.bucket_exists.return_value = True

# Patch DaprClient and Minio before web_api.main loads
_dapr_patch = patch("dapr.clients.DaprClient", return_value=_mock_dapr_client)
_minio_patch = patch("minio.Minio", return_value=_mock_minio_client)
_dapr_patch.start()
_minio_patch.start()

# Also need to clear the lru_cache on get_postgres_connection_str in case it was cached
# from a real call (shouldn't happen in tests, but safety measure)
from common.db import get_postgres_connection_str  # noqa: E402

get_postgres_connection_str.cache_clear()

# Now it's safe to import the app
from web_api.main import app  # noqa: E402


@asynccontextmanager
async def noop_lifespan(app):
    """No-op lifespan to avoid connecting to real services in tests."""
    yield


@pytest.fixture
def mock_storage():
    """Provide the mocked storage instance with sensible defaults for download tests."""
    mock = MagicMock()
    mock.check_file_exists.return_value = True
    stats = MagicMock()
    stats.size = 10 * 1024 * 1024  # 10MB
    mock.get_object_stats.return_value = stats
    mock.download_stream.return_value = iter([b"streaming-data"])
    mock.download_bytes.return_value = b"\x00" * 100

    with patch("web_api.main.storage", mock):
        yield mock


@pytest.fixture
def client(mock_storage):
    """Create a test client with mocked storage and no-op lifespan."""
    from fastapi.testclient import TestClient

    original_router_lifespan = app.router.lifespan_context
    app.router.lifespan_context = noop_lifespan
    try:
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c
    finally:
        app.router.lifespan_context = original_router_lifespan

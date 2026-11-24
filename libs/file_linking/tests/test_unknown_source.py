"""Files from unknown://unknown are never listed, linked or used to resolve placeholders as if from one host."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from file_linking.database_service import FileLinkingDatabaseService, FileListingStatus
from file_linking.placeholder_resolver import PlaceholderResolver

UNKNOWN = "unknown://unknown"


@pytest.fixture
def pool():
    return MagicMock()


@pytest.mark.asyncio
async def test_unknown_source_listing_is_not_written(pool):
    service = FileLinkingDatabaseService(pool)
    assert await service.add_file_listing(UNKNOWN, "/C:/x", FileListingStatus.COLLECTED) is False
    pool.acquire.assert_not_called()


@pytest.mark.asyncio
async def test_unknown_source_linking_is_not_written(pool):
    service = FileLinkingDatabaseService(pool)
    assert await service.add_file_linking(UNKNOWN, "/C:/a", "/C:/b") is False
    pool.acquire.assert_not_called()


@pytest.mark.asyncio
async def test_unknown_source_placeholders_are_not_resolved():
    db = MagicMock()
    db.get_placeholder_entries = AsyncMock()
    db.get_collected_files = AsyncMock()
    resolver = PlaceholderResolver(db)
    assert await resolver.resolve_placeholders_for_file("/C:/Users/bob/AppData/x", UNKNOWN) == 0
    assert await resolver.try_resolve_placeholder_path(UNKNOWN, "/C:/Users/<WINDOWS_USERNAME>/x") is None
    db.get_placeholder_entries.assert_not_awaited()
    db.get_collected_files.assert_not_awaited()


@pytest.mark.asyncio
async def test_known_source_listing_is_written():
    conn = MagicMock()
    conn.execute = AsyncMock()
    service = FileLinkingDatabaseService(MagicMock())
    assert await service.add_file_listing("host://WS01", "/C:/x", FileListingStatus.COLLECTED, conn=conn) is True
    conn.execute.assert_awaited_once()

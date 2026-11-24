"""dpapi_masterkey never pairs hives or creates linkings for files of unknown origin."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from file_enrichment_modules.dpapi_masterkey.analyzer import DPAPIMasterkeyAnalyzer

UNKNOWN = SimpleNamespace(source="unknown://unknown", project="p", path="/C:/Users/bob/AppData/Roaming/x")


@pytest.fixture
def analyzer():
    module = DPAPIMasterkeyAnalyzer.__new__(DPAPIMasterkeyAnalyzer)
    module.asyncpg_pool = MagicMock()
    return module


@pytest.mark.asyncio
async def test_unknown_source_hive_lookup_skips_database(analyzer):
    assert await analyzer._find_existing_hive(UNKNOWN, "/C:/Windows/System32/Config/SYSTEM") is None
    analyzer.asyncpg_pool.acquire.assert_not_called()


@pytest.mark.asyncio
async def test_unknown_source_gets_no_proactive_linkings(analyzer):
    with patch("file_enrichment_modules.dpapi_masterkey.analyzer.add_file_linking") as add_linking:
        await analyzer._create_proactive_file_linkings(UNKNOWN)
    add_linking.assert_not_called()

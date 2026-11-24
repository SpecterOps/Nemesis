"""Chromium stores 64-bit integers; a download over 2 GiB must not drop the whole History batch."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from chromium import history

SCHEMAS = [
    Path(__file__).resolve().parents[3] / "infra/postgres/01-schema.sql",
    Path(__file__).resolve().parents[3] / "k8s/helm/nemesis/files/01-schema.sql",
]
FILE = SimpleNamespace(object_id=str(uuid4()), agent_id="a", source="host://ws01", project="p")
THREE_GIB = 3 * 1024**3


def pool_with(conn):
    pool = MagicMock()
    pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
    pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
    return pool


@pytest.mark.asyncio
async def test_large_download_is_passed_through(monkeypatch):
    rows = [("https://x/big.iso", "C:/big.iso", 13300000000000000, 13300000000000001, THREE_GIB)]
    monkeypatch.setattr(history, "read_untrusted_sqlite_async", AsyncMock(return_value=rows))
    conn = MagicMock(executemany=AsyncMock())
    await history._insert_history_downloads(FILE.object_id, FILE, "bob", "chrome", "/tmp/h", pool_with(conn))
    (_, params), _ = conn.executemany.call_args
    assert params[0][-1] == THREE_GIB


@pytest.mark.parametrize("path", SCHEMAS, ids=lambda p: p.parent.name)
@pytest.mark.parametrize("column", ["visit_count", "total_bytes", "times_used", "source_port"])
def test_chromium_integer_columns_are_bigint(path, column):
    lines = [line.strip() for line in path.read_text().splitlines() if line.strip().startswith(f"{column} ")]
    assert lines and all(line.split()[1].rstrip(",") == "BIGINT" for line in lines), lines

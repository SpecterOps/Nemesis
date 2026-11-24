"""Titus findings are stored with findings.data as an array of objects, like every other writer."""

import json
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from common.models import MatchInfo, MatchLocation, ScanStats

with patch("common.storage.StorageS3", MagicMock()):
    import file_enrichment.global_vars as global_vars
    from file_enrichment.subscriptions import titus


class FakeConn:
    def __init__(self):
        self.executed = []

    async def execute(self, query, *params):
        self.executed.append((query, params))

    def transaction(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return self.conn


@pytest.mark.asyncio
async def test_titus_findings_data_is_array_of_objects(monkeypatch):
    conn = FakeConn()
    monkeypatch.setattr(global_vars, "asyncpg_pool", FakePool(conn))
    monkeypatch.setattr(global_vars, "tracking_service", MagicMock(update_enrichment_results=AsyncMock()))
    match = MatchInfo(
        rule_name="AWS API Key",
        rule_type="secret",
        matched_content="AKIAABCDEFGHIJKLMNOP",
        location=MatchLocation(line=1, column=1),
        snippet="key=AKIAABCDEFGHIJKLMNOP",
    )
    stats = ScanStats(blobs_seen=1, blobs_scanned=1, bytes_seen=10, bytes_scanned=10, matches_found=1)

    await titus.store_titus_results(uuid4(), "wf-1", [match], stats)

    findings = [p for q, p in conn.executed if "INSERT INTO findings" in q]
    assert findings
    for params in findings:
        data = json.loads(params[-1])
        assert isinstance(data, list) and data and all(isinstance(item, dict) for item in data)
        assert data[0]["type"] == "finding_summary"

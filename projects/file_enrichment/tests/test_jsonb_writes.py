"""Findings and transforms with NUL bytes, surrogates or non-JSON values are stored, not lost, and logged."""

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from common import data_issues
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform

with patch("common.storage.StorageS3", MagicMock()):
    import file_enrichment.activities.enrichment_modules as enrichment_modules
    import file_enrichment.global_vars as global_vars


class FakeConn:
    def __init__(self):
        self.executed = []

    async def execute(self, query, *params):
        # Mirror PostgreSQL: JSONB rejects \u0000 and lone surrogates, and params must be valid JSON text
        for value in params:
            if isinstance(value, str) and value[:1] in "[{":
                parsed = json.loads(value)
                assert "\u0000" not in value and "\\u0000" not in value
                assert parsed is not None
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


@pytest.fixture
def issues(monkeypatch):
    calls = []
    monkeypatch.setattr(data_issues, "logger", type("L", (), {"warning": lambda self, e, **kw: calls.append(kw)})())
    return calls


@pytest.mark.asyncio
async def test_dirty_finding_and_transform_are_stored_and_logged(monkeypatch, issues):
    conn = FakeConn()
    monkeypatch.setattr(global_vars, "asyncpg_pool", FakePool(conn))
    object_id = str(uuid4())
    result = EnrichmentResult(
        module_name="m",
        results={"text": "ok"},
        transforms=[
            Transform(type="t", object_id=str(uuid4()), metadata={"note": "a\x00b", "when": datetime.now(UTC)})
        ],
        findings=[
            Finding(
                category=FindingCategory.MISC,
                finding_name="f",
                origin_type=FindingOrigin.ENRICHMENT_MODULE,
                origin_name="m",
                object_id=object_id,
                severity=3,
                raw_data={"s": "x\ud800y\x00", "b": b"\x00\x01", "u": uuid4(), "d": datetime.now(UTC)},
                data=[FileObject(type="finding_summary", metadata={"summary": "z\x00"})],
            )
        ],
    )

    await enrichment_modules.store_enrichment_results(object_id, "m", result)

    queries = [q for q, _ in conn.executed]
    assert any("INSERT INTO findings" in q for q in queries)
    assert any("INSERT INTO transforms" in q for q in queries)
    findings_params = next(p for q, p in conn.executed if "INSERT INTO findings" in q)
    raw = json.loads(findings_params[6])
    assert raw["s"] == "xy" and raw["b"] == "0001"
    fields = {call["field"] for call in issues}
    assert {"findings.raw_data", "transforms.metadata", "findings.data"} <= fields
    assert all(call["kind"] == "jsonb_sanitized" and call["object_id"] == object_id for call in issues)


@pytest.mark.asyncio
async def test_clean_result_logs_nothing(monkeypatch, issues):
    conn = FakeConn()
    monkeypatch.setattr(global_vars, "asyncpg_pool", FakePool(conn))
    result = EnrichmentResult(module_name="m", results={"text": "ok"})
    await enrichment_modules.store_enrichment_results(str(uuid4()), "m", result)
    assert issues == []

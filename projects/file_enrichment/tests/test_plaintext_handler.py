"""handle_file_if_plaintext never raises, still submits to Titus when indexing fails, and indexes in small chunks (#76)."""

import asyncio
import io
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from common.workflows import setup as wf_setup

with patch("common.storage.StorageS3", MagicMock()):
    import file_enrichment.activities.plaintext_handler as handler
    import file_enrichment.global_vars as global_vars


class FakeConn:
    def __init__(self, fail_on_insert=False):
        self.inserts = []
        self.fail_on_insert = fail_on_insert

    async def execute(self, query, *args):
        if "INSERT" in query:
            if self.fail_on_insert:
                raise RuntimeError("string is too long for tsvector")
            self.inserts.append(args)

    def transaction(self):
        conn = self

        class _Tx:
            async def __aenter__(self):
                return conn

            async def __aexit__(self, *exc):
                return False

        return _Tx()


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        conn = self.conn

        class _Acquire:
            async def __aenter__(self):
                return conn

            async def __aexit__(self, *exc):
                return False

        return _Acquire()


@pytest.fixture
def conn(monkeypatch):
    connection = FakeConn()
    monkeypatch.setattr(global_vars, "asyncpg_pool", FakePool(connection))
    return connection


async def _index(text, max_bytes):
    await handler.index_plaintext_content("obj", io.StringIO(text), max_chunk_bytes=max_bytes)


def _chunks(conn):
    return [args[2] for args in conn.inserts]


# --- chunking ---


def test_default_chunk_size_is_well_under_tsvector_limit():
    assert handler.PLAINTEXT_CHUNK_MAX_BYTES <= 100_000


@pytest.mark.asyncio
async def test_chunks_respect_byte_limit_and_lose_nothing(conn):
    text = ("ascii " * 50 + "é€😀 " * 30) * 20
    await _index(text, 1000)
    chunks = _chunks(conn)
    assert len(chunks) > 1
    assert all(len(c.encode("utf-8")) <= 1000 for c in chunks)
    assert "".join(chunks) == text
    assert [args[1] for args in conn.inserts] == list(range(len(chunks)))


@pytest.mark.asyncio
async def test_ascii_chunks_use_the_full_byte_budget(conn):
    await _index("a" * 2500, 1000)
    assert [len(c) for c in _chunks(conn)] == [1000, 1000, 500]


@pytest.mark.asyncio
async def test_nulls_and_lone_surrogates_are_removed(conn):
    await _index("a\x00b\ud800c", 1000)
    assert _chunks(conn) == ["ab?c"]


@pytest.mark.asyncio
async def test_empty_file_inserts_nothing(conn):
    await _index("", 1000)
    assert conn.inserts == []


# --- the activity ---


@pytest.fixture
def activity_env(monkeypatch, tmp_path):
    """Run the activity on this loop with mocked metadata, storage, Dapr and tracking."""
    monkeypatch.setattr(wf_setup, "workflow_loop", None, raising=False)

    path = tmp_path / "file.txt"
    path.write_bytes(b"\xef\xbb\xbfhello \xff world")  # UTF-8 BOM followed by an invalid byte
    storage = MagicMock()

    @contextmanager
    def download(_object_id):
        yield SimpleNamespace(name=str(path))

    async def download_async(object_id):
        return download(object_id)

    storage.download_async = download_async
    monkeypatch.setattr(global_vars, "storage", storage)

    tracking = SimpleNamespace(update_enrichment_results=AsyncMock())
    monkeypatch.setattr(global_vars, "tracking_service", tracking)

    file_enriched = SimpleNamespace(is_plaintext=True, path="/loot/file.txt")
    monkeypatch.setattr(handler, "get_file_enriched_async", AsyncMock(return_value=file_enriched))

    client = MagicMock()
    client.publish_event = AsyncMock()
    monkeypatch.setattr(global_vars, "dapr_client", client)

    return SimpleNamespace(client=client, tracking=tracking, file_enriched=file_enriched)


async def _run_activity():
    wf_setup.workflow_loop = asyncio.get_running_loop()
    # The registered activity is a factory that returns the wrapped coroutine function
    activity = handler.handle_file_if_plaintext()
    return await activity(SimpleNamespace(workflow_id="wf-1"), {"object_id": "00000000-0000-0000-0000-0000000000aa"})


@pytest.mark.asyncio
async def test_happy_path_indexes_and_submits(activity_env, conn):
    result = await _run_activity()
    assert result == {"indexed": True, "titus_submitted": True, "errors": []}
    # Invalid bytes after a BOM are replaced instead of raising
    assert _chunks(conn) == ["hello � world"]
    activity_env.client.publish_event.assert_awaited_once()


@pytest.mark.asyncio
async def test_index_failure_still_submits_to_titus(activity_env, monkeypatch):
    failing = FakeConn(fail_on_insert=True)
    monkeypatch.setattr(global_vars, "asyncpg_pool", FakePool(failing))
    result = await _run_activity()
    assert result["indexed"] is False
    assert result["titus_submitted"] is True
    assert result["errors"] and result["errors"][0].startswith("index:")
    activity_env.client.publish_event.assert_awaited_once()
    activity_env.tracking.update_enrichment_results.assert_awaited_with("wf-1", failure_list=["plaintext_index"])


@pytest.mark.asyncio
async def test_titus_failure_is_reported_not_raised(activity_env, conn):
    activity_env.client.publish_event.side_effect = RuntimeError("pubsub down")
    result = await _run_activity()
    assert result["indexed"] is True
    assert result["titus_submitted"] is False
    assert result["errors"][0].startswith("titus:")
    activity_env.tracking.update_enrichment_results.assert_awaited_with("wf-1", failure_list=["titus_submit"])


@pytest.mark.asyncio
async def test_metadata_failure_is_reported_not_raised(activity_env, monkeypatch):
    monkeypatch.setattr(handler, "get_file_enriched_async", AsyncMock(side_effect=RuntimeError("db down")))
    result = await _run_activity()
    assert result == {"indexed": False, "titus_submitted": False, "errors": ["metadata: db down"]}
    activity_env.client.publish_event.assert_not_awaited()


@pytest.mark.asyncio
async def test_non_plaintext_is_only_submitted_to_titus(activity_env, conn):
    activity_env.file_enriched.is_plaintext = False
    result = await _run_activity()
    assert result == {"indexed": False, "titus_submitted": True, "errors": []}
    assert conn.inserts == []


@pytest.mark.asyncio
async def test_failure_recording_errors_are_swallowed(activity_env, monkeypatch):
    monkeypatch.setattr(global_vars, "asyncpg_pool", FakePool(FakeConn(fail_on_insert=True)))
    activity_env.tracking.update_enrichment_results.side_effect = RuntimeError("db down")
    result = await _run_activity()
    assert result["titus_submitted"] is True

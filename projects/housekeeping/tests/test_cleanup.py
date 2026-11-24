"""Housekeeping cleanup: storage/database ordering (#199) and the DPAPI, listing and linking cleanups (#200)."""

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import housekeeping.main as hk
import pytest


class FakeTransaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class FakeConn:
    """Records SQL; fetch/fetchval results come from queues keyed by a SQL substring."""

    def __init__(self, fetch_results=None, fetchval_result=False, fail_on=None):
        self.executed: list[tuple[str, tuple]] = []
        self.fetch_results = fetch_results or {}
        self.fetchval_result = fetchval_result
        self.fail_on = fail_on

    def _record(self, sql, args):
        self.executed.append((" ".join(sql.split()), args))
        if self.fail_on and self.fail_on in sql:
            raise RuntimeError("database down")

    async def execute(self, sql, *args):
        self._record(sql, args)

    async def fetch(self, sql, *args):
        self._record(sql, args)
        for key, rows in self.fetch_results.items():
            if key in sql:
                return rows
        return []

    async def fetchval(self, sql, *args):
        self._record(sql, args)
        return self.fetchval_result

    def transaction(self):
        return FakeTransaction()

    def sql(self, needle):
        return [s for s, _ in self.executed if needle in s]


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        conn = self.conn

        class Ctx:
            async def __aenter__(self):
                return conn

            async def __aexit__(self, *exc):
                return False

        return Ctx()


@pytest.fixture
def conn(monkeypatch):
    connection = FakeConn()
    monkeypatch.setattr(hk, "db_pool", FakePool(connection))
    return connection


@pytest.fixture
def storage(monkeypatch):
    fake = MagicMock()
    fake.delete_objects_with_status.side_effect = lambda ids: set(ids)
    fake.delete_objects_modified_before.return_value = (0, 0)
    monkeypatch.setattr(hk, "storage", fake)
    monkeypatch.setattr(hk, "is_initialized", True)
    monkeypatch.setattr(hk, "_CLEANUP_RETRY_COUNT", 1)
    return fake


# --- #199: storage first, database rows only for objects that are gone ---


def test_rows_deleted_only_when_object_and_transforms_are_gone(storage):
    storage.delete_objects_with_status.side_effect = lambda ids: set(ids) - {"t-b"}
    deletable, kept = hk.delete_expired_objects_from_storage(["a", "b", "c"], {"a": ["t-a"], "b": ["t-b"]})
    assert deletable == ["a", "c"]
    assert kept == ["b"]  # its transform object failed, so its rows (and transform row) must stay
    assert set(storage.delete_objects_with_status.call_args.args[0]) == {"a", "b", "c", "t-a", "t-b"}


def test_failed_file_object_keeps_its_rows(storage):
    storage.delete_objects_with_status.side_effect = lambda ids: set()
    deletable, kept = hk.delete_expired_objects_from_storage(["a"], {})
    assert (deletable, kept) == ([], ["a"])


@pytest.mark.asyncio
async def test_transform_map_groups_by_object(conn):
    conn.fetch_results = {
        "FROM transforms": [
            {"object_id": "a", "transform_object_id": "t1"},
            {"object_id": "a", "transform_object_id": "t2"},
            {"object_id": "b", "transform_object_id": "t3"},
        ]
    }
    assert await hk.get_transform_object_map(["a", "b"]) == {"a": ["t1", "t2"], "b": ["t3"]}


@pytest.mark.asyncio
async def test_transform_map_failure_returns_none(conn):
    conn.fail_on = "FROM transforms"
    assert await hk.get_transform_object_map(["a"]) is None


@pytest.mark.asyncio
async def test_cleanup_job_deletes_rows_only_for_removed_objects(conn, storage, monkeypatch):
    monkeypatch.setattr(hk, "get_expired_object_ids", AsyncMock(return_value=["a", "b"]))
    monkeypatch.setattr(hk, "get_transform_object_map", AsyncMock(return_value={}))
    storage.delete_objects_with_status.side_effect = lambda ids: {"a"}
    deleted = AsyncMock(return_value=True)
    monkeypatch.setattr(hk, "delete_database_entries", deleted)

    await hk.run_cleanup_job()

    deleted.assert_awaited_once_with(["a"])
    storage.delete_objects_modified_before.assert_not_called()  # no sweep outside "all"


@pytest.mark.asyncio
async def test_cleanup_job_skips_file_deletion_when_transform_lookup_fails(conn, storage, monkeypatch):
    monkeypatch.setattr(hk, "get_expired_object_ids", AsyncMock(return_value=["a"]))
    monkeypatch.setattr(hk, "get_transform_object_map", AsyncMock(return_value=None))
    deleted = AsyncMock(return_value=True)
    monkeypatch.setattr(hk, "delete_database_entries", deleted)

    await hk.run_cleanup_job()

    storage.delete_objects_with_status.assert_not_called()
    deleted.assert_awaited_once_with([])


@pytest.mark.asyncio
async def test_database_failure_after_storage_delete_is_reported(conn, storage, monkeypatch):
    """Rows stay; the next run deletes them because already-absent objects count as deleted."""
    monkeypatch.setattr(hk, "get_expired_object_ids", AsyncMock(return_value=["a"]))
    monkeypatch.setattr(hk, "get_transform_object_map", AsyncMock(return_value={}))
    conn.fail_on = "DELETE FROM files_enriched\n"
    assert await hk.delete_database_entries(["a"]) is False


@pytest.mark.asyncio
async def test_all_cleanup_sweeps_objects_written_before_the_job(conn, storage, monkeypatch):
    monkeypatch.setattr(hk, "get_expired_object_ids", AsyncMock(return_value=[]))
    before = datetime.now(UTC)
    await hk.run_cleanup_job(datetime.max)
    cutoff = storage.delete_objects_modified_before.call_args.args[0]
    assert before <= cutoff <= datetime.now(UTC)
    # every table family is cleared in "all" mode
    assert conn.sql("DELETE FROM dpapi.masterkeys")
    assert conn.sql("DELETE FROM chromium.cookies")
    assert conn.sql("DELETE FROM file_listings RETURNING")
    assert conn.sql("DELETE FROM file_linkings RETURNING")


@pytest.mark.asyncio
async def test_cleanup_job_runs_all_table_cleanups(conn, storage, monkeypatch):
    monkeypatch.setattr(hk, "get_expired_object_ids", AsyncMock(return_value=[]))
    calls = {}
    for name in (
        "delete_expired_containers",
        "delete_expired_dpapi_data",
        "delete_expired_chromium_data",
        "delete_expired_file_listings",
        "delete_expired_file_linkings",
    ):
        calls[name] = AsyncMock(return_value=True)
        monkeypatch.setattr(hk, name, calls[name])
    await hk.run_cleanup_job()
    for mock in calls.values():
        mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_cleanup_job_aborts_without_storage(monkeypatch):
    monkeypatch.setattr(hk, "is_initialized", True)
    monkeypatch.setattr(hk, "storage", None)
    get_ids = AsyncMock()
    monkeypatch.setattr(hk, "get_expired_object_ids", get_ids)
    await hk.run_cleanup_job()
    get_ids.assert_not_called()


# --- #200: DPAPI, file_listings and file_linkings ---


@pytest.mark.asyncio
async def test_dpapi_deleted_per_project_once_its_files_expired(conn):
    """Each project's DPAPI rows go only once that project has no unexpired files; other projects keep theirs."""
    cutoff = datetime(2026, 11, 24)
    assert await hk.delete_expired_dpapi_data(cutoff) is True
    deletes = [(s, a) for s, a in conn.executed if s.startswith("DELETE FROM dpapi")]
    assert [s.split()[2] for s, _ in deletes] == [
        "dpapi.masterkeys",
        "dpapi.domain_backup_keys",
        "dpapi.system_credentials",
    ]
    for sql, args in deletes:
        assert args == (cutoff,)
        assert "d.updated_at < $1" in sql
        # live files are matched on the DPAPI row's own project, in both file tables
        assert "FROM files f WHERE f.project = d.project AND f.expiration >= $1" in sql
        assert "FROM files_enriched fe WHERE fe.project = d.project AND fe.expiration >= $1" in sql
    # no global "any unexpired file anywhere" check any more
    assert not [s for s, _ in conn.executed if s.startswith("SELECT EXISTS")]


@pytest.mark.asyncio
async def test_dpapi_all_mode_deletes_everything(conn):
    assert await hk.delete_expired_dpapi_data(datetime.max) is True
    assert conn.sql("DELETE FROM dpapi.masterkeys") and conn.sql("DELETE FROM dpapi.system_credentials")
    assert not [s for s, _ in conn.executed if "EXISTS" in s]


@pytest.mark.asyncio
async def test_dpapi_failure_returns_false(conn):
    conn.fail_on = "DELETE FROM dpapi.masterkeys"
    assert await hk.delete_expired_dpapi_data() is False


@pytest.mark.parametrize(
    ("func", "table"),
    [(hk.delete_expired_file_listings, "file_listings"), (hk.delete_expired_file_linkings, "file_linkings")],
)
@pytest.mark.asyncio
async def test_listings_and_linkings_deleted_by_source_without_live_files(conn, func, table):
    cutoff = datetime(2026, 11, 24)
    assert await func(cutoff) is True
    sql, args = conn.executed[-1]
    assert sql.startswith(f"DELETE FROM {table} WHERE NOT")
    assert f"files.source = {table}.source AND files.expiration >= $1" in sql
    assert f"fe.source = {table}.source AND fe.expiration >= $1" in sql
    assert "created_at" not in sql  # the old rule deleted every row on each nightly run
    assert args == (cutoff,)


@pytest.mark.parametrize(
    ("func", "table"),
    [(hk.delete_expired_file_listings, "file_listings"), (hk.delete_expired_file_linkings, "file_linkings")],
)
@pytest.mark.asyncio
async def test_listings_and_linkings_all_mode(conn, func, table):
    assert await func(datetime.max) is True
    assert conn.executed[-1][0].startswith(f"DELETE FROM {table} RETURNING")


@pytest.mark.parametrize("func", [hk.delete_expired_file_listings, hk.delete_expired_file_linkings])
@pytest.mark.asyncio
async def test_listings_and_linkings_failure_returns_false(conn, func):
    conn.fail_on = "DELETE"
    assert await func() is False


@pytest.mark.asyncio
async def test_chromium_only_cleared_in_all_mode(conn):
    assert await hk.delete_expired_chromium_data() is True
    assert not conn.executed  # ON DELETE CASCADE handles expiring files
    assert await hk.delete_expired_chromium_data(datetime.max) is True
    assert conn.sql("DELETE FROM chromium.logins")


# --- trigger_cleanup expiration must carry a timezone ---------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["2026-01-01T00:00:00", "not a date"])
async def test_trigger_rejects_naive_or_invalid_expiration(monkeypatch, value):
    from common import data_issues

    calls = []
    monkeypatch.setattr(data_issues, "logger", type("L", (), {"warning": lambda self, e, **kw: calls.append(kw)})())
    monkeypatch.setattr(hk, "is_initialized", True)
    run = AsyncMock()
    monkeypatch.setattr(hk, "run_cleanup_job", run)
    result = await hk.trigger_cleanup(hk.CleanupRequest(expiration=value))
    assert result["status"] == "error" and "timezone" in result["message"]
    run.assert_not_called()
    assert calls and calls[0]["kind"] == "rejected_input" and calls[0]["field"] == "cleanup.expiration"


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["2026-01-01T00:00:00Z", "2026-01-01T02:00:00+02:00"])
async def test_trigger_accepts_aware_expiration_as_utc(monkeypatch, value):
    monkeypatch.setattr(hk, "is_initialized", True)
    run = AsyncMock()
    monkeypatch.setattr(hk, "run_cleanup_job", run)
    result = await hk.trigger_cleanup(hk.CleanupRequest(expiration=value))
    await asyncio.sleep(0)
    assert result["expiration_mode"] == "custom"
    assert run.call_args.args[0] == datetime(2026, 1, 1, tzinfo=UTC)

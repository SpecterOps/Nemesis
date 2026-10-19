"""Durability and retry tests for Mythic file synchronization state."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cli.mythic_connector import handlers
from cli.mythic_connector.db import Database, DatabaseError
from cli.mythic_connector.handlers import FileHandler


def make_handler(db: Database, *, url: str = "http://mythic", operation_id: str = "operation-1") -> FileHandler:
    mythic_client = SimpleNamespace(current_operation_id=operation_id)
    config = SimpleNamespace(mythic=SimpleNamespace(url=url))
    return FileHandler(mythic_client, object(), db, config)


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "state"))
    try:
        yield database
    finally:
        database.close()


def pending_value(db: Database, handler: FileHandler, agent_file_id: str) -> dict:
    raw = db.get_strict(f"{handler.state_prefix}pending:{agent_file_id}")
    assert raw is not None
    return json.loads(raw)


def test_discovery_ignores_legacy_cursor_and_preserves_success_markers(db):
    handler = make_handler(db)
    db.write_batch({"last_file_id": "900", "filemetaalready-done": "1"})

    handler._enqueue_discovered(
        [
            {"id": 10, "agent_file_id": "new-file"},
            {"id": 11, "agent_file_id": "already-done"},
        ],
        11,
    )

    assert db.get_strict(handler.state_prefix + "cursor") == b"11"
    assert pending_value(db, handler, "new-file") == {
        "id": 10,
        "uuid": "new-file",
        "attempt": 0,
        "retry_at": 0,
    }
    assert db.get_strict(handler.state_prefix + "pending:already-done") is None
    assert db.get_strict("filemetaalready-done") == b"1"
    assert db.get_strict("last_file_id") == b"900"


def test_state_is_scoped_by_server_and_operation(db):
    first = make_handler(db, url="https://one.example/", operation_id="op-a")
    same_server_other_operation = make_handler(db, url="https://one.example", operation_id="op-b")
    other_server = make_handler(db, url="https://two.example", operation_id="op-a")

    first._enqueue_discovered([{"id": 1, "agent_file_id": "file-a"}], 1)
    same_server_other_operation._enqueue_discovered([{"id": 2, "agent_file_id": "file-b"}], 2)
    other_server._enqueue_discovered([{"id": 3, "agent_file_id": "file-c"}], 3)

    assert len({first.state_prefix, same_server_other_operation.state_prefix, other_server.state_prefix}) == 3
    assert db.get_strict(first.state_prefix + "cursor") == b"1"
    assert db.get_strict(same_server_other_operation.state_prefix + "cursor") == b"2"
    assert db.get_strict(other_server.state_prefix + "cursor") == b"3"
    assert pending_value(db, first, "file-a")["id"] == 1
    assert db.get_strict(first.state_prefix + "pending:file-b") is None


@pytest.mark.asyncio
async def test_incomplete_and_missing_pending_rows_are_retained_while_later_complete_row_finishes(db, monkeypatch):
    handler = make_handler(db)
    handler._enqueue_discovered(
        [
            {"id": 1, "agent_file_id": "incomplete"},
            {"id": 2, "agent_file_id": "complete"},
            {"id": 3, "agent_file_id": "temporarily-missing"},
        ],
        3,
    )
    monkeypatch.setattr(
        handler,
        "_refresh_pending",
        AsyncMock(
            return_value=[
                {"id": 1, "agent_file_id": "incomplete", "complete": False},
                {"id": 2, "agent_file_id": "complete", "complete": True},
            ]
        ),
    )

    async def mark_complete(item):
        handler._mark_processed(item["agent_file_id"])

    handler.handle_file = AsyncMock(side_effect=mark_complete)
    await handler.process_pending_once()

    assert db.get_strict(handler.state_prefix + "pending:incomplete") is not None
    assert db.get_strict(handler.state_prefix + "pending:temporarily-missing") is not None
    assert db.get_strict(handler.state_prefix + "pending:complete") is None
    assert db.get_strict("filemetacomplete") == b"1"
    handler.handle_file.assert_awaited_once()


@pytest.mark.asyncio
async def test_retry_schedule_persists_across_restart_and_caps_at_five_minutes(db, tmp_path, monkeypatch):
    handler = make_handler(db)
    handler._enqueue_discovered([{"id": 7, "agent_file_id": "retry"}], 7)
    monkeypatch.setattr(
        handler, "_refresh_pending", AsyncMock(return_value=[{"id": 7, "agent_file_id": "retry", "complete": True}])
    )
    handler.handle_file = AsyncMock()  # Model a transient upload failure: no success marker is written.
    clock = [1_000.0]
    monkeypatch.setattr(handlers.time, "time", lambda: clock[0])

    for attempt, delay in enumerate(handlers.RETRY_DELAYS_SEC, start=1):
        await handler.process_pending_once()
        state = pending_value(db, handler, "retry")
        assert state["attempt"] == attempt
        assert state["retry_at"] == clock[0] + delay
        clock[0] += delay

    db.close()
    restarted_db = Database(str(tmp_path / "state"))
    try:
        restarted_handler = make_handler(restarted_db)
        state = pending_value(restarted_db, restarted_handler, "retry")
        assert state["attempt"] == len(handlers.RETRY_DELAYS_SEC)
        assert state["retry_at"] == clock[0]

        clock[0] = state["retry_at"]
        restarted_handler._refresh_pending = AsyncMock(
            return_value=[{"id": 7, "agent_file_id": "retry", "complete": True}]
        )
        restarted_handler.handle_file = AsyncMock()
        await restarted_handler.process_pending_once()
        assert pending_value(restarted_db, restarted_handler, "retry") == {
            **state,
            "attempt": len(handlers.RETRY_DELAYS_SEC) + 1,
            "retry_at": clock[0] + handlers.RETRY_DELAYS_SEC[-1],
        }
    finally:
        restarted_db.close()


@pytest.mark.asyncio
async def test_retry_deadline_is_measured_after_slow_upload_attempt(db, monkeypatch):
    handler = make_handler(db)
    handler._enqueue_discovered([{"id": 8, "agent_file_id": "slow-retry"}], 8)
    handler._refresh_pending = AsyncMock(return_value=[{"id": 8, "agent_file_id": "slow-retry", "complete": True}])
    clock = [500.0]
    monkeypatch.setattr(handlers.time, "time", lambda: clock[0])

    async def slow_failed_attempt(_item):
        clock[0] += 12

    handler.handle_file = AsyncMock(side_effect=slow_failed_attempt)
    await handler.process_pending_once()

    state = pending_value(db, handler, "slow-retry")
    assert state["attempt"] == 1
    assert state["retry_at"] == 517.0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "record",
    [
        {"id": "not-an-integer", "agent_file_id": "bad-id"},
        {"id": 2},
    ],
)
async def test_malformed_discovery_row_does_not_advance_cursor(db, monkeypatch, record):
    handler = make_handler(db)

    async def malformed_stream(**_kwargs):
        yield {"filemeta_stream": [record]}

    monkeypatch.setattr(handlers.mythic, "subscribe_custom_query", malformed_stream)

    with pytest.raises((ValueError, TypeError)):
        await handler._discovery_stream()

    assert db.get_strict(handler.state_prefix + "cursor") is None
    if record.get("agent_file_id"):
        assert db.get_strict(handler.state_prefix + f"pending:{record['agent_file_id']}") is None


def test_database_batch_is_atomic_when_a_later_value_cannot_be_encoded(db):
    with pytest.raises(DatabaseError):
        db.write_batch({"would-have-been-written": "value", "invalid": object()})

    assert db.get_strict("would-have-been-written") is None
    assert db.get_strict("invalid") is None


def test_database_strict_reads_propagate_storage_errors(db):
    db.close()
    with pytest.raises(DatabaseError):
        db.get_strict("state")


@pytest.mark.asyncio
async def test_deleted_pending_file_is_removed_without_success_marker(db, monkeypatch):
    handler = make_handler(db)
    handler._enqueue_discovered([{"id": 1, "agent_file_id": "deleted"}], 1)
    handler._refresh_pending = AsyncMock(
        return_value=[{"id": 1, "agent_file_id": "deleted", "deleted": True, "complete": False}]
    )
    handler.handle_file = AsyncMock()

    await handler.process_pending_once()

    assert db.get_strict(handler.state_prefix + "pending:deleted") is None
    assert db.get_strict("filemetadeleted") is None
    handler.handle_file.assert_not_awaited()

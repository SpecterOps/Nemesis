"""create_text_reader never raises on bad bytes (#76); a workflow's timeout clock starts when it runs (#79)."""

import io
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from common.helpers import create_text_reader
from common.workflows.tracking_service import WorkflowStatus, WorkflowTrackingService

# --- create_text_reader ---


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"\xef\xbb\xbfhello \xff world", "hello � world"),  # UTF-8 BOM, then an invalid byte
        (b"\xff\xfeh\x00i\x00\x00\xd8", "hi�"),  # UTF-16LE BOM, then a lone high surrogate
        (b"\xfe\xff\x00h\x00i\xd8\x00", "hi�"),  # UTF-16BE BOM, then a lone high surrogate
        (b"plain \xff text", "plain � text"),  # no BOM
    ],
)
def test_text_reader_replaces_invalid_bytes_on_every_branch(raw, expected):
    with create_text_reader(io.BytesIO(raw)) as reader:
        assert reader.read().lstrip("﻿") == expected


def test_text_reader_valid_utf8_unchanged():
    with create_text_reader(io.BytesIO("héllo".encode())) as reader:
        assert reader.read() == "héllo"


def test_text_reader_utf8_bom_is_stripped():
    with create_text_reader(io.BytesIO(b"\xef\xbb\xbfabc")) as reader:
        assert reader.read() == "abc"


# --- WorkflowTrackingService.update_status ---


def make_service():
    conn = MagicMock()
    conn.execute = AsyncMock()
    acquire = MagicMock()
    acquire.__aenter__ = AsyncMock(return_value=conn)
    acquire.__aexit__ = AsyncMock(return_value=False)
    pool = MagicMock()
    pool.acquire.return_value = acquire
    return WorkflowTrackingService("file_enrichment", pool, MagicMock()), conn


@pytest.mark.asyncio
async def test_running_resets_start_time_only_from_scheduled():
    service, conn = make_service()
    before = datetime.now(UTC)
    await service.update_status("wf-1", WorkflowStatus.RUNNING)
    query, *args = conn.execute.await_args.args
    assert "start_time = CASE WHEN status = $1 THEN $2 ELSE start_time END" in query
    assert args[0] == WorkflowStatus.SCHEDULED
    assert before <= args[1] <= datetime.now(UTC)
    assert args[2:] == [WorkflowStatus.RUNNING, "wf-1"]


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [WorkflowStatus.COMPLETED, WorkflowStatus.FAILED, WorkflowStatus.TIMEOUT])
async def test_other_statuses_leave_start_time_alone(status):
    service, conn = make_service()
    await service.update_status("wf-1", status)
    query = conn.execute.await_args.args[0]
    assert "start_time" not in query


@pytest.mark.asyncio
async def test_status_with_error_message_appends_failure():
    service, conn = make_service()
    await service.update_status("wf-1", WorkflowStatus.FAILED, error_message="boom")
    query, *args = conn.execute.await_args.args
    assert "array_append" in query and "start_time" not in query
    assert args == [WorkflowStatus.FAILED, "boom", "wf-1"]


@pytest.mark.asyncio
async def test_update_status_propagates_db_errors():
    service, conn = make_service()
    conn.execute.side_effect = RuntimeError("db down")
    with pytest.raises(RuntimeError):
        await service.update_status("wf-1", WorkflowStatus.RUNNING)

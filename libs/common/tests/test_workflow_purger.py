from datetime import UTC, datetime, timedelta

import grpc
import pytest
from common.workflows.workflow_purger import WorkflowPurger


def test_completed_workflow_waits_for_purge_grace_after_completion():
    now = datetime(2026, 5, 21, tzinfo=UTC)
    purger = WorkflowPurger("test", None, None, purge_grace_seconds=60)

    record = {
        "status": "COMPLETED",
        "start_time": now - timedelta(seconds=120),
        "runtime_seconds": 90,
    }

    assert not purger._is_ready_for_purge(record, now)


def test_completed_workflow_is_ready_after_purge_grace():
    now = datetime(2026, 5, 21, tzinfo=UTC)
    purger = WorkflowPurger("test", None, None, purge_grace_seconds=60)

    record = {
        "status": "COMPLETED",
        "start_time": now - timedelta(seconds=180),
        "runtime_seconds": 90,
    }

    assert purger._is_ready_for_purge(record, now)


def test_running_workflow_remains_ready_for_timeout_checks():
    now = datetime(2026, 5, 21, tzinfo=UTC)
    purger = WorkflowPurger("test", None, None, purge_grace_seconds=60)

    record = {
        "status": "RUNNING",
        "start_time": now,
        "runtime_seconds": None,
    }

    assert purger._is_ready_for_purge(record, now)


# --- _verify_and_purge_workflow error handling ---


class _RpcError(grpc.RpcError):
    def __init__(self, code, details):
        self._code, self._details = code, details

    def code(self):
        return self._code

    def details(self):
        return self._details


class _Client:
    def __init__(self, error):
        self.error = error
        self.purged = []

    def get_workflow_state(self, wf_id, fetch_payloads=False):
        raise self.error

    def purge_workflow(self, wf_id, recursive=True):
        self.purged.append(wf_id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        _RpcError(grpc.StatusCode.UNKNOWN, "no such instance exists"),
        _RpcError(grpc.StatusCode.NOT_FOUND, "workflow not found"),
    ],
)
async def test_missing_instance_counts_as_purged(error):
    purger = WorkflowPurger("test", None, _Client(error))
    assert await purger._verify_and_purge_workflow("wf-1") == (True, "wf-1")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        _RpcError(grpc.StatusCode.UNAVAILABLE, "connection refused"),
        _RpcError(grpc.StatusCode.DEADLINE_EXCEEDED, "deadline exceeded"),
        _RpcError(grpc.StatusCode.INTERNAL, None),
    ],
)
async def test_transient_rpc_error_is_not_marked_purged(error):
    """A sidecar hiccup must leave the row for the next cycle, not mark it purged and leak the Dapr state."""
    purger = WorkflowPurger("test", None, _Client(error))
    assert await purger._verify_and_purge_workflow("wf-1") == (False, None)

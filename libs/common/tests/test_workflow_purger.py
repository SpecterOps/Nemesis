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


# --- _handle_running_workflow: timeouts ---


class _Conn:
    def __init__(self, runtime_seconds, update_result):
        self.runtime_seconds = runtime_seconds
        self.update_result = update_result
        self.executed = []

    async def fetchrow(self, query, wf_id):
        return {"start_time": datetime(2026, 5, 21, tzinfo=UTC), "runtime_seconds": self.runtime_seconds}

    async def execute(self, query, *args):
        self.executed.append((" ".join(query.split()), args))
        return self.update_result


class _Pool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        pool = self

        class _Acquire:
            async def __aenter__(self):
                return pool.conn

            async def __aexit__(self, *exc):
                return False

        return _Acquire()


class _TerminatingClient:
    def __init__(self):
        self.terminated = []

    def terminate_workflow(self, wf_id):
        self.terminated.append(wf_id)


@pytest.mark.asyncio
@pytest.mark.parametrize("update_result", ["UPDATE 1", "UPDATE 0"])
async def test_timeout_only_marks_a_workflow_that_is_still_running(update_result):
    """Every replica's purger scans all workflows, so two can time out the same one; and a workflow can finish between
    the check and the update. Only a row still RUNNING becomes TIMEOUT, so neither appends a second failure message
    nor overwrites COMPLETED."""
    conn = _Conn(runtime_seconds=900, update_result=update_result)
    client = _TerminatingClient()
    purger = WorkflowPurger("test", _Pool(conn), client, max_execution_time=300)

    assert await purger._handle_running_workflow("test.wf-1") == (True, "test.wf-1")
    assert client.terminated == ["test.wf-1"]
    ((query, args),) = conn.executed
    assert "SET status = 'TIMEOUT'" in query and "WHERE wf_id = $1 AND status = 'RUNNING'" in query
    assert args[0] == "test.wf-1" and "exceeded max execution time" in args[1]


@pytest.mark.asyncio
async def test_workflow_within_its_time_is_left_running():
    conn = _Conn(runtime_seconds=10, update_result="UPDATE 1")
    client = _TerminatingClient()
    purger = WorkflowPurger("test", _Pool(conn), client, max_execution_time=300)

    assert await purger._handle_running_workflow("test.wf-1") == (False, None)
    assert client.terminated == [] and conn.executed == []

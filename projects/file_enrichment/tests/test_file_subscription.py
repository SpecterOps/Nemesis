"""File subscription backpressure and redelivery (#79).

A message holds a workflow slot until its workflow finishes, transient errors return RETRY (redelivered), and
messages that can never succeed return DROP.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import NAMESPACE_URL, uuid5

import asyncpg
import pytest
import pytest_asyncio
from dapr.ext.workflow.workflow_state import WorkflowStatus as DaprWorkflowStatus

with patch("common.storage.StorageS3", MagicMock()):
    import file_enrichment.global_vars as global_vars
    import file_enrichment.subscriptions.file as sub
    from file_enrichment.workflow_manager import WorkflowManager


def label_id(label: str) -> str:
    """Readable test label as a stable UUID string (file events carry UUID object IDs)."""
    return str(uuid5(NAMESPACE_URL, f"nemesis-test:{label}"))


def event(**file_overrides):
    if "object_id" in file_overrides:
        file_overrides["object_id"] = label_id(file_overrides["object_id"])
    data = {
        "object_id": label_id("obj-1"),
        "agent_id": "agent",
        "source": "host://ws01",
        "project": "proj",
        "timestamp": "2026-01-01T00:00:00Z",
        "expiration": "2027-01-01T00:00:00Z",
        "path": "/loot/a.txt",
        **file_overrides,
    }
    return {
        "data": data,
        "datacontenttype": "application/json",
        "id": "evt-1",
        "pubsubname": "files",
        "source": "web-api",
        "specversion": "1.0",
        "topic": "new_file",
        "traceid": "t",
        "traceparent": "t",
        "tracestate": "",
        "type": "com.dapr.event.sent",
    }


class FakeWorkflowClient:
    """get_workflow_state returns RUNNING until finish() is called."""

    def __init__(self):
        self.status = DaprWorkflowStatus.RUNNING
        self.error: Exception | None = None

    def get_workflow_state(self, instance_id, fetch_payloads=True):
        if self.error:
            raise self.error
        if self.status is None:
            return None
        return SimpleNamespace(runtime_status=self.status)


@pytest_asyncio.fixture
async def env(monkeypatch):
    monkeypatch.setattr(sub, "NUM_WORKERS", 2)
    monkeypatch.setattr(sub, "SLOT_WAIT_SECONDS", 0.2)
    monkeypatch.setattr(sub, "COMPLETION_POLL_SECONDS", 0.01)
    monkeypatch.setattr(sub, "save_file_message", AsyncMock())
    manager = SimpleNamespace(run_workflow=AsyncMock(side_effect=lambda f: f"wf-{f.object_id}"))
    monkeypatch.setattr(global_vars, "workflow_manager", manager)
    client = FakeWorkflowClient()
    monkeypatch.setattr(global_vars, "workflow_client", client)
    sub.start_workers()
    try:
        yield SimpleNamespace(manager=manager, client=client)
    finally:
        await sub.stop_workers()


async def _settle():
    for _ in range(20):
        await asyncio.sleep(0.02)


def free_slots():
    return sub.workflow_slots._value


@pytest.mark.asyncio
async def test_success_holds_slot_until_workflow_finishes(env):
    assert await sub.file_subscription_handler(event()) == sub.SUCCESS
    env.manager.run_workflow.assert_awaited_once()
    await _settle()
    assert free_slots() == 1  # still running
    env.client.status = DaprWorkflowStatus.COMPLETED
    await _settle()
    assert free_slots() == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("terminal", [DaprWorkflowStatus.FAILED, DaprWorkflowStatus.TERMINATED, None])
async def test_slot_released_on_any_terminal_state_or_purge(env, terminal):
    await sub.file_subscription_handler(event())
    env.client.status = terminal
    await _settle()
    assert free_slots() == 2


@pytest.mark.asyncio
async def test_full_slots_wait_then_retry(env):
    assert await sub.file_subscription_handler(event(object_id="a")) == sub.SUCCESS
    assert await sub.file_subscription_handler(event(object_id="b")) == sub.SUCCESS
    # Both slots are held by running workflows: the third waits, then asks for redelivery.
    assert await sub.file_subscription_handler(event(object_id="c")) == sub.RETRY
    assert env.manager.run_workflow.await_count == 2


@pytest.mark.asyncio
async def test_waiting_message_proceeds_when_a_slot_frees(env, monkeypatch):
    monkeypatch.setattr(sub, "SLOT_WAIT_SECONDS", 5)
    await sub.file_subscription_handler(event(object_id="a"))
    await sub.file_subscription_handler(event(object_id="b"))
    waiting = asyncio.create_task(sub.file_subscription_handler(event(object_id="c")))
    await _settle()
    assert not waiting.done()
    env.client.status = DaprWorkflowStatus.COMPLETED
    assert await asyncio.wait_for(waiting, 2) == sub.SUCCESS


@pytest.mark.asyncio
async def test_malformed_event_is_dropped(env):
    bad = event()
    del bad["data"]["project"]
    assert await sub.file_subscription_handler(bad) == sub.DROP
    env.manager.run_workflow.assert_not_awaited()
    assert free_slots() == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error", [RuntimeError("dapr unavailable"), ConnectionError("db down"), asyncpg.TooManyConnectionsError("x")]
)
async def test_transient_error_retries_and_frees_slot(env, error):
    env.manager.run_workflow.side_effect = error
    assert await sub.file_subscription_handler(event()) == sub.RETRY
    assert free_slots() == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [ValueError("bad creation_time"), asyncpg.DataError("bad value")])
async def test_permanent_error_drops_and_frees_slot(env, monkeypatch, error):
    monkeypatch.setattr(sub, "save_file_message", AsyncMock(side_effect=error))
    assert await sub.file_subscription_handler(event()) == sub.DROP
    assert free_slots() == 2


@pytest.mark.asyncio
async def test_event_before_startup_retries(monkeypatch):
    monkeypatch.setattr(sub, "workflow_slots", None)
    assert await sub.file_subscription_handler(event()) == sub.RETRY


@pytest.mark.asyncio
async def test_state_errors_keep_waiting_until_safety_timeout(env, monkeypatch):
    monkeypatch.setattr(sub, "completion_timeout_seconds", lambda: 0.1)
    env.client.error = RuntimeError("sidecar restarting")
    await sub.file_subscription_handler(event())
    await _settle()
    assert free_slots() == 2


@pytest.mark.asyncio
async def test_stop_releases_waiters(env):
    await sub.file_subscription_handler(event())
    await sub.stop_workers()
    assert sub.slot_holders == set()
    assert sub.workflow_slots is None
    sub.start_workers()  # so the fixture's stop has something to stop


# --- WorkflowManager.run_workflow ---


@pytest.mark.asyncio
async def test_schedule_failure_marks_registered_workflow_failed(monkeypatch):
    tracking = SimpleNamespace(register_workflow=AsyncMock(return_value="wf-1"), update_status=AsyncMock())
    monkeypatch.setattr(global_vars, "tracking_service", tracking)
    client = MagicMock()
    client.schedule_new_workflow.side_effect = RuntimeError("dapr down")
    monkeypatch.setattr(global_vars, "workflow_client", client)
    file = sub.File.model_validate(event()["data"])

    with pytest.raises(RuntimeError):
        await WorkflowManager(pool=MagicMock()).run_workflow(file)

    status = tracking.update_status.await_args.args
    assert status[0] == "wf-1" and status[1] == "FAILED"

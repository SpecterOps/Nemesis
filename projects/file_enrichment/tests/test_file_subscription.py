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


TERMINAL = {DaprWorkflowStatus.COMPLETED, DaprWorkflowStatus.FAILED, DaprWorkflowStatus.TERMINATED, None}


class FakeWorkflowClient:
    """Async client whose wait_for_workflow_completion returns once the test sets a terminal status (None = purged)."""

    def __init__(self):
        self.status = DaprWorkflowStatus.RUNNING
        self.error: Exception | None = None
        self.waits = 0

    async def wait_for_workflow_completion(self, instance_id, *, fetch_payloads=True, timeout_in_seconds=0):
        self.waits += 1
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_in_seconds if timeout_in_seconds else None
        while True:
            if self.error:
                raise self.error
            if self.status in TERMINAL:
                return None if self.status is None else SimpleNamespace(runtime_status=self.status)
            if deadline is not None and loop.time() >= deadline:
                raise TimeoutError("Timed-out waiting for the orchestration to complete")
            await asyncio.sleep(0.005)


@pytest_asyncio.fixture
async def env(monkeypatch):
    monkeypatch.setattr(sub, "NUM_WORKERS", 2)
    monkeypatch.setattr(sub, "SLOT_WAIT_SECONDS", 0.2)
    monkeypatch.setattr(sub, "COMPLETION_RETRY_SECONDS", 0.01)
    monkeypatch.setattr(sub, "save_file_message", AsyncMock())
    manager = SimpleNamespace(run_workflow=AsyncMock(side_effect=lambda f: f"wf-{f.object_id}"))
    monkeypatch.setattr(global_vars, "workflow_manager", manager)
    client = FakeWorkflowClient()
    monkeypatch.setattr(global_vars, "async_workflow_client", client)
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
async def test_slot_released_when_wait_times_out(env, monkeypatch):
    monkeypatch.setattr(sub, "completion_timeout_seconds", lambda: 0.1)
    await sub.file_subscription_handler(event())
    await asyncio.sleep(1.2)  # the wait's timeout is rounded up to a whole second
    assert free_slots() == 2


@pytest.mark.asyncio
async def test_wait_error_then_success_releases_slot(env):
    env.client.error = RuntimeError("sidecar restarting")
    await sub.file_subscription_handler(event())
    await _settle()
    assert free_slots() == 1  # still waiting after the failed attempts
    env.client.error = None
    env.client.status = DaprWorkflowStatus.COMPLETED
    await _settle()
    assert free_slots() == 2
    assert env.client.waits > 1


@pytest.mark.asyncio
async def test_slot_freed_without_polling_delay(env, monkeypatch):
    """The slot frees as soon as the workflow finishes, not after a poll interval."""
    monkeypatch.setattr(sub, "COMPLETION_RETRY_SECONDS", 60)
    await sub.file_subscription_handler(event())
    await asyncio.sleep(0.05)
    env.client.status = DaprWorkflowStatus.COMPLETED
    await asyncio.sleep(0.05)
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


# --- tracing: spans under the request span (FastAPI instrumentation continues the Dapr delivery trace) ---

import file_enrichment.tracing as tracing  # noqa: E402
from opentelemetry.instrumentation.utils import is_instrumentation_enabled  # noqa: E402
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter  # noqa: E402


@pytest.fixture
def tracer(monkeypatch):
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    t = provider.get_tracer("test")
    monkeypatch.setattr(tracing, "_tracer", t)
    return SimpleNamespace(tracer=t, spans=lambda: {s.name: s for s in exporter.get_finished_spans()})


async def deliver(tracer, evt):
    """Call the handler inside a span standing in for the instrumented request."""
    with tracer.tracer.start_as_current_span("request"):
        return await sub.file_subscription_handler(evt)


@pytest.mark.asyncio
async def test_slot_wait_is_traced_under_the_request(env, tracer):
    assert await deliver(tracer, event()) == sub.SUCCESS

    spans = tracer.spans()
    request, wait = spans["request"], spans["wait_for_slot"]
    assert wait.parent.span_id == request.context.span_id
    assert request.attributes["object_id"] == label_id("obj-1")
    assert request.attributes["pubsub.status"] == "SUCCESS"


@pytest.mark.asyncio
async def test_request_span_records_drop_for_malformed_event(env, tracer):
    bad = event()
    del bad["data"]["object_id"]
    assert await deliver(tracer, bad) == sub.DROP

    spans = tracer.spans()
    assert spans["request"].attributes["pubsub.status"] == "DROP"
    assert "wait_for_slot" not in spans


@pytest.mark.asyncio
async def test_request_span_records_retry_when_no_slot_frees(env, tracer):
    await sub.file_subscription_handler(event(object_id="a"))
    await sub.file_subscription_handler(event(object_id="b"))
    assert await deliver(tracer, event(object_id="c")) == sub.RETRY
    assert tracer.spans()["request"].attributes["pubsub.status"] == "RETRY"


@pytest.mark.asyncio
async def test_slot_holder_creates_no_spans(env, tracer, monkeypatch):
    seen = {}

    async def holder(instance_id):
        seen["instrumented"] = is_instrumentation_enabled()

    monkeypatch.setattr(sub, "hold_slot_until_done", holder)
    await deliver(tracer, event())
    await _settle()
    assert seen["instrumented"] is False
    assert is_instrumentation_enabled()  # only the holder task is suppressed

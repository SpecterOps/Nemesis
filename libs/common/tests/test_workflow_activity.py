"""The workflow_activity decorator registers async activities the Dapr SDK awaits natively."""

import asyncio
import threading
from unittest.mock import patch

import pytest
from common.workflows import setup
from dapr.ext.workflow._durabletask.internal.shared import is_async_callable


@pytest.fixture
def registered():
    """Capture what the decorator hands to the Dapr runtime instead of registering it."""
    captured = {}

    def fake_activity(name=None):
        def register(fn):
            captured[name or fn.__name__] = fn
            return fn

        return register

    with patch.object(setup.wf_runtime, "activity", side_effect=fake_activity):
        yield captured


@pytest.fixture
def app_loop():
    """An event loop running in another thread, like the FastAPI loop activities are sent to."""
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    setup.set_workflow_runtime_loop(loop)
    yield loop
    loop.call_soon_threadsafe(loop.stop)
    thread.join(timeout=5)
    loop.close()
    setup.set_workflow_runtime_loop(None)  # pyright: ignore[reportArgumentType]


def test_async_activity_is_registered_as_async(registered):
    @setup.workflow_activity
    async def fetch(ctx, value):
        return value

    fn = registered["fetch"]
    # The SDK awaits it on the worker loop instead of blocking a thread pool worker
    assert is_async_callable(fn)
    assert fn.__name__ == "fetch"


def test_async_activity_runs_on_the_app_loop(registered, app_loop):
    seen = {}

    @setup.workflow_activity(name="double")
    async def double(ctx, value):
        seen["loop"] = asyncio.get_running_loop()
        return value * 2

    # asyncio.run stands in for the SDK worker's own event loop
    assert asyncio.run(registered["double"](None, 21)) == 42
    assert seen["loop"] is app_loop


def test_activities_overlap_without_threads(registered, app_loop):
    @setup.workflow_activity
    async def nap(ctx, value):
        await asyncio.sleep(0.2)
        return value

    async def run_many():
        return await asyncio.gather(*(registered["nap"](None, i) for i in range(50)))

    loop = asyncio.new_event_loop()
    try:
        start = loop.time()
        assert loop.run_until_complete(run_many()) == list(range(50))
        # 50 x 0.2s run concurrently, not one after another
        assert loop.time() - start < 2
    finally:
        loop.close()


def test_activity_runs_inline_when_already_on_the_app_loop(registered):
    @setup.workflow_activity
    async def where(ctx):
        return asyncio.get_running_loop()

    async def main():
        setup.set_workflow_runtime_loop(asyncio.get_running_loop())
        try:
            return await registered["where"](None), asyncio.get_running_loop()
        finally:
            setup.set_workflow_runtime_loop(None)  # pyright: ignore[reportArgumentType]

    ran_on, current = asyncio.run(main())
    assert ran_on is current


def test_activity_errors_reach_the_sdk(registered, app_loop):
    @setup.workflow_activity
    async def boom(ctx):
        raise ValueError("bad input")

    with pytest.raises(ValueError, match="bad input"):
        asyncio.run(registered["boom"](None))


def test_cancelling_the_activity_cancels_the_app_loop_coroutine(registered, app_loop):
    started = threading.Event()
    cancelled = threading.Event()

    @setup.workflow_activity
    async def slow(ctx):
        started.set()
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    async def main():
        task = asyncio.create_task(registered["slow"](None))
        await asyncio.to_thread(started.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(main())
    assert cancelled.wait(5)


def test_sync_activity_is_registered_unchanged(registered):
    def add_one(ctx, value):
        return value + 1

    setup.workflow_activity(add_one)
    fn = registered["add_one"]
    assert fn is add_one
    assert not is_async_callable(fn)


def test_async_activity_without_loop_fails_clearly(registered):
    setup.set_workflow_runtime_loop(None)  # pyright: ignore[reportArgumentType]

    @setup.workflow_activity
    async def orphan(ctx):
        return 1

    with pytest.raises(RuntimeError, match="event loop is not set"):
        asyncio.run(registered["orphan"](None))


def test_real_registration_is_async():
    @setup.workflow_activity(name="nemesis_test_probe")
    async def probe(ctx, value):
        return value

    registry = setup.wf_runtime._WorkflowRuntime__worker._registry  # pyright: ignore[reportAttributeAccessIssue]
    assert is_async_callable(registry.get_activity("nemesis_test_probe"))


def test_runtime_uses_the_configured_limits():
    options = setup.wf_runtime._WorkflowRuntime__worker.concurrency_options  # pyright: ignore[reportAttributeAccessIssue]
    assert options.maximum_concurrent_activity_work_items == setup.WORKFLOW_MAX_CONCURRENT_ACTIVITIES
    assert options.maximum_concurrent_orchestration_work_items == setup.WORKFLOW_MAX_CONCURRENT_ORCHESTRATIONS
    assert options.maximum_thread_pool_workers == setup.WORKFLOW_THREAD_POOL_WORKERS


@pytest.mark.parametrize(("raw", "expected"), [(None, 7), ("", 7), (" 12 ", 12)])
def test_env_int_reads_positive_values(monkeypatch, raw, expected):
    if raw is None:
        monkeypatch.delenv("NEMESIS_TEST_LIMIT", raising=False)
    else:
        monkeypatch.setenv("NEMESIS_TEST_LIMIT", raw)
    assert setup._env_int("NEMESIS_TEST_LIMIT", 7) == expected


@pytest.mark.parametrize("raw", ["0", "-3", "lots"])
def test_env_int_rejects_bad_values(monkeypatch, raw):
    monkeypatch.setenv("NEMESIS_TEST_LIMIT", raw)
    with pytest.raises(ValueError, match="NEMESIS_TEST_LIMIT must be a positive integer"):
        setup._env_int("NEMESIS_TEST_LIMIT", 7)

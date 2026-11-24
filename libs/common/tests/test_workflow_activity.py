"""The workflow_activity decorator must register a sync wrapper the Dapr SDK will not await."""

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
def running_loop():
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


def test_async_activity_is_registered_as_sync(registered):
    @setup.workflow_activity
    async def fetch(ctx, value):
        return value

    fn = registered["fetch"]
    # SDK >= 1.19 awaits activities it classifies as async; this wrapper returns a plain value
    assert not is_async_callable(fn)
    assert not hasattr(fn, "__wrapped__")
    assert fn.__name__ == "fetch"


def test_async_activity_runs_on_the_workflow_loop(registered, running_loop):
    seen = {}

    @setup.workflow_activity(name="double")
    async def double(ctx, value):
        seen["loop"] = asyncio.get_running_loop()
        return value * 2

    assert registered["double"](None, 21) == 42
    assert seen["loop"] is running_loop


def test_sync_activity_result_is_returned_directly(registered):
    @setup.workflow_activity
    def add_one(ctx, value):
        return value + 1

    fn = registered["add_one"]
    assert not is_async_callable(fn)
    assert fn(None, 1) == 2


def test_async_activity_without_loop_fails_clearly(registered):
    setup.set_workflow_runtime_loop(None)  # pyright: ignore[reportArgumentType]

    @setup.workflow_activity
    async def orphan(ctx):
        return 1

    with pytest.raises(RuntimeError, match="event loop is not set"):
        registered["orphan"](None)

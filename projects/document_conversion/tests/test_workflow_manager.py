"""Workflow scheduling and completion waiting in document_conversion (Dapr clients mocked)."""

import asyncio
import sys
import types
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

# document_conversion.workflow imports activities that reach Dapr/SeaweedFS at import time
_fake_workflow = types.ModuleType("document_conversion.workflow")
_fake_workflow.document_conversion_workflow = MagicMock(name="document_conversion_workflow")  # pyright: ignore[reportAttributeAccessIssue]
sys.modules.setdefault("document_conversion.workflow", _fake_workflow)

import document_conversion.global_vars as global_vars  # noqa: E402
import document_conversion.workflow_manager as wm  # noqa: E402


def _state(name):
    return SimpleNamespace(runtime_status=SimpleNamespace(name=name))


@pytest.fixture
def client(monkeypatch):
    client = MagicMock()
    client.schedule_new_workflow = AsyncMock()
    client.wait_for_workflow_completion = AsyncMock(return_value=_state("COMPLETED"))
    client.terminate_workflow = AsyncMock()
    monkeypatch.setattr(global_vars, "async_workflow_client", client)
    tracking = MagicMock()
    tracking.register_workflow = AsyncMock(return_value="document_conversion.abc")
    monkeypatch.setattr(global_vars, "tracking_service", tracking)
    monkeypatch.setattr(wm, "workflow_semaphore", asyncio.Semaphore(2))
    monkeypatch.setattr(wm, "active_workflows", {})
    monkeypatch.setattr(wm, "workflow_lock", asyncio.Lock())
    return client


async def _drain():
    while wm._monitor_tasks:
        await asyncio.gather(*list(wm._monitor_tasks))


@pytest.mark.asyncio
async def test_schedules_and_waits_without_polling(client):
    await wm.start_workflow_with_concurrency_control(SimpleNamespace(object_id="obj-1", file_name="a.docx"))
    await _drain()

    client.schedule_new_workflow.assert_awaited_once()
    assert client.schedule_new_workflow.await_args.kwargs["instance_id"] == "document_conversion.abc"
    assert client.schedule_new_workflow.await_args.kwargs["input"] == {"object_id": "obj-1"}
    client.wait_for_workflow_completion.assert_awaited_once()
    assert client.wait_for_workflow_completion.await_args.kwargs["timeout_in_seconds"] <= wm.max_workflow_execution_time
    client.terminate_workflow.assert_not_awaited()
    assert wm.active_workflows == {}
    assert wm.workflow_semaphore._value == 2  # slot released


@pytest.mark.asyncio
async def test_slot_is_held_until_the_workflow_finishes(client):
    finished = asyncio.Event()

    async def wait(*args, **kwargs):
        await finished.wait()
        return _state("FAILED")

    client.wait_for_workflow_completion.side_effect = wait
    await wm.start_workflow_with_concurrency_control(SimpleNamespace(object_id="obj-1", file_name="a.docx"))
    await asyncio.sleep(0)
    assert wm.workflow_semaphore._value == 1
    finished.set()
    await _drain()
    assert wm.workflow_semaphore._value == 2


@pytest.mark.asyncio
async def test_timeout_terminates_the_workflow(client, monkeypatch):
    monkeypatch.setattr(wm, "max_workflow_execution_time", 0.05)

    async def never(*args, **kwargs):
        await asyncio.sleep(kwargs["timeout_in_seconds"] / 20)
        raise TimeoutError

    client.wait_for_workflow_completion.side_effect = never
    await wm.monitor_workflow_completion("document_conversion.slow")
    client.terminate_workflow.assert_awaited_once_with("document_conversion.slow")
    assert wm.workflow_semaphore._value == 3  # released once (fixture semaphore started at 2)


@pytest.mark.asyncio
async def test_wait_errors_are_retried(client, monkeypatch):
    monkeypatch.setattr(wm.asyncio, "sleep", AsyncMock())
    client.wait_for_workflow_completion.side_effect = [RuntimeError("sidecar restarting"), _state("COMPLETED")]
    await wm.monitor_workflow_completion("document_conversion.retry")
    assert client.wait_for_workflow_completion.await_count == 2
    client.terminate_workflow.assert_not_awaited()


@pytest.mark.asyncio
async def test_terminate_failure_still_releases_the_slot(client, monkeypatch):
    monkeypatch.setattr(wm, "max_workflow_execution_time", 0)
    client.terminate_workflow.side_effect = RuntimeError("gone")
    await wm.monitor_workflow_completion("document_conversion.gone")
    assert wm.workflow_semaphore._value == 3


@pytest.mark.asyncio
async def test_schedule_failure_releases_the_slot(client):
    client.schedule_new_workflow.side_effect = RuntimeError("sidecar down")
    with pytest.raises(RuntimeError, match="sidecar down"):
        await wm.start_workflow_with_concurrency_control(SimpleNamespace(object_id="obj-1", file_name="a.docx"))
    assert wm.workflow_semaphore._value == 2
    assert wm._monitor_tasks == set()
    assert wm.active_workflows == {}

"""Bulk enrichment: single_enrichment_workflow re-runs one module through run_enrichment_modules.

It used to look up a per-module `enrich_<name>` activity that no longer exists (removed when all modules moved into
run_enrichment_modules), so every bulk task failed with a KeyError.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import dapr.ext.workflow._durabletask.internal.protos as pb
import pytest
from dapr.ext.workflow import TaskFailedError

with patch("common.storage.StorageS3", MagicMock()):
    import common.workflows.setup as wf_setup
    import file_enrichment.activities.enrichment_modules as enrichment_modules
    import file_enrichment.global_vars as global_vars
    import file_enrichment.workflow as workflow

OBJECT_ID = "00000000-0000-0000-0000-000000000001"

# --- the workflow ---


class _Ctx:
    is_replaying = False
    current_utc_datetime = __import__("datetime").datetime(2026, 1, 1)
    instance_id = "file_enrichment.bulk-test"

    def call_activity(self, fn, **kwargs):
        return (getattr(fn, "__name__", str(fn)), kwargs.get("input"))


def _drive(fail_modules: bool = False):
    """Run the workflow generator; returns (awaited (name, input) pairs, return value or raised exception)."""
    gen = workflow.single_enrichment_workflow()(_Ctx(), {"enrichment_name": "yara", "object_id": OBJECT_ID})
    awaited = []
    step = next(gen)
    try:
        while True:
            awaited.append(step)
            if fail_modules and step[0] == "run_enrichment_modules":
                details = pb.TaskFailureDetails(errorMessage="yara exploded", errorType="Boom")
                step = gen.throw(TaskFailedError("yara exploded", details))
            else:
                step = gen.send(
                    [["yara", {"status": "success", "module": "yara"}]] if step[0] == "run_enrichment_modules" else None
                )
    except StopIteration as stop:
        return awaited, stop.value
    except TaskFailedError as e:
        return awaited, e


def test_runs_only_the_requested_module_then_finalizes():
    awaited, result = _drive()
    assert [name for name, _ in awaited] == ["run_enrichment_modules", "finalize_workflow_success"]
    assert awaited[0][1] == {"object_id": OBJECT_ID, "modules": ["yara"]}
    assert result == [["yara", {"status": "success", "module": "yara"}]]


def test_failed_module_run_marks_the_workflow_failed():
    awaited, result = _drive(fail_modules=True)
    assert [name for name, _ in awaited] == ["run_enrichment_modules", "finalize_workflow_failure"]
    assert "yara exploded" in awaited[1][1]["error_message"]
    assert isinstance(result, TaskFailedError)


# --- the module activity ---


class _Module:
    def __init__(self, applies: bool = True):
        self.applies = applies
        self.processed = 0

    async def should_process(self, object_id, path):
        return self.applies

    async def process(self, object_id, path):
        self.processed += 1
        return SimpleNamespace(transforms=[], findings=[])


@pytest.fixture
def modules(monkeypatch, tmp_path):
    """Three loaded modules, a fake downloaded file, and recorded result storage/tracking."""
    loaded = {"yara": _Module(), "pe": _Module(), "office": _Module(applies=False)}
    monkeypatch.setattr(global_vars, "global_module_map", loaded)
    monkeypatch.setattr(global_vars, "module_execution_order", ["yara", "pe", "office"])

    path = tmp_path / "file.bin"
    path.write_bytes(b"MZ")
    temp_file = MagicMock()
    temp_file.name = str(path)
    monkeypatch.setattr(global_vars, "storage", SimpleNamespace(download_async=AsyncMock(return_value=temp_file)))

    tracking = SimpleNamespace(update_enrichment_results=AsyncMock())
    monkeypatch.setattr(global_vars, "tracking_service", tracking)
    stored = []
    monkeypatch.setattr(
        enrichment_modules, "store_enrichment_results", AsyncMock(side_effect=lambda o, m, r: stored.append(m))
    )
    loaded_state = SimpleNamespace(loaded=loaded, stored=stored, tracking=tracking, temp_file=temp_file)
    return loaded_state


async def _run_activity(monkeypatch, activity_input):
    monkeypatch.setattr(wf_setup, "workflow_loop", asyncio.get_running_loop())
    ctx = SimpleNamespace(workflow_id="file_enrichment.bulk-test")
    return await enrichment_modules.run_enrichment_modules()(ctx, activity_input)


@pytest.mark.asyncio
async def test_selected_module_is_the_only_one_run(modules, monkeypatch):
    results = await _run_activity(monkeypatch, {"object_id": OBJECT_ID, "modules": ["pe"]})
    assert results == [("pe", {"status": "success", "module": "pe"})]
    assert modules.stored == ["pe"]
    assert modules.loaded["yara"].processed == 0
    modules.tracking.update_enrichment_results.assert_awaited_once_with(
        instance_id="file_enrichment.bulk-test", success_list=["pe"]
    )
    modules.temp_file.__exit__.assert_called_once()  # the download is cleaned up


@pytest.mark.asyncio
async def test_selected_module_still_decides_whether_the_file_applies(modules, monkeypatch):
    assert await _run_activity(monkeypatch, {"object_id": OBJECT_ID, "modules": ["office"]}) == []
    assert modules.loaded["office"].processed == 0
    assert modules.stored == []


@pytest.mark.asyncio
async def test_without_a_selection_every_applicable_module_runs(modules, monkeypatch):
    results = await _run_activity(monkeypatch, {"object_id": OBJECT_ID})
    assert [name for name, _ in results] == ["yara", "pe"]


@pytest.mark.asyncio
async def test_unknown_module_fails_the_activity(modules, monkeypatch):
    with pytest.raises(ValueError, match="Unknown enrichment module\\(s\\): nope"):
        await _run_activity(monkeypatch, {"object_id": OBJECT_ID, "modules": ["nope", "pe"]})
    assert modules.stored == []
    global_vars.storage.download_async.assert_not_awaited()

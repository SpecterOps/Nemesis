"""Enrichment workflow ordering and failure tolerance.

The workflow must finish publishing before it finalizes (also when replaying), and one failed activity must not skip
the other activities, the publishing steps, or finalization (#76).
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import dapr.ext.workflow._durabletask.internal.protos as pb
import pytest
from dapr.ext.workflow import TaskFailedError

with patch("common.storage.StorageS3", MagicMock()):
    import file_enrichment.workflow as workflow


class _Ctx:
    def __init__(self, replaying):
        self.is_replaying = replaying
        self.current_utc_datetime = __import__("datetime").datetime(2026, 1, 1)
        self.instance_id = "file_enrichment.test"
        self.scheduled = []

    def call_activity(self, fn, **kwargs):
        name = getattr(fn, "__name__", str(fn))
        self.scheduled.append(name)
        return ("activity", name, kwargs.get("input"))


def _failure(name):
    return TaskFailedError(f"{name} failed", pb.TaskFailureDetails(errorMessage=f"{name} failed", errorType="Boom"))


def _run(replaying=False, failing=()):
    """Drive the workflow generator; tasks named in ``failing`` raise TaskFailedError when awaited.

    Returns (awaited task names in order, scheduled activity names in order, workflow return value).
    """
    ctx = _Ctx(replaying)
    awaited = []
    with patch.object(workflow, "File", MagicMock(model_validate=lambda d: SimpleNamespace(object_id="obj-1"))):
        gen = workflow.enrichment_pipeline_workflow()(ctx, {"object_id": "obj-1", "path": "/a.txt"})
        step = next(gen)
        try:
            while True:
                name = step[1]
                awaited.append(name)
                step = gen.throw(_failure(name)) if name in failing else gen.send(None)
        except StopIteration as stop:
            return awaited, ctx.scheduled, stop.value
    raise AssertionError("unreachable")


ENRICHMENT = ["run_enrichment_modules", "check_file_linkings", "handle_file_if_plaintext"]
FINAL = ["publish_enriched_file", "publish_findings_alerts"]


@pytest.mark.parametrize("replaying", [False, True])
def test_final_tasks_are_awaited_before_finalize(replaying):
    awaited, _, result = _run(replaying)
    assert awaited == ["get_basic_analysis", *ENRICHMENT, *FINAL, "finalize_workflow_success"]
    assert result == {}


def test_enrichment_tasks_are_scheduled_together_before_any_is_awaited():
    ctx_order = _run()[1]
    # All three are scheduled before the first is awaited, so they run in parallel.
    assert ctx_order[1:4] == ENRICHMENT


@pytest.mark.parametrize("failed", ENRICHMENT)
def test_one_enrichment_failure_still_runs_everything_else(failed):
    awaited, _, result = _run(failing={failed})
    # The other enrichment tasks are still awaited and the publishing steps still run.
    for name in ENRICHMENT + FINAL:
        assert name in awaited
    assert awaited[-1] == "finalize_workflow_failure"
    assert "finalize_workflow_success" not in awaited
    assert result == {"failed_activities": [failed]}


def test_failure_message_names_failed_activities():
    ctx = _Ctx(False)
    with patch.object(workflow, "File", MagicMock(model_validate=lambda d: SimpleNamespace(object_id="obj-1"))):
        gen = workflow.enrichment_pipeline_workflow()(ctx, {"object_id": "obj-1"})
        step = next(gen)
        failing = {"handle_file_if_plaintext", "publish_findings_alerts"}
        try:
            while step[1] != "finalize_workflow_failure":
                step = gen.throw(_failure(step[1])) if step[1] in failing else gen.send(None)
        except StopIteration:
            pytest.fail("finalize_workflow_failure was not called")
    assert step[2]["error_message"] == "activities failed: handle_file_if_plaintext, publish_findings_alerts"


def test_publish_failure_does_not_skip_the_other_publish_step():
    awaited, _, result = _run(failing={"publish_enriched_file"})
    assert "publish_findings_alerts" in awaited
    assert result == {"failed_activities": ["publish_enriched_file"]}


def test_basic_analysis_failure_still_fails_the_workflow():
    with pytest.raises(TaskFailedError):
        _run(failing={"get_basic_analysis"})

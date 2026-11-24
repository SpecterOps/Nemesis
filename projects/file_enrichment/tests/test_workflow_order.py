"""The enrichment workflow must finish publishing before it finalizes, also when replaying."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

with patch("common.storage.StorageS3", MagicMock()):
    import file_enrichment.workflow as workflow


class _Ctx:
    def __init__(self, replaying):
        self.is_replaying = replaying
        self.current_utc_datetime = __import__("datetime").datetime(2026, 1, 1)
        self.instance_id = "file_enrichment.test"

    def call_activity(self, fn, **kwargs):
        return ("activity", getattr(fn, "__name__", str(fn)))


def _run(replaying):
    """Drive the generator, answering every yield, and return what it yielded in order."""
    yielded = []
    with patch.object(workflow.wf, "when_all", side_effect=lambda tasks: ("when_all", tuple(t[1] for t in tasks))):
        gen = workflow.enrichment_pipeline_workflow()(_Ctx(replaying), {"object_id": "obj-1", "path": "/a.txt"})
        value = None
        try:
            while True:
                step = gen.send(value)
                yielded.append(step)
                value = [None] * len(step[1]) if step[0] == "when_all" else None
        except StopIteration:
            pass
    return yielded


@pytest.mark.parametrize("replaying", [False, True])
def test_final_tasks_are_awaited_before_finalize(replaying):
    with patch.object(workflow, "File", MagicMock(model_validate=lambda d: SimpleNamespace(object_id="obj-1"))):
        steps = _run(replaying)
    names = [s[1] for s in steps]
    final = ("publish_enriched_file", "publish_findings_alerts")
    assert final in names
    assert names.index(final) < names.index("finalize_workflow_success")
    assert names[-1] == "finalize_workflow_success"

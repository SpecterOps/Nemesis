"""Every input the triage workflow hands to Dapr must survive Dapr's own JSON encoder (UUIDs included)."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest
from agents.schemas import TriageCategory, TriageRequest, TriageResult
from dapr.ext.workflow._durabletask.internal.shared import from_json, to_json

# agents.main fetches a secret through DaprClient at import time
with patch("dapr.clients.DaprClient") as _client:
    _client.return_value.__enter__.return_value.get_secret.return_value = SimpleNamespace(
        secret={"HASURA_ADMIN_SECRET": "x"}
    )
    import agents.main as agents_main


def triage_request(object_id: UUID) -> TriageRequest:
    data = [{"type": "finding_summary", "metadata": {"summary": "a password"}}]
    return TriageRequest(finding_id=7, finding_name="f", object_id=object_id, data=data, file_path="/x")


def test_triage_request_dump_encodes_for_dapr():
    object_id = uuid4()
    encoded = from_json(to_json(triage_request(object_id).model_dump()))
    assert encoded["object_id"] == str(object_id)
    assert TriageRequest(**encoded).object_id == object_id


def test_triage_result_dump_encodes_for_dapr():
    result = TriageResult(finding_id=1, decision=TriageCategory.TRUE_POSITIVE, explanation="e", success=True)
    assert from_json(to_json(result.model_dump()))["decision"] == "true_positive"


class FakeContext:
    is_replaying = True

    def __init__(self):
        self.inputs: list[tuple[str, object]] = []

    def call_activity(self, activity, input=None, **kwargs):  # noqa: A002 - matches Dapr's keyword
        self.inputs.append((getattr(activity, "__name__", str(activity)), input))
        return object()


def run_workflow(ctx: FakeContext, workflow_input: dict, replies: list):
    gen = agents_main.finding_triage_workflow.__wrapped__(ctx, workflow_input)  # pyright: ignore[reportFunctionMemberAccess]
    next(gen)
    for reply in replies:
        try:
            gen.send(reply)
        except StopIteration:
            return


VALIDATION = {"decision": "true_positive", "explanation": "e", "confidence": 0.9, "true_positive_context": "c"}
CONSENSUS = {"has_consensus": True, "decision": "false_positive", "count": 3}


@pytest.mark.parametrize(
    ("replies", "expected"),
    [
        # no consensus, LLM validates, result inserted
        (
            [{"has_consensus": False}, VALIDATION, None],
            ["check_consensus_activity", "validate", "insert_triage_result"],
        ),
        # consensus reached, result inserted without the LLM
        ([CONSENSUS, None], ["check_consensus_activity", "insert_triage_result"]),
    ],
)
def test_every_activity_input_encodes_for_dapr(replies, expected):
    object_id = uuid4()
    ctx = FakeContext()
    workflow_input = from_json(to_json(triage_request(object_id).model_dump()))
    with (
        patch.object(agents_main.ModelManager, "is_available", return_value=True),
        patch.object(agents_main.agent_manager, "get_wrapper_function", return_value=MagicMock(__name__="validate")),
    ):
        run_workflow(ctx, workflow_input, replies)

    assert [name for name, _ in ctx.inputs] == expected
    for name, activity_input in ctx.inputs:
        decoded = from_json(to_json(activity_input))
        if "object_id" in decoded:
            assert decoded["object_id"] == str(object_id), name


def test_raw_uuid_is_what_dapr_rejects():
    """Guards the premise: Dapr's encoder can't take a bare UUID, so inputs must be made JSON-safe first."""
    with pytest.raises(TypeError):
        to_json({"object_id": uuid4()})

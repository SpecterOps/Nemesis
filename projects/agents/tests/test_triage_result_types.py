"""TriageResult.decision only accepts the values findings_triage_history.value allows."""

import pytest
from agents.schemas import TriageCategory, TriageResult
from pydantic import ValidationError


@pytest.mark.parametrize("value", [c.value for c in TriageCategory])
def test_known_decisions_accepted(value):
    assert TriageResult(finding_id=1, decision=value, explanation="e", success=True).decision == TriageCategory(value)


@pytest.mark.parametrize("value", ["maybe", "TRUE_POSITIVE", ""])
def test_unknown_decision_rejected(value):
    with pytest.raises(ValidationError):
        TriageResult(finding_id=1, decision=value, explanation="e", success=True)


def test_decision_dumps_as_plain_string():
    dumped = TriageResult(finding_id=1, decision="false_positive", explanation="e", success=True).model_dump(
        mode="json"
    )
    assert dumped["decision"] == "false_positive"

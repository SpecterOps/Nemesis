"""Over-long LLM triage text is stored truncated (not lost) and the truncation is logged."""

import pytest
from agents.schemas import TRIAGE_TEXT_MAX_LENGTH
from agents.triage_text import fit_triage_text
from common import data_issues


@pytest.fixture
def issues(monkeypatch):
    calls = []
    monkeypatch.setattr(data_issues, "logger", type("L", (), {"warning": lambda self, e, **kw: calls.append(kw)})())
    return calls


@pytest.mark.parametrize("value", [None, "", "short", "x" * TRIAGE_TEXT_MAX_LENGTH])
def test_fitting_text_is_unchanged(value, issues):
    assert fit_triage_text(value, "explanation", 7) == value
    assert issues == []


def test_long_text_is_truncated_and_logged(issues):
    out = fit_triage_text("y" * 6000, "true_positive_context", 42)
    assert out == "y" * TRIAGE_TEXT_MAX_LENGTH
    assert issues == [
        {
            "kind": "triage_text_truncated",
            "field": "findings_triage_history.true_positive_context",
            "object_id": None,
            "finding_id": 42,
            "length": 6000,
            "limit": TRIAGE_TEXT_MAX_LENGTH,
        }
    ]

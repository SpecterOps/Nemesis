"""findings.data reaches the triage agent as an array of objects."""

from uuid import uuid4

import pytest
from agents.finding_data import extract_summary_from_triage_request
from agents.schemas import TriageRequest
from pydantic import ValidationError


def request(data):
    return TriageRequest(finding_id=1, finding_name="f", object_id=uuid4(), data=data, file_path="/x")


def test_summary_from_first_object():
    data = [{"type": "finding_summary", "metadata": {"summary": "first"}}, {"metadata": {"summary": "second"}}]
    assert extract_summary_from_triage_request(request(data)) == "first"


@pytest.mark.parametrize("data", [[], [{"type": "finding_summary"}], [{"metadata": "not a dict"}]])
def test_no_summary(data):
    assert extract_summary_from_triage_request(request(data)) is None


def test_json_string_items_are_rejected():
    with pytest.raises(ValidationError):
        request(['{"metadata": {"summary": "old shape"}}'])

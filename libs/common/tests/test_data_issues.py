"""Data issues are logged (never silently fixed), and JSONB values are sanitized with a report."""

import json
import math
from datetime import UTC, datetime
from enum import StrEnum
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from common import data_issues
from common.data_issues import DataIssueKind, log_data_issue
from common.helpers import jsonb_dumps, sanitize_for_jsonb_report
from pydantic import BaseModel


class Recorder:
    def __init__(self):
        self.calls = []

    def warning(self, event, **kwargs):
        self.calls.append((event, kwargs))


@pytest.fixture
def issues(monkeypatch):
    recorder = Recorder()
    monkeypatch.setattr(data_issues, "logger", recorder)
    return recorder.calls


def test_log_data_issue_emits_structured_warning(issues):
    object_id = uuid4()
    log_data_issue(DataIssueKind.EXTENSION_TOO_LONG, field="files_enriched.extension", object_id=object_id, length=80)
    assert issues == [
        (
            "data_issue",
            {
                "kind": "extension_too_long",
                "field": "files_enriched.extension",
                "object_id": str(object_id),
                "length": 80,
            },
        )
    ]


def test_log_data_issue_without_object(issues):
    log_data_issue(DataIssueKind.REJECTED_INPUT, field="metadata.timestamp", reason="naive datetime")
    assert issues[0][1]["object_id"] is None and issues[0][1]["reason"] == "naive datetime"


def test_clean_input_is_unchanged_and_not_logged(issues):
    value = {"a": [1, 2.5, True, None, "text\nwith\ttabs"], "b": {"c": "d"}}
    assert json.loads(jsonb_dumps(value, column="findings.raw_data")) == value
    assert issues == []


def test_strings_are_cleaned_and_counted(issues):
    object_id = uuid4()
    out = json.loads(jsonb_dumps({"s": "a\x00b\x01c\ud800d"}, column="findings.raw_data", object_id=object_id))
    assert out == {"s": "abcd"}
    (_, detail) = issues[0]
    assert detail["kind"] == "jsonb_sanitized" and detail["field"] == "findings.raw_data"
    assert detail["object_id"] == str(object_id)
    assert (detail["nul_bytes"], detail["control_chars"], detail["surrogates"]) == (1, 1, 1)


class Color(StrEnum):
    RED = "red"


class Inner(BaseModel):
    when: datetime
    id: UUID


def test_standard_types_convert_without_being_an_issue(issues):
    when = datetime(2026, 1, 2, tzinfo=UTC)
    object_id = uuid4()
    out = json.loads(jsonb_dumps({"m": Inner(when=when, id=object_id), "e": Color.RED, "u": object_id}, column="c"))
    assert out == {"m": {"when": "2026-01-02T00:00:00Z", "id": str(object_id)}, "e": "red", "u": str(object_id)}
    assert issues == []


def test_non_json_values_are_converted_and_counted(issues):
    clean, report = sanitize_for_jsonb_report(
        {"bytes": b"\x01\xff", "nan": math.nan, "inf": math.inf, 7: "key", "obj": SimpleNamespace(x=1)}
    )
    assert clean["bytes"] == "01ff" and clean["nan"] is None and clean["inf"] is None and clean["7"] == "key"
    assert isinstance(clean["obj"], str)
    assert report.non_json_values == 5
    assert report.changed


def test_nested_lists_tuples_and_sets(issues):
    clean, report = sanitize_for_jsonb_report({"t": ("a\x00",), "l": [["b"]], "s": {"c"}})
    assert clean == {"t": ["a"], "l": [["b"]], "s": ["c"]}
    assert report.nul_bytes == 1


def test_dict_keys_are_cleaned(issues):
    out = json.loads(jsonb_dumps({"k\x00ey": 1}, column="c"))
    assert out == {"key": 1}
    assert issues[0][1]["nul_bytes"] == 1


def test_context_is_included_in_log(issues):
    jsonb_dumps({"s": "\x00"}, column="findings.data", finding_name="x")
    assert issues[0][1]["finding_name"] == "x"

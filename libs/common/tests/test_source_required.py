"""Every stored file has a source; an omitted one becomes unknown://unknown, which is never correlated."""

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from common import data_issues
from common.models import File
from common.models2.api import UNKNOWN_SOURCE, FileMetadata, is_known_source
from pydantic import ValidationError

REPO = Path(__file__).resolve().parents[3]
SCHEMA = (REPO / "infra/postgres/01-schema.sql").read_text()


@pytest.fixture
def issues(monkeypatch):
    calls = []
    monkeypatch.setattr(data_issues, "logger", type("L", (), {"warning": lambda self, e, **kw: calls.append(kw)})())
    return calls


def metadata(**overrides) -> FileMetadata:
    now = datetime.now(UTC)
    fields = {"agent_id": "a", "project": "p", "path": "/x", "timestamp": now, "expiration": now + timedelta(days=1)}
    return FileMetadata(**(fields | overrides))


# --- models ------------------------------------------------------------------------------------------------


def test_metadata_source_defaults_to_unknown():
    assert metadata().source == UNKNOWN_SOURCE


def test_metadata_null_source_means_unknown():
    assert metadata(source=None).source == UNKNOWN_SOURCE


def test_metadata_keeps_given_source():
    assert metadata(source="host://WS01").source == "host://WS01"


@pytest.mark.parametrize("value", ["", "   ", "x" * 1001])
def test_metadata_rejects_blank_or_too_long_source(value):
    with pytest.raises(ValidationError):
        metadata(source=value)


@pytest.mark.parametrize("value", [None, "", "  "])
def test_file_requires_non_blank_source(value):
    now = datetime.now(UTC)
    fields = {
        "object_id": uuid4(),
        "agent_id": "a",
        "project": "p",
        "path": "/x",
        "timestamp": now,
        "expiration": now + timedelta(days=1),
    }
    with pytest.raises(ValidationError):
        File(**fields)  # missing
    with pytest.raises(ValidationError):
        File(**fields, source=value)


def test_defaulted_source_is_logged_when_file_is_created(issues):
    object_id = uuid4()
    file = File.from_file_metadata(metadata(), object_id)
    assert file.source == UNKNOWN_SOURCE
    assert issues == [
        {"kind": "source_defaulted", "field": "files.source", "object_id": str(object_id), "source": UNKNOWN_SOURCE}
    ]


def test_known_source_is_not_logged(issues):
    File.from_file_metadata(metadata(source="host://WS01"), uuid4())
    assert issues == []


def test_is_known_source():
    assert is_known_source("host://WS01")
    assert not is_known_source(UNKNOWN_SOURCE)


# --- schema --------------------------------------------------------------------------------------------------


def table_body(name: str) -> str:
    match = re.search(rf"CREATE TABLE (?:IF NOT EXISTS )?{re.escape(name)} \((.*?)\n\);", SCHEMA, re.S)
    assert match, name
    return match.group(1)


@pytest.mark.parametrize(
    "table",
    [
        "files",
        "files_enriched",
        "container_processing",
        "chromium.history",
        "chromium.downloads",
        "chromium.state_keys",
        "chromium.chrome_keys",
        "chromium.logins",
        "chromium.cookies",
    ],
)
def test_source_is_required_and_non_blank(table):
    assert "source VARCHAR(1000) NOT NULL CHECK (btrim(source) <> '')" in table_body(table)


@pytest.mark.parametrize("table", ["file_listings", "file_linkings"])
def test_listings_and_linkings_never_hold_unknown_source(table):
    assert f"source <> '{UNKNOWN_SOURCE}'" in table_body(table)


@pytest.mark.parametrize(
    "table", ["chromium.history", "chromium.downloads", "chromium.state_keys", "chromium.logins", "chromium.cookies"]
)
def test_chromium_uniqueness_excludes_unknown_source(table):
    assert "UNIQUE (project, source" not in table_body(table)
    pattern = (
        rf"CREATE UNIQUE INDEX IF NOT EXISTS \w+ ON {re.escape(table)} \(project, source[^)]*\)\n"
        rf"\s+WHERE source <> '{re.escape(UNKNOWN_SOURCE)}';"
    )
    assert re.search(pattern, SCHEMA), table

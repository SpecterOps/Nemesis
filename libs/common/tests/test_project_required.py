"""Every stored row belongs to a project: the schema and the upload models both refuse a missing or blank one."""

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from common.models import File
from common.models2.api import FileMetadata
from pydantic import ValidationError

REPO = Path(__file__).resolve().parents[3]
SCHEMAS = [REPO / "infra/postgres/01-schema.sql", REPO / "k8s/helm/nemesis/files/01-schema.sql"]


def project_columns(schema: str) -> list[str]:
    return [line.strip() for line in schema.splitlines() if re.match(r"\s+project\s+(VARCHAR|TEXT)", line)]


@pytest.mark.parametrize("path", SCHEMAS, ids=lambda p: p.parent.name)
def test_every_project_column_is_required_and_non_blank(path):
    columns = project_columns(path.read_text())
    assert len(columns) >= 13
    for column in columns:
        assert "NOT NULL" in column, column
        assert "CHECK (btrim(project) <> '')" in column, column


@pytest.mark.parametrize("path", SCHEMAS, ids=lambda p: p.parent.name)
def test_no_null_tolerant_project_uniqueness(path):
    assert "NULLS NOT DISTINCT" not in path.read_text()


def test_schema_copies_match():
    assert SCHEMAS[0].read_text() == SCHEMAS[1].read_text()


def file_fields(**overrides):
    now = datetime.now(UTC)
    return {
        "object_id": "00000000-0000-0000-0000-000000000001",
        "agent_id": "a",
        "project": "op",
        "timestamp": now,
        "expiration": now + timedelta(days=1),
        "path": "/x",
    } | overrides


@pytest.mark.parametrize("model", [FileMetadata, File])
def test_valid_project_accepted(model):
    assert model(**file_fields(project="engagement-1")).project == "engagement-1"


@pytest.mark.parametrize("model", [FileMetadata, File])
@pytest.mark.parametrize("value", [None, "", "   ", "\t", "x" * 256])
def test_missing_blank_or_oversized_project_rejected(model, value):
    with pytest.raises(ValidationError):
        model(**file_fields(project=value))


@pytest.mark.parametrize("model", [FileMetadata, File])
def test_project_field_required(model):
    fields = file_fields()
    del fields["project"]
    with pytest.raises(ValidationError):
        model(**fields)

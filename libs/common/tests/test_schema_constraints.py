"""The schema enforces the same rules as the Python writers, so Hasura/frontend/notebook writes can't bypass them."""

import re
from pathlib import Path

import pytest
from common.models import FindingCategory, FindingOrigin

REPO = Path(__file__).resolve().parents[3]
SCHEMA = (REPO / "infra/postgres/01-schema.sql").read_text()
HELM_SCHEMA = REPO / "k8s/helm/nemesis/files/01-schema.sql"


def table_columns(table: str) -> dict[str, str]:
    """Column name -> full definition (multi-line CHECKs joined) for a CREATE TABLE in the schema."""
    match = re.search(rf"CREATE TABLE (?:IF NOT EXISTS )?{re.escape(table)} \((.*?)\n\);", SCHEMA, re.S)
    assert match, f"table {table} not found"
    columns: dict[str, str] = {}
    current = None
    for line in match.group(1).splitlines():
        if not line.strip() or line.strip().startswith("--"):
            continue
        head = re.match(r"    ([a-z_]+) ", line)
        if head and head.group(1) not in {"unique", "foreign", "primary", "check", "constraint"}:
            current = head.group(1)
            columns[current] = line.strip()
        elif current and (line.startswith("        ") or line.strip().startswith(")")):
            columns[current] += " " + line.strip()
        else:
            current = None
    return columns


def check_values(definition: str) -> set[str]:
    match = re.search(r"CHECK \([a-z_]+ IN \((.*?)\)\)", definition, re.S)
    assert match, definition
    return set(re.findall(r"'([a-z_]+)'", match.group(1)))


TRIAGE_VALUES = {"true_positive", "false_positive", "needs_review", "not_triaged", "error"}


def test_finding_enums_match_python():
    columns = table_columns("findings")
    assert check_values(columns["category"]) == {c.value for c in FindingCategory}
    assert check_values(columns["origin_type"]) == {o.value for o in FindingOrigin}
    assert "CHECK (severity BETWEEN 0 AND 10)" in columns["severity"]


def test_triage_values_checked_on_history_and_denormalized_copy():
    assert check_values(table_columns("findings_triage_history")["value"]) == TRIAGE_VALUES
    triage_value = table_columns("findings")["triage_value"]
    assert check_values(triage_value) == TRIAGE_VALUES
    assert "NOT NULL" not in triage_value  # NULL until first triage


def test_container_processing_constraints():
    columns = table_columns("container_processing")
    assert check_values(columns["status"]) == {
        "submitted",
        "processing",
        "extracting",
        "extracted",
        "workflows_complete",
        "failed",
    }
    assert check_values(columns["container_type"]) == {"zip", "dd_image"}
    for column in (
        "agent_id",
        "total_files_extracted",
        "total_bytes_extracted",
        "workflows_completed",
        "workflows_failed",
        "workflows_total",
        "total_bytes_processed",
    ):
        assert "NOT NULL" in columns[column], column


def test_masterkey_type_required_and_checked():
    column = table_columns("dpapi.masterkeys")["masterkey_type"]
    assert "NOT NULL" in column and "DEFAULT 'unknown'" in column
    assert check_values(column) == {"unknown", "user", "system", "system_user"}


@pytest.mark.parametrize(
    ("table", "required"),
    [
        ("files", ["agent_id", "timestamp", "expiration", "path"]),
        (
            "files_enriched",
            ["agent_id", "timestamp", "expiration", "path", "file_name", "size", "hashes", "magic_type"]
            + ["mime_type", "is_plaintext", "is_container"],
        ),
    ],
)
def test_always_written_columns_are_not_null(table, required):
    columns = table_columns(table)
    for column in required:
        assert "NOT NULL" in columns[column], f"{table}.{column}"


@pytest.mark.parametrize(
    ("table", "column"),
    [
        ("chromium.downloads", "total_bytes"),
        ("chromium.history", "visit_count"),
    ],
)
def test_chromium_int64_columns_are_bigint(table, column):
    assert " BIGINT" in table_columns(table)[column]


def test_dead_dataset_table_removed():
    assert "files_enriched_dataset" not in SCHEMA
    assert "get_parent_path" not in SCHEMA


def test_helm_schema_matches():
    assert HELM_SCHEMA.read_text() == SCHEMA

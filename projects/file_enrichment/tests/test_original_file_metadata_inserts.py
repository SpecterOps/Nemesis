"""Original file times and security_info reach the files and files_enriched rows (they used to always be NULL)."""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from common.models import File

with patch("common.storage.StorageS3", MagicMock()):
    import file_enrichment.global_vars as global_vars
    import file_enrichment.subscriptions.file as sub
    from file_enrichment.activities import basic_analysis


class RecordingPool:
    def __init__(self):
        self.calls: list[tuple[str, tuple]] = []

    def acquire(self):
        pool = self

        class _Conn:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def execute(self, query, *args):
                pool.calls.append((query, args))

        return _Conn()


@pytest.fixture
def pool(monkeypatch):
    recording = RecordingPool()
    monkeypatch.setattr(global_vars, "asyncpg_pool", recording)
    return recording


def make_file(**overrides) -> File:
    now = datetime.now(UTC)
    return File(
        object_id=uuid4(),
        agent_id="a",
        source="host://ws01",
        project="p",
        timestamp=now,
        expiration=now + timedelta(days=1),
        path="/loot/a.txt",
        **overrides,
    )


def column_values(query: str, args: tuple) -> dict:
    columns = query.split("(", 1)[1].split(")", 1)[0]
    names = [c.strip() for c in columns.split(",")]
    return dict(zip(names, args, strict=True))


@pytest.mark.asyncio
async def test_files_insert_writes_original_times_and_security(pool):
    created = datetime(2024, 1, 1, tzinfo=UTC)
    modified = datetime(2024, 1, 2, tzinfo=UTC)
    await sub.save_file_message(
        make_file(creation_time=created, modification_time=modified, security_info={"owner": "alice", "mode": 0o644})
    )
    values = column_values(*pool.calls[0])
    assert values["file_creation_time"] == created
    assert values["file_access_time"] is None
    assert values["file_modification_time"] == modified
    assert json.loads(values["security_info"]) == {"owner": "alice", "group": None, "mode": 0o644, "extra": None}


@pytest.mark.asyncio
async def test_files_insert_without_details_writes_nulls(pool):
    await sub.save_file_message(make_file())
    values = column_values(*pool.calls[0])
    assert values["file_creation_time"] is None and values["security_info"] is None


@pytest.mark.asyncio
async def test_files_enriched_insert_reads_model_field_names(pool):
    """The activity input is a File dump (creation_time, ...); the insert used to read file_creation_time keys."""
    file = make_file(
        creation_time=datetime(2024, 1, 1, tzinfo=UTC),
        access_time=datetime(2024, 1, 3, tzinfo=UTC),
        modification_time=datetime(2024, 1, 2, tzinfo=UTC),
        security_info={"owner": "alice", "extra": {"acl": "D:(A;;FA;;;WD)"}},
    )
    file_enriched = {
        **file.model_dump(exclude_none=True),
        "file_name": "a.txt",
        "size": 1,
        "hashes": {"md5": "m", "sha1": "s", "sha256": "h"},
        "magic_type": "data",
        "mime_type": "application/octet-stream",
        "is_plaintext": False,
        "is_container": False,
    }
    await basic_analysis.save_file_enriched_to_db(file_enriched)
    values = column_values(*pool.calls[0])
    assert values["file_creation_time"] == datetime(2024, 1, 1, tzinfo=UTC)
    assert values["file_access_time"] == datetime(2024, 1, 3, tzinfo=UTC)
    assert values["file_modification_time"] == datetime(2024, 1, 2, tzinfo=UTC)
    assert json.loads(values["security_info"])["extra"] == {"acl": "D:(A;;FA;;;WD)"}


@pytest.mark.asyncio
async def test_files_enriched_security_info_is_sanitized_and_logged(pool, monkeypatch):
    from common import data_issues

    logged = []
    monkeypatch.setattr(
        data_issues, "logger", type("L", (), {"warning": lambda self, event, **kw: logged.append(kw)})()
    )
    file = make_file(security_info={"owner": "al\x00ice"})
    file_enriched = {
        **file.model_dump(exclude_none=True),
        "file_name": "a.txt",
        "size": 1,
        "hashes": {"md5": "m", "sha1": "s", "sha256": "h"},
        "magic_type": "data",
        "mime_type": "text/plain",
        "is_plaintext": True,
        "is_container": False,
    }
    await basic_analysis.save_file_enriched_to_db(file_enriched)
    assert json.loads(column_values(*pool.calls[0])["security_info"])["owner"] == "alice"
    assert logged and logged[0]["kind"] == "jsonb_sanitized" and logged[0]["field"] == "files_enriched.security_info"

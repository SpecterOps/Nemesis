"""Tests for metadata validation, ZIP extraction and LargeContainerProcessor in web_api.large_containers.

Storage (S3), Dapr and PostgreSQL are mocked.
"""

import json
import os
import zipfile
from datetime import UTC, date, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from web_api.large_containers import (
    DEFAULT_EXPIRATION_DAYS,
    ContainerExtractionError,
    ContainerMetadataError,
    ContainerProgress,
    ContainerStatus,
    LargeContainerProcessor,
    ZipContainerExtractor,
    coerce_metadata_value,
    normalize_container_path,
    validate_container_metadata,
)

# --- coerce_metadata_value / validate_container_metadata ---------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [("proj", "proj"), (2024, "2024"), (1.5, "1.5"), (date(2024, 1, 2), "2024-01-02")],
)
def test_coerce_scalars_to_str(value, expected):
    assert coerce_metadata_value("project", value, required=True) == expected


def test_coerce_optional_none_returns_none():
    assert coerce_metadata_value("source", None) is None


@pytest.mark.parametrize(
    ("value", "match"),
    [
        (None, "required"),
        ("   ", "must not be empty"),
        (True, "boolean"),
        (["a"], "must be a string, got list"),
        ({"a": 1}, "must be a string, got dict"),
        ("x" * 256, "too long"),
    ],
)
def test_coerce_rejects_invalid(value, match):
    with pytest.raises(ContainerMetadataError, match=match):
        coerce_metadata_value("project", value, required=True)


def test_source_length_limit_is_1000():
    assert coerce_metadata_value("source", "s" * 1000) == "s" * 1000
    with pytest.raises(ContainerMetadataError, match="too long"):
        coerce_metadata_value("source", "s" * 1001)


def test_validate_container_metadata_coerces_in_place():
    meta = {"agent_id": 7, "project": 2024, "source": None, "path": "/x"}
    validate_container_metadata(meta)
    assert meta == {"agent_id": "7", "project": "2024", "source": None, "path": "/x"}


def test_validate_container_metadata_requires_agent_and_project():
    with pytest.raises(ContainerMetadataError, match="agent_id"):
        validate_container_metadata({"project": "p"})


# --- normalize_container_path ------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("C:\\Users\\x\\a.zip", "/C:/Users/x/a.zip"),
        ("C:/Users/x/a.zip", "/C:/Users/x/a.zip"),
        ("/mounted-containers/case/a.zip", "/mounted-containers/case/a.zip"),
        ("s3://bucket/key/a.zip", "s3://bucket/key/a.zip"),
        ("a.zip", "a.zip"),
        ("", ""),
    ],
)
def test_normalize_container_path(path, expected):
    assert normalize_container_path(path) == expected


# --- set_container_info ------------------------------------------------------------------


def _extractor(cls=ZipContainerExtractor, storage=None, dapr=None):
    return cls(storage or MagicMock(), dapr or MagicMock(), ContainerProgress())


def test_default_expiration_is_timestamp_plus_default_days():
    ts = datetime(2020, 1, 1, tzinfo=UTC)
    extractor = _extractor()
    meta = {"agent_id": "a", "project": "p", "path": "/x.zip", "timestamp": ts.isoformat()}
    extractor.set_container_info("cid", meta)
    assert datetime.fromisoformat(meta["expiration"]) == ts + timedelta(days=DEFAULT_EXPIRATION_DAYS)


def test_default_expiration_accepts_aware_datetime_timestamp():
    extractor = _extractor()
    meta = {"agent_id": "a", "project": "p", "path": "/x.zip", "timestamp": datetime(2021, 6, 1, tzinfo=UTC)}
    extractor.set_container_info("cid", meta)
    assert datetime.fromisoformat(meta["expiration"]) == datetime(2021, 6, 1, tzinfo=UTC) + timedelta(
        days=DEFAULT_EXPIRATION_DAYS
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timestamp", datetime(2021, 6, 1)),
        ("timestamp", "2021-06-01T00:00:00"),
        ("expiration", "2031-06-01T00:00:00"),
        ("timestamp", "not a date"),
    ],
)
def test_naive_or_invalid_times_are_rejected_and_logged(field, value, monkeypatch):
    from common import data_issues

    calls = []
    monkeypatch.setattr(data_issues, "logger", type("L", (), {"warning": lambda self, e, **kw: calls.append(kw)})())
    extractor = _extractor()
    meta = {"agent_id": "a", "project": "p", "path": "/x.zip", field: value}
    with pytest.raises(ContainerMetadataError, match=field):
        extractor.set_container_info("cid", meta)
    assert calls and calls[0]["kind"] == "rejected_input" and field in calls[0]["reason"]


def test_aware_times_are_normalized_to_utc():
    extractor = _extractor()
    meta = {
        "agent_id": "a",
        "project": "p",
        "path": "/x.zip",
        "timestamp": "2021-06-01T02:00:00+02:00",
        "expiration": "2031-06-01T00:00:00Z",
    }
    extractor.set_container_info("cid", meta)
    assert meta["timestamp"] == "2021-06-01T00:00:00+00:00"
    assert meta["expiration"] == "2031-06-01T00:00:00+00:00"


def test_explicit_expiration_is_kept():
    extractor = _extractor()
    meta = {"agent_id": "a", "project": "p", "path": "/x.zip", "expiration": "2030-01-01T00:00:00+00:00"}
    extractor.set_container_info("cid", meta)
    assert meta["expiration"] == "2030-01-01T00:00:00+00:00"


def test_missing_timestamp_defaults_to_now():
    extractor = _extractor()
    meta = {"agent_id": "a", "project": "p", "path": "/x.zip"}
    before = datetime.now(UTC)
    extractor.set_container_info("cid", meta)
    assert datetime.fromisoformat(meta["timestamp"]) >= before


def test_invalid_timestamp_raises_metadata_error():
    extractor = _extractor()
    with pytest.raises(ContainerMetadataError, match="timestamp"):
        extractor.set_container_info("cid", {"agent_id": "a", "project": "p", "path": "/x", "timestamp": "nope"})


def test_set_container_info_rejects_bad_types_before_extraction():
    extractor = _extractor()
    with pytest.raises(ContainerMetadataError, match="project"):
        extractor.set_container_info("cid", {"agent_id": "a", "project": ["x"], "path": "/x.zip"})


def test_container_member_path_for_windows_container():
    extractor = _extractor()
    extractor.set_container_info("cid", {"agent_id": "a", "project": "p", "path": "C:\\Users\\x\\a.zip"})
    assert extractor.container_member_path("inner/file.txt") == "/C:/Users/x/inner/file.txt"
    assert extractor.container_member_path("inner\\b.txt") == "/C:/Users/x/inner/b.txt"


def test_container_member_path_strips_mount_prefix():
    extractor = _extractor()
    extractor.set_container_info("cid", {"agent_id": "a", "project": "p", "path": "/mounted-containers/c1/a.zip"})
    assert extractor.container_member_path("d/f.txt") == "c1/d/f.txt"


# --- ZIP extraction ----------------------------------------------------------------------


@pytest.fixture
def zip_path(tmp_path):
    p = tmp_path / "test.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("docs/a.txt", b"alpha")
        z.writestr("docs/b.log", b"bravo")
        z.writestr("c.txt", b"charlie")
    return p


@pytest.fixture
def storage():
    s = MagicMock()
    uploaded = []

    def _upload(path):
        with open(path, "rb") as f:
            uploaded.append((path, f.read()))
        return f"obj-{len(uploaded)}"

    s.upload_file.side_effect = _upload
    s.uploaded = uploaded
    return s


def _zip_extractor(storage, dapr, **meta):
    extractor = ZipContainerExtractor(storage, dapr, ContainerProgress())
    extractor.set_container_info(
        "cid", {"agent_id": "a", "project": 2024, "source": "s", "path": "C:\\loot\\test.zip", **meta}
    )
    extractor.progress_tracker.initialize("cid", 0, 0)
    return extractor


def test_zip_extracts_and_publishes_normalized_paths(zip_path, storage):
    dapr = MagicMock()
    extractor = _zip_extractor(storage, dapr)
    processed = extractor.extract_and_process(zip_path)

    assert processed == 3
    messages = [json.loads(c.kwargs["data"]) for c in dapr.publish_event.call_args_list]
    assert sorted(m["path"] for m in messages) == ["/C:/loot/c.txt", "/C:/loot/docs/a.txt", "/C:/loot/docs/b.log"]
    assert {m["project"] for m in messages} == {"2024"}
    assert sorted(c for _, c in storage.uploaded) == [b"alpha", b"bravo", b"charlie"]
    assert all(not os.path.exists(p) for p, _ in storage.uploaded)
    storage.delete_object.assert_not_called()


def test_zip_filter_skips_counted_once(zip_path, storage):
    extractor = _zip_extractor(storage, MagicMock(), file_filters={"pattern_type": "glob", "exclude": ["*.log"]})
    count, _ = extractor.estimate_container_contents(zip_path)
    processed = extractor.extract_and_process(zip_path)

    assert count == processed == 2
    assert extractor.filter_stats["files_skipped_by_filter"] == 1


def test_zip_publish_failure_deletes_uploaded_objects(zip_path, storage):
    dapr = MagicMock()
    dapr.publish_event.side_effect = RuntimeError("pubsub down")
    extractor = _zip_extractor(storage, dapr)

    processed = extractor.extract_and_process(zip_path)

    assert processed == 0
    assert extractor.filter_stats["files_skipped_by_error"] == 3
    assert sorted(c.args[0] for c in storage.delete_object.call_args_list) == ["obj-1", "obj-2", "obj-3"]
    assert all(not os.path.exists(p) for p, _ in storage.uploaded)


def test_zip_publish_failure_with_delete_failure_is_logged_not_raised(zip_path, storage):
    dapr = MagicMock()
    dapr.publish_event.side_effect = RuntimeError("pubsub down")
    storage.delete_object.side_effect = RuntimeError("s3 down")
    extractor = _zip_extractor(storage, dapr)

    assert extractor.extract_and_process(zip_path) == 0
    assert extractor.filter_stats["files_skipped_by_error"] == 3
    assert all(not os.path.exists(p) for p, _ in storage.uploaded)


def test_zip_upload_failure_removes_temp_file(zip_path, storage):
    temp_paths = []

    def failing_upload(path):
        temp_paths.append(path)
        raise ConnectionError("s3 down")

    storage.upload_file.side_effect = failing_upload
    dapr = MagicMock()
    extractor = _zip_extractor(storage, dapr)

    assert extractor.extract_and_process(zip_path) == 0
    assert len(temp_paths) == 3
    assert all(not os.path.exists(p) for p in temp_paths)
    dapr.publish_event.assert_not_called()
    storage.delete_object.assert_not_called()


def test_bad_zip_raises_extraction_error(tmp_path, storage):
    p = tmp_path / "bad.zip"
    p.write_bytes(b"not a zip")
    extractor = _zip_extractor(storage, MagicMock())
    with pytest.raises(ContainerExtractionError):
        extractor.extract_and_process(p)


# --- LargeContainerProcessor -------------------------------------------------------------


@pytest.fixture
def processor(storage):
    proc = LargeContainerProcessor.__new__(LargeContainerProcessor)
    proc.storage = storage
    proc.progress_tracker = ContainerProgress()
    proc.extractors = {"zip": ZipContainerExtractor}
    proc.postgres_connection_string = "postgresql://unused"
    proc.create_container_record = MagicMock()
    proc.update_container_status = MagicMock()
    proc.update_container_extraction_progress = MagicMock()
    proc.mark_container_failed = MagicMock()
    proc.record_container_error_message = MagicMock()
    return proc


@pytest.fixture
def mock_dapr():
    client = MagicMock()
    client.__enter__.return_value = client
    with patch("web_api.large_containers.DaprClient", return_value=client):
        yield client


def _meta(**kw):
    return {"agent_id": "a", "project": "p", "source": "s", "path": "/mounted-containers/test.zip", **kw}


def test_process_container_success(processor, mock_dapr, zip_path):
    result = processor.process_container_from_path("cid", zip_path, _meta())
    assert result["success"] is True
    assert result["processed_files"] == 3
    assert result["error_message"] is None
    processor.record_container_error_message.assert_not_called()
    processor.mark_container_failed.assert_not_called()


def test_process_container_zero_files_is_not_success(processor, mock_dapr, zip_path):
    result = processor.process_container_from_path(
        "cid", zip_path, _meta(file_filters={"pattern_type": "glob", "include": ["*.nomatch"]})
    )
    assert result["success"] is False
    assert result["processed_files"] == 0
    assert "No files" in result["error_message"]
    processor.record_container_error_message.assert_called_once()


def test_process_container_file_errors_is_not_success(processor, mock_dapr, zip_path, storage):
    storage.upload_file.side_effect = ConnectionError("s3 down")
    result = processor.process_container_from_path("cid", zip_path, _meta())
    assert result["success"] is False
    assert result["files_skipped_by_error"] == 3
    assert result["status"] == ContainerStatus.EXTRACTED


def test_process_container_extraction_error_marks_failed_and_raises(processor, mock_dapr, tmp_path):
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"garbage")
    with pytest.raises(ContainerExtractionError):
        processor.process_container_from_path("cid", bad, _meta())
    processor.mark_container_failed.assert_called_once()
    assert processor.mark_container_failed.call_args.args[0] == "cid"


def test_process_container_bad_metadata_raises_before_record(processor, mock_dapr, zip_path):
    with pytest.raises(ContainerMetadataError):
        processor.process_container_from_path("cid", zip_path, _meta(project={"bad": 1}))
    processor.create_container_record.assert_not_called()
    processor.mark_container_failed.assert_not_called()


# --- create_container_record --------------------------------------------------------------


def _patched_connect():
    cursor = MagicMock()
    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.cursor.return_value.__enter__.return_value = cursor
    return conn, cursor


def test_create_container_record_truncates_long_filename():
    proc = LargeContainerProcessor.__new__(LargeContainerProcessor)
    proc.postgres_connection_string = "postgresql://unused"
    conn, cursor = _patched_connect()
    with patch("web_api.large_containers.psycopg.connect", return_value=conn):
        proc.create_container_record("cid", "zip", {"filename": "f" * 300 + ".zip", "agent_id": "a"}, 1, 1)
    params = cursor.execute.call_args.args[1]
    assert params[2] == "f" * 255


def test_create_container_record_uses_path_basename_when_no_filename():
    proc = LargeContainerProcessor.__new__(LargeContainerProcessor)
    proc.postgres_connection_string = "postgresql://unused"
    conn, cursor = _patched_connect()
    with patch("web_api.large_containers.psycopg.connect", return_value=conn):
        proc.create_container_record("cid", "zip", {"path": "/C:/loot/x.zip"}, 1, 1)
    assert cursor.execute.call_args.args[1][2] == "x.zip"


def test_create_container_record_db_error_raises():
    proc = LargeContainerProcessor.__new__(LargeContainerProcessor)
    proc.postgres_connection_string = "postgresql://unused"
    with (
        patch("web_api.large_containers.psycopg.connect", side_effect=RuntimeError("db down")),
        pytest.raises(RuntimeError),
    ):
        proc.create_container_record("cid", "zip", {"filename": "x.zip"}, 1, 1)


def test_mark_container_failed_sets_status_and_swallows_db_errors():
    proc = LargeContainerProcessor.__new__(LargeContainerProcessor)
    proc.postgres_connection_string = "postgresql://unused"
    conn, cursor = _patched_connect()
    with patch("web_api.large_containers.psycopg.connect", return_value=conn):
        proc.mark_container_failed("cid", "boom")
    params = cursor.execute.call_args.args[1]
    assert params[0] == ContainerStatus.FAILED and params[1] == "boom" and params[3] == "cid"

    with patch("web_api.large_containers.psycopg.connect", side_effect=RuntimeError("db down")):
        proc.mark_container_failed("cid", "boom")  # does not raise

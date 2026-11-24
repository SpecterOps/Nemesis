"""StorageS3 deletion helpers: per-object status, already-absent objects, and the bounded bucket sweep."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from common.storage import StorageS3
from minio.error import S3Error


def s3_error(code: str) -> S3Error:
    return S3Error(MagicMock(), code, "message", "resource", "request-id", "host-id")


@pytest.fixture
def storage():
    # Bypass __init__, which reads credentials from Dapr.
    instance = StorageS3.__new__(StorageS3)
    instance.minio_client = MagicMock()
    instance.bucket_name = "files"
    return instance


def test_delete_object_success(storage):
    assert storage.delete_object("a") is True
    storage.minio_client.remove_object.assert_called_once_with("files", "a")


def test_delete_object_already_absent_counts_as_deleted(storage):
    storage.minio_client.remove_object.side_effect = s3_error("NoSuchKey")
    assert storage.delete_object("a") is True


@pytest.mark.parametrize("error", [s3_error("AccessDenied"), s3_error("NoSuchBucket"), ConnectionError("down")])
def test_delete_object_failure(storage, error):
    storage.minio_client.remove_object.side_effect = error
    assert storage.delete_object("a") is False


def test_delete_objects_with_status_reports_each_object(storage):
    def remove(_bucket, object_id):
        if object_id == "bad":
            raise ConnectionError("down")
        if object_id == "gone":
            raise s3_error("NoSuchKey")

    storage.minio_client.remove_object.side_effect = remove
    assert storage.delete_objects_with_status(["ok", "bad", "gone", "ok"]) == {"ok", "gone"}
    assert storage.minio_client.remove_object.call_count == 3  # duplicates deleted once
    assert storage.delete_objects(["ok", "bad", "gone"]) == 2


def test_delete_objects_modified_before_skips_new_objects(storage):
    cutoff = datetime(2026, 11, 24, 12, tzinfo=UTC)
    storage.minio_client.list_objects.return_value = iter(
        [
            SimpleNamespace(object_name="old", is_dir=False, last_modified=cutoff - timedelta(days=1)),
            SimpleNamespace(object_name="new", is_dir=False, last_modified=cutoff + timedelta(seconds=1)),
            SimpleNamespace(object_name="at-cutoff", is_dir=False, last_modified=cutoff),
            SimpleNamespace(object_name="dir/", is_dir=True, last_modified=None),
            SimpleNamespace(object_name="failing", is_dir=False, last_modified=cutoff - timedelta(hours=1)),
        ]
    )

    def remove(_bucket, object_id):
        if object_id == "failing":
            raise ConnectionError("down")

    storage.minio_client.remove_object.side_effect = remove
    assert storage.delete_objects_modified_before(cutoff) == (1, 1)
    removed = [c.args[1] for c in storage.minio_client.remove_object.call_args_list]
    assert removed == ["old", "failing"]
    storage.minio_client.list_objects.assert_called_once_with("files", recursive=True)

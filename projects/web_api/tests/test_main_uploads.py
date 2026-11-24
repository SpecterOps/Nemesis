"""Tests for /files and /containers upload handling in web_api.main (#11, #166, #167, #172)."""

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
import web_api.main as main
from fastapi import HTTPException

OBJECT_ID = str(uuid.uuid4())


def _metadata(**overrides) -> str:
    data = {"agent_id": "agent123", "project": "proj1", "path": "C:\\Users\\bob\\file.txt"}
    data.update(overrides)
    return json.dumps(data)


@pytest.fixture
def submit_mock(monkeypatch):
    mock = AsyncMock(return_value=uuid.uuid4())
    monkeypatch.setattr(main, "submit_file", mock)
    return mock


@pytest.fixture
def upload_storage(mock_storage):
    mock_storage.upload_uploadfile.return_value = OBJECT_ID
    return mock_storage


def _post_file(client, metadata: str):
    return client.post("/files", files={"file": ("file.txt", b"hello")}, data={"metadata": metadata})


class TestUploadFile:
    def test_happy_path_normalizes_path_and_submits(self, client, upload_storage, submit_mock):
        response = _post_file(client, _metadata())
        assert response.status_code == 200
        assert response.json()["object_id"] == OBJECT_ID
        file_model = submit_mock.await_args.args[0]
        assert file_model.path == "/C:/Users/bob/file.txt"
        assert file_model.expiration > datetime.now(UTC)
        upload_storage.delete_object.assert_not_called()

    def test_validation_error_returns_400_without_uploading(self, client, upload_storage, submit_mock):
        response = _post_file(client, json.dumps({"project": "p", "path": "/x"}))  # agent_id missing
        assert response.status_code == 400
        assert any("agent_id" in err["loc"] for err in response.json()["detail"])
        upload_storage.upload_uploadfile.assert_not_called()
        submit_mock.assert_not_called()

    def test_invalid_json_returns_400(self, client, upload_storage, submit_mock):
        response = _post_file(client, "{not json")
        assert response.status_code == 400
        upload_storage.upload_uploadfile.assert_not_called()

    def test_non_object_json_returns_400(self, client, upload_storage, submit_mock):
        response = _post_file(client, "[1, 2]")
        assert response.status_code == 400

    def test_past_expiration_rejected(self, client, upload_storage, submit_mock):
        past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
        response = _post_file(client, _metadata(expiration=past))
        assert response.status_code == 400
        assert "expiration" in response.json()["detail"]
        upload_storage.upload_uploadfile.assert_not_called()

    def test_naive_past_expiration_rejected(self, client, upload_storage, submit_mock):
        response = _post_file(client, _metadata(expiration="2001-01-01T00:00:00"))
        assert response.status_code == 400

    def test_future_expiration_accepted(self, client, upload_storage, submit_mock):
        future = (datetime.now(UTC) + timedelta(days=5)).isoformat()
        response = _post_file(client, _metadata(expiration=future))
        assert response.status_code == 200

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("project", "p" * 256),
            ("agent_id", "a" * 256),
            ("source", "s" * 1001),
            ("path", "/dir/" + "f" * 256),
        ],
    )
    def test_metadata_too_long_rejected(self, client, upload_storage, submit_mock, field, value):
        response = _post_file(client, _metadata(**{field: value}))
        assert response.status_code == 400
        detail = str(response.json()["detail"])
        assert "too long" in detail or "at most 255 characters" in detail
        upload_storage.upload_uploadfile.assert_not_called()

    def test_metadata_at_limit_accepted(self, client, upload_storage, submit_mock):
        response = _post_file(client, _metadata(project="p" * 255, agent_id="a" * 255, path="/d/" + "f" * 255))
        assert response.status_code == 200

    def test_publish_failure_deletes_uploaded_object(self, client, upload_storage, submit_mock):
        submit_mock.side_effect = RuntimeError("pubsub down")
        response = _post_file(client, _metadata())
        assert response.status_code == 500
        upload_storage.delete_object.assert_called_once_with(OBJECT_ID)

    def test_submit_http_error_deletes_object_and_keeps_status(self, client, upload_storage, submit_mock):
        submit_mock.side_effect = HTTPException(status_code=400, detail="missing")
        response = _post_file(client, _metadata())
        assert response.status_code == 400
        upload_storage.delete_object.assert_called_once_with(OBJECT_ID)

    def test_orphan_delete_failure_does_not_mask_error(self, client, upload_storage, submit_mock):
        submit_mock.side_effect = RuntimeError("pubsub down")
        upload_storage.delete_object.side_effect = RuntimeError("s3 down")
        response = _post_file(client, _metadata())
        assert response.status_code == 500
        assert "pubsub down" in response.json()["detail"]


class TestSubmitFile:
    def test_missing_object_returns_400(self, mock_storage):
        import asyncio

        from common.models import File as FileModel

        mock_storage.check_file_exists.return_value = False
        file_model = FileModel(
            object_id=OBJECT_ID,
            agent_id="a",
            project="p",
            timestamp=datetime.now(UTC),
            expiration=datetime.now(UTC) + timedelta(days=1),
            path="/x",
        )
        with pytest.raises(HTTPException) as exc:
            asyncio.run(main.submit_file(file_model))
        assert exc.value.status_code == 400


@pytest.fixture
def temp_container_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("TEMP_CONTAINER_PATH", str(tmp_path))
    return tmp_path


def _post_container(client, filename="../../evil.zip", metadata=None):
    return client.post(
        "/containers",
        files={"file": (filename, b"PK\x03\x04data")},
        data={"metadata": metadata or _metadata(path="C:\\Users\\bob\\evil.zip")},
    )


class TestSubmitContainer:
    def test_temp_path_ignores_client_filename_and_path_is_normalized(self, client, temp_container_dir, monkeypatch):
        seen = {}

        def fake_process(container_id, file_path: Path, metadata):
            seen["path"] = file_path
            seen["exists"] = file_path.exists()
            seen["content"] = file_path.read_bytes()
            seen["metadata"] = metadata
            seen["container_id"] = container_id
            return {"estimated_files": 1, "estimated_size": 10}

        monkeypatch.setattr(main.container_processor, "process_container_from_path", fake_process)
        response = _post_container(client)
        assert response.status_code == 200
        assert seen["path"] == temp_container_dir / f"{seen['container_id']}.bin"
        assert seen["exists"] and seen["content"] == b"PK\x03\x04data"
        assert seen["metadata"]["filename"] == "evil.zip" or seen["metadata"]["filename"].endswith("evil.zip")
        assert seen["metadata"]["path"] == "/C:/Users/bob/evil.zip"
        # temp file cleaned up
        assert list(temp_container_dir.iterdir()) == []

    def test_partial_temp_file_removed_when_copy_fails(self, client, temp_container_dir, monkeypatch):
        def failing_copy(file, dest_path):
            with open(dest_path, "wb") as f:
                f.write(b"partial")
            raise OSError("disk full")

        process = AsyncMock()
        monkeypatch.setattr(main, "_copy_upload_to_path", failing_copy)
        monkeypatch.setattr(main.container_processor, "process_container_from_path", process)
        response = _post_container(client)
        assert response.status_code == 500
        assert list(temp_container_dir.iterdir()) == []
        process.assert_not_called()

    def test_temp_file_removed_when_processing_fails(self, client, temp_container_dir, monkeypatch):
        def boom(*args):
            raise RuntimeError("extract failed")

        monkeypatch.setattr(main.container_processor, "process_container_from_path", boom)
        response = _post_container(client)
        assert response.status_code == 500
        assert list(temp_container_dir.iterdir()) == []

    def test_progress_cleaned_up_after_extraction(self, client, temp_container_dir, monkeypatch):
        tracker = main.container_processor.progress_tracker

        def fake_process(container_id, file_path, metadata):
            tracker.initialize(container_id, 1, 1)
            fake_process.cid = container_id
            return {"estimated_files": 1, "estimated_size": 1}

        monkeypatch.setattr(main.container_processor, "process_container_from_path", fake_process)
        assert _post_container(client).status_code == 200
        assert tracker.get_progress(fake_process.cid) is None

    def test_long_filename_rejected(self, client, temp_container_dir, monkeypatch):
        process = AsyncMock()
        monkeypatch.setattr(main.container_processor, "process_container_from_path", process)
        response = _post_container(client, filename="a" * 300 + ".zip")
        assert response.status_code == 400
        process.assert_not_called()

    def test_past_expiration_rejected(self, client, temp_container_dir, monkeypatch):
        process = AsyncMock()
        monkeypatch.setattr(main.container_processor, "process_container_from_path", process)
        response = _post_container(client, metadata=_metadata(expiration="2001-01-01T00:00:00Z"))
        assert response.status_code == 400
        process.assert_not_called()

    def test_validation_error_returns_400(self, client, temp_container_dir):
        response = _post_container(client, metadata=json.dumps({"path": "/x"}))
        assert response.status_code == 400


class TestContainerProgressEviction:
    def test_evicts_only_stale_entries(self):
        tracker = main.container_processor.progress_tracker
        tracker.initialize("old", 1, 1)
        tracker.initialize("new", 1, 1)
        tracker.get_progress("old")["started_at"] = datetime.now() - timedelta(days=8)
        try:
            assert main._evict_stale_container_progress() == 1
            assert tracker.get_progress("old") is None
            assert tracker.get_progress("new") is not None
        finally:
            tracker.cleanup("old")
            tracker.cleanup("new")

    def test_status_poll_cleans_up_finished_container(self, client, monkeypatch):
        tracker = main.container_processor.progress_tracker
        tracker.initialize("c1", 1, 1)
        status = {
            "status": "workflows_complete",
            "workflows_total": 1,
            "workflows_completed": 1,
            "workflows_failed": 0,
            "total_bytes_extracted": 1,
            "total_bytes_processed": 1,
            "processing_started_at": None,
        }
        monkeypatch.setattr(main.container_processor, "get_container_status", lambda cid: status)
        response = client.get("/containers/c1/status")
        assert response.status_code == 200
        assert response.json()["progress_percent_files"] == 100
        assert tracker.get_progress("c1") is None

    def test_status_poll_keeps_extracting_container(self, client, monkeypatch):
        tracker = main.container_processor.progress_tracker
        tracker.initialize("c2", 2, 2)
        tracker.update_file_progress("c2", "a.txt", 1)
        status = {
            "status": "extracting",
            "workflows_total": 0,
            "workflows_completed": 0,
            "workflows_failed": 0,
            "total_bytes_extracted": 0,
            "total_bytes_processed": 0,
            "processing_started_at": None,
        }
        monkeypatch.setattr(main.container_processor, "get_container_status", lambda cid: status)
        try:
            response = client.get("/containers/c2/status")
            assert response.json()["current_file"] == "a.txt"
            assert tracker.get_progress("c2") is not None
        finally:
            tracker.cleanup("c2")

    def test_status_unknown_container_404(self, client, monkeypatch):
        monkeypatch.setattr(main.container_processor, "get_container_status", lambda cid: None)
        assert client.get("/containers/nope/status").status_code == 404


class TestSubmitContainerErrorMapping:
    def test_metadata_error_returns_400(self, client, temp_container_dir, monkeypatch):
        def bad_metadata(*args):
            raise main.ContainerMetadataError("Container metadata field 'project' is required")

        monkeypatch.setattr(main.container_processor, "process_container_from_path", bad_metadata)
        response = _post_container(client)
        assert response.status_code == 400
        assert "project" in response.json()["detail"]
        assert list(temp_container_dir.iterdir()) == []

    def test_extraction_error_returns_422(self, client, temp_container_dir, monkeypatch):
        def unreadable(*args):
            raise main.ContainerExtractionError("Could not read ZIP file: bad header")

        monkeypatch.setattr(main.container_processor, "process_container_from_path", unreadable)
        response = _post_container(client)
        assert response.status_code == 422
        assert "Could not read ZIP file" in response.json()["detail"]
        assert list(temp_container_dir.iterdir()) == []

    def test_partial_extraction_reported(self, client, temp_container_dir, monkeypatch):
        monkeypatch.setattr(
            main.container_processor,
            "process_container_from_path",
            lambda *a: {
                "estimated_files": 3,
                "estimated_size": 30,
                "success": False,
                "error_message": "2 file(s)/filesystem(s) failed to extract",
            },
        )
        response = _post_container(client)
        assert response.status_code == 200
        body = response.json()
        assert body["success"] is False
        assert body["error_message"] == "2 file(s)/filesystem(s) failed to extract"
        assert "failed or was partial" in body["message"]
        assert body["estimated_files"] == 3 and body["estimated_size"] == 30

    def test_successful_extraction_keeps_original_shape(self, client, temp_container_dir, monkeypatch):
        monkeypatch.setattr(
            main.container_processor,
            "process_container_from_path",
            lambda *a: {"estimated_files": 1, "estimated_size": 1, "success": True, "error_message": None},
        )
        body = _post_container(client).json()
        assert body["message"] == "Files extracted from container and processing initiated"
        assert body["success"] is True and body["error_message"] is None
        assert {"container_id", "estimated_files", "estimated_size", "filter_config"} <= body.keys()

    def test_uri_path_left_unchanged(self, client, temp_container_dir, monkeypatch):
        seen = {}

        def fake_process(cid, path, metadata):
            seen.update(metadata)
            return {"estimated_files": 0, "estimated_size": 0}

        monkeypatch.setattr(main.container_processor, "process_container_from_path", fake_process)
        assert _post_container(client, metadata=_metadata(path="smb://host/share/a.zip")).status_code == 200
        assert seen["path"] == "smb://host/share/a.zip"

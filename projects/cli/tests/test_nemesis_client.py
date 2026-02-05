"""Tests for cli.nemesis_client module - NemesisClient init, metadata creation, file upload."""

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from cli.config import NemesisConfig, PasswordCredential, StrictHttpUrl
from cli.nemesis_client import NemesisClient


def _make_config() -> NemesisConfig:
    return NemesisConfig(
        url=StrictHttpUrl("https://nemesis.local:8080"),
        credential=PasswordCredential(username="testuser", password="testpass"),
    )


class TestNemesisClientInit:
    def test_init(self):
        cfg = _make_config()
        client = NemesisClient(cfg)
        assert client.cfg is cfg
        assert client.auth is not None
        assert client.auth.username == "testuser"
        assert client.auth.password == "testpass"


class TestCreateFileMetadata:
    def test_creates_metadata(self):
        client = NemesisClient(_make_config())
        meta = client.create_file_metadata(
            path="/path/to/file.txt",
            agent_id="agent-1",
            project="project-1",
        )
        assert meta.agent_id == "agent-1"
        assert meta.project == "project-1"
        assert meta.path == "/path/to/file.txt"
        assert meta.source is None
        assert isinstance(meta.timestamp, datetime)
        assert isinstance(meta.expiration, datetime)
        assert meta.expiration.year > meta.timestamp.year

    def test_creates_metadata_with_source(self):
        client = NemesisClient(_make_config())
        meta = client.create_file_metadata(
            path="/file.txt",
            agent_id="a",
            project="p",
            source="host://10.0.0.1",
        )
        assert meta.source == "host://10.0.0.1"


class TestPostFile:
    def test_no_metadata_raises(self):
        client = NemesisClient(_make_config())
        with pytest.raises(ValueError, match="metadata is required"):
            client.post_file("/tmp/test.txt", None)

    def test_file_not_found(self):
        client = NemesisClient(_make_config())
        meta = client.create_file_metadata("/nonexistent", "a", "p")
        result = client.post_file("/nonexistent/file.txt", meta)
        assert hasattr(result, "detail")
        assert "not found" in result.detail.lower() or "No such file" in result.detail

    def test_successful_upload(self, tmp_path):
        """Test successful file upload with mocked requests."""
        client = NemesisClient(_make_config())
        meta = client.create_file_metadata("/path/to/file.txt", "a", "p")

        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "object_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "submission_id": "f0e1d2c3-b4a5-6789-0abc-def123456789",
        }

        with patch("cli.nemesis_client.requests.post", return_value=mock_response):
            result = client.post_file(str(test_file), meta)
        assert str(result.object_id) == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

    def test_upload_server_error(self, tmp_path):
        """Server returning non-200 should produce ErrorResponse."""
        client = NemesisClient(_make_config())
        meta = client.create_file_metadata("/file.txt", "a", "p")

        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        mock_response = MagicMock()
        mock_response.status_code = 500

        with patch("cli.nemesis_client.requests.post", return_value=mock_response):
            result = client.post_file(str(test_file), meta)
        assert hasattr(result, "detail")
        assert "500" in result.detail

    def test_upload_with_binary_stream(self, tmp_path):
        """Test upload with a file-like object (BinaryIO)."""
        client = NemesisClient(_make_config())
        meta = client.create_file_metadata("/file.txt", "a", "p")

        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "object_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
            "submission_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
        }

        with (
            open(test_file, "rb") as f,
            patch("cli.nemesis_client.requests.post", return_value=mock_response),
        ):
            result = client.post_file(f, meta)
        assert str(result.object_id) == "b2c3d4e5-f6a7-8901-bcde-f12345678901"

    def test_upload_permission_denied(self, tmp_path):
        """Files without read permission should return ErrorResponse."""
        import os

        client = NemesisClient(_make_config())
        meta = client.create_file_metadata("/file.txt", "a", "p")

        test_file = tmp_path / "noperm.txt"
        test_file.write_text("secret")
        os.chmod(test_file, 0o000)

        try:
            result = client.post_file(str(test_file), meta)
            assert hasattr(result, "detail")
        finally:
            os.chmod(test_file, 0o644)


class TestGetHealth:
    def test_success(self):
        client = NemesisClient(_make_config())
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "healthy"}

        with patch("cli.nemesis_client.requests.get", return_value=mock_response):
            result = client.get_health()
        assert result is not None

    def test_server_error(self):
        client = NemesisClient(_make_config())
        mock_response = MagicMock()
        mock_response.status_code = 503

        with patch("cli.nemesis_client.requests.get", return_value=mock_response):
            result = client.get_health()
        assert hasattr(result, "detail")

    def test_connection_error_returns_none(self):
        client = NemesisClient(_make_config())

        with patch("cli.nemesis_client.requests.get", side_effect=Exception("Connection refused")):
            result = client.get_health()
        assert result is None


class TestGetApiInfo:
    def test_success(self):
        client = NemesisClient(_make_config())
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"version": "2.0.0", "name": "Nemesis"}

        with patch("cli.nemesis_client.requests.get", return_value=mock_response):
            result = client.get_api_info()
        assert result is not None

    def test_connection_error_returns_none(self):
        client = NemesisClient(_make_config())

        with patch("cli.nemesis_client.requests.get", side_effect=Exception("timeout")):
            result = client.get_api_info()
        assert result is None


class TestReloadYaraRules:
    def test_success(self):
        client = NemesisClient(_make_config())
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"message": "Yara rules reloaded successfully"}

        with patch("cli.nemesis_client.requests.post", return_value=mock_response):
            result = client.reload_yara_rules()
        assert result is not None
        assert result.message == "Yara rules reloaded successfully"

    def test_connection_error_returns_none(self):
        client = NemesisClient(_make_config())

        with patch("cli.nemesis_client.requests.post", side_effect=Exception("fail")):
            result = client.reload_yara_rules()
        assert result is None

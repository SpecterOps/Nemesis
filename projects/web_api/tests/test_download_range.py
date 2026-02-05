"""Tests for the download endpoint's range request (offset/length) support."""

from unittest.mock import MagicMock


class TestDownloadNoRangeParams:
    """When no offset/length params are given, backward-compatible streaming behavior."""

    def test_returns_streaming_response(self, client, mock_storage):
        response = client.get("/files/test-object-id")
        assert response.status_code == 200
        mock_storage.download_stream.assert_called_once_with("test-object-id")
        mock_storage.download_bytes.assert_not_called()


class TestDownloadWithLength:
    """When length is specified, uses download_bytes and returns Response."""

    def test_returns_range_with_content_length(self, client, mock_storage):
        mock_storage.download_bytes.return_value = b"\xde\xad" * 50
        response = client.get("/files/test-object-id?length=1048576")
        assert response.status_code == 200
        mock_storage.download_bytes.assert_called_once_with("test-object-id", 0, 1048576)
        assert response.headers["content-length"] == str(100)  # len(b"\xde\xad" * 50)
        assert response.content == b"\xde\xad" * 50

    def test_returns_octet_stream_content_type(self, client, mock_storage):
        response = client.get("/files/test-object-id?length=100")
        assert response.headers["content-type"] == "application/octet-stream"


class TestDownloadWithOffsetAndLength:
    """When both offset and length are specified."""

    def test_correct_range_passed_to_storage(self, client, mock_storage):
        mock_storage.download_bytes.return_value = b"partial-data"
        response = client.get("/files/test-object-id?offset=100&length=50")
        assert response.status_code == 200
        mock_storage.download_bytes.assert_called_once_with("test-object-id", 100, 50)
        assert response.content == b"partial-data"


class TestDownloadOffsetBeyondFileSize:
    """When offset is at or beyond the file size."""

    def test_returns_400(self, client, mock_storage):
        # File is 10MB, offset is 10MB (= size, so beyond valid range)
        response = client.get(f"/files/test-object-id?offset={10 * 1024 * 1024}")
        assert response.status_code == 400
        assert "beyond file size" in response.json()["detail"].lower()


class TestDownloadLargeFileSmallRange:
    """A large file with a small range request should bypass the full-size limit."""

    def test_serves_range_for_large_file(self, client, mock_storage):
        # Make file larger than DOWNLOAD_SIZE_LIMIT_MB (500MB)
        stats = MagicMock()
        stats.size = 600 * 1024 * 1024  # 600MB
        mock_storage.get_object_stats.return_value = stats
        mock_storage.download_bytes.return_value = b"x" * 1024

        response = client.get("/files/test-object-id?length=1048576")
        assert response.status_code == 200
        mock_storage.download_bytes.assert_called_once()


class TestDownloadFileNotFound:
    """When the file doesn't exist."""

    def test_returns_404(self, client, mock_storage):
        mock_storage.check_file_exists.return_value = False
        response = client.get("/files/nonexistent-id")
        assert response.status_code == 404


class TestDownloadRawWithLength:
    """When raw=True and length are both specified."""

    def test_returns_text_plain_content_type(self, client, mock_storage):
        mock_storage.download_bytes.return_value = b"raw text data"
        response = client.get("/files/test-object-id?raw=True&length=100")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")

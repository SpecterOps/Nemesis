"""Tests for the test harness infrastructure itself."""

import os
import tempfile

import pytest

from .factories import FileEnrichedFactory
from .harness import ModuleTestHarness
from .mock_pool import MockAsyncpgPool, MockRecord
from .mock_storage import MockStorageMinio


class TestMockStorageMinio:
    """Tests for MockStorageMinio."""

    def test_register_and_download_file(self):
        """Test registering a file and downloading it."""
        storage = MockStorageMinio()

        # Create a temp file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test content")
            temp_path = f.name

        try:
            storage.register_file("test-uuid", temp_path)

            with storage.download("test-uuid") as downloaded:
                with open(downloaded.name, "rb") as content_file:
                    content = content_file.read()
                assert content == b"test content"
        finally:
            os.unlink(temp_path)

    def test_download_bytes(self):
        """Test downloading raw bytes."""
        storage = MockStorageMinio()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"0123456789")
            temp_path = f.name

        try:
            storage.register_file("test-uuid", temp_path)

            # Full file
            assert storage.download_bytes("test-uuid") == b"0123456789"

            # With offset
            assert storage.download_bytes("test-uuid", offset=5) == b"56789"

            # With length
            assert storage.download_bytes("test-uuid", length=5) == b"01234"

            # With offset and length
            assert storage.download_bytes("test-uuid", offset=2, length=3) == b"234"
        finally:
            os.unlink(temp_path)

    def test_upload_bytes(self):
        """Test uploading raw bytes."""
        storage = MockStorageMinio()

        file_uuid = storage.upload(b"uploaded content")

        # Should be able to download it back
        assert storage.download_bytes(str(file_uuid)) == b"uploaded content"

    def test_upload_file(self):
        """Test uploading a file by path."""
        storage = MockStorageMinio()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"file content")
            temp_path = f.name

        try:
            file_uuid = storage.upload_file(temp_path)

            # Should be able to download it back
            assert storage.download_bytes(str(file_uuid)) == b"file content"
        finally:
            os.unlink(temp_path)

    def test_check_file_exists(self):
        """Test checking if a file exists."""
        storage = MockStorageMinio()

        assert not storage.check_file_exists("nonexistent")

        storage._uploaded_files["exists"] = b"data"
        assert storage.check_file_exists("exists")

    def test_file_not_found_raises(self):
        """Test that downloading non-existent file raises."""
        storage = MockStorageMinio()

        with pytest.raises(FileNotFoundError):
            storage.download("nonexistent")

        with pytest.raises(FileNotFoundError):
            storage.download_bytes("nonexistent")


class TestMockAsyncpgPool:
    """Tests for MockAsyncpgPool."""

    @pytest.mark.asyncio
    async def test_register_and_fetchrow(self):
        """Test registering data and fetching it."""
        pool = MockAsyncpgPool()

        pool.register_file_enriched(
            "test-uuid",
            {
                "file_name": "test.exe",
                "size": 1024,
            },
        )

        row = await pool.fetchrow("SELECT * FROM files_enriched WHERE object_id = $1", "test-uuid")

        assert row is not None
        assert row["file_name"] == "test.exe"
        assert row["size"] == 1024
        # Should have default values for required fields
        assert row["object_id"] == "test-uuid"
        assert row["agent_id"] == "test-agent"

    @pytest.mark.asyncio
    async def test_fetchrow_returns_none_for_unknown(self):
        """Test that fetchrow returns None for unknown IDs."""
        pool = MockAsyncpgPool()

        row = await pool.fetchrow("SELECT * FROM files_enriched WHERE object_id = $1", "unknown-uuid")

        assert row is None

    @pytest.mark.asyncio
    async def test_execute_log(self):
        """Test that queries are logged."""
        pool = MockAsyncpgPool()

        await pool.execute("INSERT INTO test VALUES ($1)", "value")
        await pool.fetchrow("SELECT * FROM test WHERE id = $1", "id")

        log = pool.get_execute_log()
        assert len(log) == 2
        assert log[0] == ("INSERT INTO test VALUES ($1)", ("value",))
        assert log[1] == ("SELECT * FROM test WHERE id = $1", ("id",))

    def test_mock_record_attribute_access(self):
        """Test that MockRecord supports attribute access."""
        record = MockRecord({"name": "test", "value": 42})

        assert record["name"] == "test"
        assert record.name == "test"
        assert record["value"] == 42
        assert record.value == 42

        with pytest.raises(AttributeError):
            _ = record.nonexistent


class TestFileEnrichedFactory:
    """Tests for FileEnrichedFactory."""

    def test_create_basic(self):
        """Test creating basic file_enriched data."""
        data = FileEnrichedFactory.create(
            object_id="test-id",
            file_name="test.bin",
            size=1024,
        )

        assert data["object_id"] == "test-id"
        assert data["file_name"] == "test.bin"
        assert data["size"] == 1024
        assert data["agent_id"] == "test-agent"
        assert data["hashes"] is not None

    def test_create_pe_file(self):
        """Test creating PE file data."""
        data = FileEnrichedFactory.create_pe_file(
            file_name="malware.exe",
            is_64bit=True,
        )

        assert data["file_name"] == "malware.exe"
        assert "PE32+" in data["magic_type"]
        assert data["mime_type"] == "application/x-dosexec"

    def test_create_plaintext_file(self):
        """Test creating plaintext file data."""
        data = FileEnrichedFactory.create_plaintext_file(
            file_name=".git-credentials",
        )

        assert data["file_name"] == ".git-credentials"
        assert data["is_plaintext"] is True
        assert data["mime_type"] == "text/plain"

    def test_create_container_file(self):
        """Test creating container file data."""
        data = FileEnrichedFactory.create_zip_file(
            file_name="archive.zip",
        )

        assert data["file_name"] == "archive.zip"
        assert data["is_container"] is True
        assert data["mime_type"] == "application/zip"

    def test_create_extracted_file(self):
        """Test creating extracted file data."""
        data = FileEnrichedFactory.create_extracted_file(
            file_name="inner.exe",
            originating_object_id="parent-uuid",
            nesting_level=2,
        )

        assert data["file_name"] == "inner.exe"
        assert data["originating_object_id"] == "parent-uuid"
        assert data["nesting_level"] == 2


class TestModuleTestHarness:
    """Tests for ModuleTestHarness."""

    def test_register_file(self):
        """Test registering a file with the harness."""
        harness = ModuleTestHarness()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test data")
            temp_path = f.name

        try:
            harness.register_file(
                object_id="test-uuid",
                local_path=temp_path,
                file_enriched=FileEnrichedFactory.create_pe_file(object_id="test-uuid"),
            )

            # Should be registered in storage
            assert harness.storage.check_file_exists("test-uuid")

            # Should be registered in pool
            assert "test-uuid" in harness.pool._file_enriched_data
        finally:
            os.unlink(temp_path)

    def test_register_file_auto_metadata(self):
        """Test that harness auto-creates metadata if not provided."""
        harness = ModuleTestHarness()

        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test data")
            temp_path = f.name

        try:
            harness.register_file(
                object_id="test-uuid",
                local_path=temp_path,
            )

            # Should have auto-generated metadata
            data = harness.pool._file_enriched_data["test-uuid"]
            assert data["file_name"] == os.path.basename(temp_path)
            assert data["size"] == len(b"test data")
        finally:
            os.unlink(temp_path)

    def test_register_file_bytes(self):
        """Test registering raw bytes with the harness."""
        harness = ModuleTestHarness()

        harness.register_file_bytes(
            object_id="test-uuid",
            data=b"binary data",
            file_enriched=FileEnrichedFactory.create(file_name="test.bin"),
        )

        # Should be accessible
        assert harness.storage.download_bytes("test-uuid") == b"binary data"
        assert "test-uuid" in harness.pool._file_enriched_data

    def test_clear(self):
        """Test clearing the harness."""
        harness = ModuleTestHarness()

        harness.register_file_bytes(
            object_id="test-uuid",
            data=b"data",
            file_enriched=FileEnrichedFactory.create(),
        )

        harness.clear()

        assert not harness.storage.check_file_exists("test-uuid")
        assert "test-uuid" not in harness.pool._file_enriched_data

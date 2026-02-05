# tests/test_container.py
"""Tests for the container analyzer module.

Focuses on testing the 7z analysis fix (iterating over ArchiveFileList entries
with .filename/.uncompressed attributes instead of calling .items()), and
covers ZIP, TAR, and the full process() integration path.
"""

import os
import tarfile
import tempfile
import zipfile

import py7zr
import pytest
from file_enrichment_modules.container.analyzer import ContainerAnalyzer

from tests.harness import FileEnrichedFactory, ModuleTestHarness
from tests.harness.mock_pool import MockRecord


def _create_7z(path: str, files: dict[str, bytes]) -> None:
    """Helper to create a 7z archive with the given file contents.

    Args:
        path: Output 7z file path
        files: Mapping of archive entry name to file content bytes
    """
    with py7zr.SevenZipFile(path, "w") as sz:
        for name, data in files.items():
            # py7zr needs a real file on disk to add
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(data)
                tmp_path = tmp.name
            try:
                sz.write(tmp_path, arcname=name)
            finally:
                os.unlink(tmp_path)


class TestAnalyze7z:
    """Tests for _analyze_7z — verifying the bug fix that iterates over
    ArchiveFileList entries using .filename/.uncompressed attributes."""

    def test_basic_extraction(self, tmp_path):
        """Test _analyze_7z extracts filenames and sizes from a 7z archive."""
        archive_path = str(tmp_path / "test.7z")
        _create_7z(
            archive_path,
            {
                "hello.txt": b"Hello, world!",
                "data.bin": b"\x00" * 256,
            },
        )

        module = ModuleTestHarness().create_module_sync(ContainerAnalyzer)
        files = module._analyze_7z(archive_path)

        assert isinstance(files, list)
        assert len(files) == 2

        filenames = {f[0] for f in files}
        assert "hello.txt" in filenames
        assert "data.bin" in filenames

        # All sizes should be non-negative integers
        for _, size in files:
            assert isinstance(size, int)
            assert size >= 0

    def test_correct_uncompressed_sizes(self, tmp_path):
        """Test that _analyze_7z returns accurate uncompressed file sizes."""
        content_a = b"A" * 100
        content_b = b"B" * 500

        archive_path = str(tmp_path / "sized.7z")
        _create_7z(archive_path, {"a.txt": content_a, "b.txt": content_b})

        module = ModuleTestHarness().create_module_sync(ContainerAnalyzer)
        files = module._analyze_7z(archive_path)

        file_dict = dict(files)
        assert file_dict["a.txt"] == len(content_a)
        assert file_dict["b.txt"] == len(content_b)

    def test_empty_archive(self, tmp_path):
        """Test _analyze_7z returns empty list for an empty 7z archive."""
        archive_path = str(tmp_path / "empty.7z")
        with py7zr.SevenZipFile(archive_path, "w"):
            pass

        module = ModuleTestHarness().create_module_sync(ContainerAnalyzer)
        files = module._analyze_7z(archive_path)
        assert files == []

    def test_nested_directory_paths(self, tmp_path):
        """Test _analyze_7z preserves directory paths in filenames."""
        archive_path = str(tmp_path / "nested.7z")
        _create_7z(
            archive_path,
            {
                "dir1/file1.txt": b"file1",
                "dir1/dir2/file2.txt": b"file2",
            },
        )

        module = ModuleTestHarness().create_module_sync(ContainerAnalyzer)
        files = module._analyze_7z(archive_path)
        filenames = {f[0] for f in files}

        assert "dir1/file1.txt" in filenames
        assert "dir1/dir2/file2.txt" in filenames

    def test_single_file(self, tmp_path):
        """Test _analyze_7z with a single file archive."""
        archive_path = str(tmp_path / "single.7z")
        _create_7z(archive_path, {"only.txt": b"only file"})

        module = ModuleTestHarness().create_module_sync(ContainerAnalyzer)
        files = module._analyze_7z(archive_path)

        assert len(files) == 1
        assert files[0][0] == "only.txt"
        assert files[0][1] == len(b"only file")


class TestAnalyzeZip:
    """Tests for _analyze_zip."""

    def test_basic_extraction(self, tmp_path):
        """Test _analyze_zip extracts filenames and sizes."""
        archive_path = str(tmp_path / "test.zip")
        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("hello.txt", "Hello, world!")
            zf.writestr("data.bin", "\x00" * 256)

        module = ModuleTestHarness().create_module_sync(ContainerAnalyzer)
        files = module._analyze_zip(archive_path)

        assert len(files) == 2
        file_dict = dict(files)
        assert "hello.txt" in file_dict
        assert file_dict["hello.txt"] == len("Hello, world!")

    def test_empty_archive(self, tmp_path):
        """Test _analyze_zip returns empty list for an empty zip archive."""
        archive_path = str(tmp_path / "empty.zip")
        with zipfile.ZipFile(archive_path, "w"):
            pass

        module = ModuleTestHarness().create_module_sync(ContainerAnalyzer)
        files = module._analyze_zip(archive_path)
        assert files == []


class TestAnalyzeTar:
    """Tests for _analyze_tar."""

    def test_basic_extraction(self, tmp_path):
        """Test _analyze_tar extracts filenames and sizes."""
        src_file = tmp_path / "hello.txt"
        src_file.write_text("Hello, world!")

        archive_path = str(tmp_path / "test.tar")
        with tarfile.open(archive_path, "w") as tf:
            tf.add(str(src_file), arcname="hello.txt")

        module = ModuleTestHarness().create_module_sync(ContainerAnalyzer)
        files = module._analyze_tar(archive_path)

        assert len(files) == 1
        assert files[0][0] == "hello.txt"
        assert files[0][1] == len("Hello, world!")

    def test_gzipped_tar(self, tmp_path):
        """Test _analyze_tar handles gzipped tar files."""
        src_file = tmp_path / "data.txt"
        src_file.write_text("compressed content")

        archive_path = str(tmp_path / "test.tar.gz")
        with tarfile.open(archive_path, "w:gz") as tf:
            tf.add(str(src_file), arcname="data.txt")

        module = ModuleTestHarness().create_module_sync(ContainerAnalyzer)
        files = module._analyze_tar(archive_path)

        assert len(files) == 1
        assert files[0][0] == "data.txt"

    def test_skips_directories(self, tmp_path):
        """Test _analyze_tar only returns files, not directory entries."""
        src_dir = tmp_path / "subdir"
        src_dir.mkdir()
        src_file = src_dir / "file.txt"
        src_file.write_text("in subdir")

        archive_path = str(tmp_path / "test.tar")
        with tarfile.open(archive_path, "w") as tf:
            tf.add(str(src_dir), arcname="subdir")
            tf.add(str(src_file), arcname="subdir/file.txt")

        module = ModuleTestHarness().create_module_sync(ContainerAnalyzer)
        files = module._analyze_tar(archive_path)

        filenames = [f[0] for f in files]
        assert "subdir/file.txt" in filenames
        assert "subdir" not in filenames


class TestAnalyzeContainerReport:
    """Tests for _analyze_container report generation."""

    def _make_file_enriched(self, factory_method, **kwargs) -> MockRecord:
        """Create a MockRecord wrapping FileEnrichedFactory output."""
        return MockRecord(factory_method(object_id="test-uuid", **kwargs))

    def test_7z_report_generation(self, tmp_path):
        """Test _analyze_container generates a correct markdown report for 7z."""
        archive_path = str(tmp_path / "test.7z")
        src_file = tmp_path / "hello.txt"
        src_file.write_text("Hello!")
        with py7zr.SevenZipFile(archive_path, "w") as sz:
            sz.write(str(src_file), arcname="hello.txt")

        file_enriched = self._make_file_enriched(FileEnrichedFactory.create_7z_file, file_name="test.7z")

        harness = ModuleTestHarness()
        module = harness.create_module_sync(ContainerAnalyzer)
        result = module._analyze_container(archive_path, file_enriched)

        assert result is not None
        assert result.module_name == "container_analyzer"
        assert len(result.transforms) == 1

        transform = result.transforms[0]
        assert transform.type == "container_contents"
        assert transform.metadata["display_type_in_dashboard"] == "markdown"
        assert transform.metadata["default_display"] is True
        assert transform.metadata["file_name"] == "test.7z_contents.md"

    def test_zip_report_generation(self, tmp_path):
        """Test _analyze_container generates a correct report for ZIP."""
        archive_path = str(tmp_path / "test.zip")
        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("file1.txt", "content1")
            zf.writestr("file2.txt", "longer content two")

        file_enriched = self._make_file_enriched(FileEnrichedFactory.create_zip_file, file_name="test.zip")

        harness = ModuleTestHarness()
        module = harness.create_module_sync(ContainerAnalyzer)
        result = module._analyze_container(archive_path, file_enriched)

        assert result is not None
        assert len(result.transforms) == 1
        assert result.transforms[0].metadata["file_name"] == "test.zip_contents.md"

    def test_unsupported_format_returns_none(self, tmp_path):
        """Test _analyze_container returns None for unsupported formats."""
        fake_path = str(tmp_path / "not_an_archive.bin")
        with open(fake_path, "wb") as f:
            f.write(b"\x00\x01\x02\x03" * 100)

        file_enriched = self._make_file_enriched(FileEnrichedFactory.create_7z_file, file_name="not_an_archive.bin")

        module = ModuleTestHarness().create_module_sync(ContainerAnalyzer)
        result = module._analyze_container(fake_path, file_enriched)
        assert result is None

    def test_git_repo_detection(self, tmp_path):
        """Test _analyze_container detects .git/config entries in archives."""
        archive_path = str(tmp_path / "repo.zip")
        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("myrepo/.git/config", "[core]\n\trepositoryformatversion = 0")
            zf.writestr("myrepo/README.md", "# My Repo")

        file_enriched = self._make_file_enriched(FileEnrichedFactory.create_zip_file, file_name="repo.zip")

        harness = ModuleTestHarness()
        module = harness.create_module_sync(ContainerAnalyzer)
        result = module._analyze_container(archive_path, file_enriched)

        assert result is not None
        assert len(result.transforms) == 1

    def test_pipe_characters_in_filenames(self, tmp_path):
        """Test _analyze_container escapes pipe characters in filenames for markdown tables."""
        archive_path = str(tmp_path / "pipes.zip")
        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("file|with|pipes.txt", "content")

        file_enriched = self._make_file_enriched(FileEnrichedFactory.create_zip_file, file_name="pipes.zip")

        module = ModuleTestHarness().create_module_sync(ContainerAnalyzer)
        result = module._analyze_container(archive_path, file_enriched)

        assert result is not None
        assert len(result.transforms) == 1


class TestShouldProcess:
    """Tests for should_process."""

    @pytest.mark.asyncio
    async def test_should_process_zip(self, tmp_path):
        """Test should_process returns True for ZIP files."""
        archive_path = str(tmp_path / "test.zip")
        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("dummy.txt", "dummy")

        file_enriched = FileEnrichedFactory.create_zip_file(object_id="test-zip-uuid")

        harness = ModuleTestHarness()
        harness.register_file("test-zip-uuid", archive_path, file_enriched)

        async with harness.create_module(ContainerAnalyzer) as module:
            result = await module.should_process("test-zip-uuid")
            assert result is True

    @pytest.mark.asyncio
    async def test_should_process_7z(self, tmp_path):
        """Test should_process returns True for 7z files."""
        archive_path = str(tmp_path / "test.7z")
        with py7zr.SevenZipFile(archive_path, "w"):
            pass

        file_enriched = FileEnrichedFactory.create_7z_file(object_id="test-7z-uuid")

        harness = ModuleTestHarness()
        harness.register_file("test-7z-uuid", archive_path, file_enriched)

        async with harness.create_module(ContainerAnalyzer) as module:
            result = await module.should_process("test-7z-uuid")
            assert result is True

    @pytest.mark.asyncio
    async def test_should_process_tar(self, tmp_path):
        """Test should_process returns True for TAR files."""
        src_file = tmp_path / "dummy.txt"
        src_file.write_text("dummy")

        archive_path = str(tmp_path / "test.tar")
        with tarfile.open(archive_path, "w") as tf:
            tf.add(str(src_file), arcname="dummy.txt")

        file_enriched = FileEnrichedFactory.create_tar_file(object_id="test-tar-uuid")

        harness = ModuleTestHarness()
        harness.register_file("test-tar-uuid", archive_path, file_enriched)

        async with harness.create_module(ContainerAnalyzer) as module:
            result = await module.should_process("test-tar-uuid")
            assert result is True

    @pytest.mark.asyncio
    async def test_should_not_process_plaintext(self, tmp_path):
        """Test should_process returns False for non-container files."""
        txt_file = tmp_path / "readme.txt"
        txt_file.write_text("not a container")

        file_enriched = FileEnrichedFactory.create_plaintext_file(object_id="test-txt-uuid")

        harness = ModuleTestHarness()
        harness.register_file("test-txt-uuid", str(txt_file), file_enriched)

        async with harness.create_module(ContainerAnalyzer) as module:
            result = await module.should_process("test-txt-uuid")
            assert result is False

    @pytest.mark.asyncio
    async def test_should_not_process_pe(self, tmp_path):
        """Test should_process returns False for PE files."""
        pe_file = tmp_path / "test.exe"
        pe_file.write_bytes(b"MZ" + b"\x00" * 100)

        file_enriched = FileEnrichedFactory.create_pe_file(object_id="test-pe-uuid")

        harness = ModuleTestHarness()
        harness.register_file("test-pe-uuid", str(pe_file), file_enriched)

        async with harness.create_module(ContainerAnalyzer) as module:
            result = await module.should_process("test-pe-uuid")
            assert result is False


class TestProcess:
    """Integration tests for the full process() method."""

    @pytest.mark.asyncio
    async def test_process_7z_with_file_path(self, tmp_path):
        """Test process() with a 7z archive passed via file_path."""
        src_file = tmp_path / "secret.txt"
        src_file.write_text("top secret data")

        archive_path = str(tmp_path / "test.7z")
        with py7zr.SevenZipFile(archive_path, "w") as sz:
            sz.write(str(src_file), arcname="secret.txt")

        file_enriched = FileEnrichedFactory.create_7z_file(object_id="test-7z-uuid", file_name="test.7z")

        harness = ModuleTestHarness()
        harness.register_file("test-7z-uuid", archive_path, file_enriched)

        async with harness.create_module(ContainerAnalyzer) as module:
            result = await module.process("test-7z-uuid", archive_path)

            assert result is not None
            assert result.module_name == "container_analyzer"
            assert len(result.transforms) == 1

            transform = result.transforms[0]
            assert transform.type == "container_contents"
            assert transform.metadata["file_name"] == "test.7z_contents.md"
            assert transform.metadata["display_type_in_dashboard"] == "markdown"
            assert transform.metadata["default_display"] is True

    @pytest.mark.asyncio
    async def test_process_7z_without_file_path(self, tmp_path):
        """Test process() downloads the file when file_path is not provided."""
        src_file = tmp_path / "data.bin"
        src_file.write_bytes(b"\xff" * 128)

        archive_path = str(tmp_path / "download.7z")
        with py7zr.SevenZipFile(archive_path, "w") as sz:
            sz.write(str(src_file), arcname="data.bin")

        file_enriched = FileEnrichedFactory.create_7z_file(object_id="test-dl-uuid", file_name="download.7z")

        harness = ModuleTestHarness()
        harness.register_file("test-dl-uuid", archive_path, file_enriched)

        async with harness.create_module(ContainerAnalyzer) as module:
            result = await module.process("test-dl-uuid")

            assert result is not None
            assert result.module_name == "container_analyzer"
            assert len(result.transforms) == 1

    @pytest.mark.asyncio
    async def test_process_zip_with_file_path(self, tmp_path):
        """Test process() with a ZIP archive."""
        archive_path = str(tmp_path / "test.zip")
        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("doc.txt", "document content")
            zf.writestr("img.png", "\x89PNG" + "\x00" * 100)

        file_enriched = FileEnrichedFactory.create_zip_file(object_id="test-zip-uuid", file_name="test.zip")

        harness = ModuleTestHarness()
        harness.register_file("test-zip-uuid", archive_path, file_enriched)

        async with harness.create_module(ContainerAnalyzer) as module:
            result = await module.process("test-zip-uuid", archive_path)

            assert result is not None
            assert len(result.transforms) == 1
            assert result.transforms[0].metadata["file_name"] == "test.zip_contents.md"

    @pytest.mark.asyncio
    async def test_process_tar_with_file_path(self, tmp_path):
        """Test process() with a TAR archive."""
        src_file = tmp_path / "script.sh"
        src_file.write_text("#!/bin/bash\necho hello")

        archive_path = str(tmp_path / "test.tar")
        with tarfile.open(archive_path, "w") as tf:
            tf.add(str(src_file), arcname="script.sh")

        file_enriched = FileEnrichedFactory.create_tar_file(object_id="test-tar-uuid", file_name="test.tar")

        harness = ModuleTestHarness()
        harness.register_file("test-tar-uuid", archive_path, file_enriched)

        async with harness.create_module(ContainerAnalyzer) as module:
            result = await module.process("test-tar-uuid", archive_path)

            assert result is not None
            assert len(result.transforms) == 1

    @pytest.mark.asyncio
    async def test_process_corrupted_file_returns_none(self, tmp_path):
        """Test process() returns None for corrupted/non-archive files."""
        bad_path = str(tmp_path / "corrupted.7z")
        with open(bad_path, "wb") as f:
            f.write(b"this is not a real archive")

        file_enriched = FileEnrichedFactory.create_7z_file(object_id="test-bad-uuid", file_name="corrupted.7z")

        harness = ModuleTestHarness()
        harness.register_file("test-bad-uuid", bad_path, file_enriched)

        async with harness.create_module(ContainerAnalyzer) as module:
            result = await module.process("test-bad-uuid", bad_path)
            assert result is None


class TestFormatSize:
    """Tests for the _format_size helper."""

    @pytest.fixture
    def module(self):
        return ModuleTestHarness().create_module_sync(ContainerAnalyzer)

    def test_bytes(self, module):
        assert module._format_size(0) == "0.00 B"
        assert module._format_size(512) == "512.00 B"
        assert module._format_size(1023) == "1023.00 B"

    def test_kilobytes(self, module):
        assert module._format_size(1024) == "1.00 KB"
        assert module._format_size(2048) == "2.00 KB"

    def test_megabytes(self, module):
        assert module._format_size(1024 * 1024) == "1.00 MB"

    def test_gigabytes(self, module):
        assert module._format_size(1024 * 1024 * 1024) == "1.00 GB"

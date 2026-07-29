"""Security-focused tests for archive content extraction."""

from pathlib import Path

import py7zr
import pytest
from file_enrichment_modules.container_contents import containers

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "containers"
MALICIOUS_SYMLINK_CHAIN_FIXTURE = FIXTURES_DIR / "malicious_symlink_chain.7z"


def test_extracts_regular_7z_archive(tmp_path):
    archive_path = tmp_path / "regular.7z"
    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir()

    with py7zr.SevenZipFile(archive_path, "w") as archive:
        archive.writestr(b"expected contents", "nested/file.txt")

    assert containers.safe_extract_archive(str(archive_path), str(extract_dir))
    assert (extract_dir / "nested" / "file.txt").read_bytes() == b"expected contents"


def test_blocks_symlink_chain_fixture_before_extraction(tmp_path, monkeypatch):
    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir()
    extract_called = False

    with py7zr.SevenZipFile(MALICIOUS_SYMLINK_CHAIN_FIXTURE) as archive:
        assert any(member.is_symlink for member in archive.list())

    def track_extract_call(*args, **kwargs):
        nonlocal extract_called
        extract_called = True

    monkeypatch.setattr(py7zr.SevenZipFile, "extract", track_extract_call)

    assert not containers.safe_extract_archive(str(MALICIOUS_SYMLINK_CHAIN_FIXTURE), str(extract_dir))
    assert not extract_called
    assert list(extract_dir.iterdir()) == []


def test_blocks_7z_archive_over_extraction_size_limit(tmp_path, monkeypatch):
    archive_path = tmp_path / "oversized.7z"
    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir()

    with py7zr.SevenZipFile(archive_path, "w") as archive:
        archive.writestr(b"too large", "file.txt")

    monkeypatch.setattr(containers, "MAX_EXTRACTED_ARCHIVE_SIZE", 4)

    assert not containers.safe_extract_archive(str(archive_path), str(extract_dir))
    assert list(extract_dir.iterdir()) == []


@pytest.mark.parametrize(
    "filename",
    [
        "../escape.txt",
        "nested/../../escape.txt",
        "/absolute/path.txt",
        "C:\\absolute\\path.txt",
        "\\\\server\\share\\path.txt",
        "nested/\x00name.txt",
    ],
)
def test_rejects_unsafe_archive_member_names(filename):
    assert not containers.is_safe_archive_member_name(filename)


def test_path_containment_does_not_accept_sibling_prefix(tmp_path):
    base_path = tmp_path / "base"
    sibling_path = tmp_path / "base-sibling" / "file.txt"

    assert not containers.is_safe_path(str(base_path), str(sibling_path))

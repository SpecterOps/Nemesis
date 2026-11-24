"""Tests for DD/disk-image extraction in web_api.large_containers.

Uses tiny FAT12 images built in-memory so real pytsk3 parsing (FS_Info / Volume_Info) is
exercised. Storage (S3) and Dapr are mocked.
"""

import os
import struct
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import UUID

import pytest
from web_api.large_containers import (
    ContainerExtractionError,
    ContainerProgress,
    DDImageContainerExtractor,
)

CID = UUID(int=0xC1D)  # container_processing.container_id is a UUID


SECTOR = 512
FS_SECTORS = 2048
SECTORS_PER_FAT = 7
ROOT_ENTRIES = 16


def _set_fat12(fat: bytearray, cluster: int, value: int) -> None:
    idx = cluster * 3 // 2
    if cluster % 2 == 0:
        fat[idx] = value & 0xFF
        fat[idx + 1] = (fat[idx + 1] & 0xF0) | ((value >> 8) & 0x0F)
    else:
        fat[idx] = (fat[idx] & 0x0F) | ((value << 4) & 0xF0)
        fat[idx + 1] = (value >> 4) & 0xFF


def build_fat12(files: dict[str, bytes], hidden_sectors: int = 0) -> bytes:
    """Build a minimal FAT12 filesystem with files in the root directory (8.3 names)."""
    boot = bytearray(SECTOR)
    boot[0:3] = b"\xeb\x3c\x90"
    boot[3:11] = b"MSDOS5.0"
    struct.pack_into(
        "<HBHBHHBHHHI",
        boot,
        11,
        SECTOR,
        1,
        1,
        2,
        ROOT_ENTRIES,
        FS_SECTORS,
        0xF8,
        SECTORS_PER_FAT,
        32,
        64,
        hidden_sectors,
    )
    boot[36] = 0x80
    boot[38] = 0x29
    boot[39:43] = b"\x12\x34\x56\x78"
    boot[43:54] = b"TESTVOL    "
    boot[54:62] = b"FAT12   "
    boot[510:512] = b"\x55\xaa"

    fat = bytearray(SECTORS_PER_FAT * SECTOR)
    _set_fat12(fat, 0, 0xFF8)
    _set_fat12(fat, 1, 0xFFF)

    root = bytearray(SECTOR)
    data = bytearray()
    cluster = 2
    for i, (name, content) in enumerate(files.items()):
        base, ext = name.split(".")
        entry = bytearray(32)
        entry[0:8] = base.upper().ljust(8).encode()
        entry[8:11] = ext.upper().ljust(3).encode()
        entry[11] = 0x20
        n_clusters = max(1, -(-len(content) // SECTOR))
        struct.pack_into("<H", entry, 26, cluster if content else 0)
        struct.pack_into("<I", entry, 28, len(content))
        root[i * 32 : (i + 1) * 32] = entry
        if content:
            for c in range(cluster, cluster + n_clusters):
                _set_fat12(fat, c, c + 1 if c < cluster + n_clusters - 1 else 0xFFF)
            data += content.ljust(n_clusters * SECTOR, b"\x00")
            cluster += n_clusters

    image = bytes(boot) + bytes(fat) * 2 + bytes(root) + bytes(data)
    return image.ljust(FS_SECTORS * SECTOR, b"\x00")


def build_mbr_image(partitions: list[dict[str, bytes] | None], start_lba: int = 64) -> bytes:
    """Build a disk with an MBR partition table. A None entry is an empty (non-FAT) partition."""
    mbr = bytearray(SECTOR)
    lba = start_lba
    bodies = []
    for i, files in enumerate(partitions):
        entry = bytearray(16)
        entry[4] = 0x01  # FAT12
        struct.pack_into("<II", entry, 8, lba, FS_SECTORS)
        mbr[446 + i * 16 : 446 + (i + 1) * 16] = entry
        bodies.append(build_fat12(files, hidden_sectors=lba) if files is not None else b"\x00" * FS_SECTORS * SECTOR)
        lba += FS_SECTORS
    mbr[510:512] = b"\x55\xaa"
    return bytes(mbr) + b"\x00" * (start_lba - 1) * SECTOR + b"".join(bodies)


@pytest.fixture
def storage():
    s = MagicMock()
    uploaded = []

    def _upload(path):
        with open(path, "rb") as f:
            uploaded.append((path, f.read()))
        return UUID(int=len(uploaded))

    s.upload_file.side_effect = _upload
    s.uploaded = uploaded
    return s


@pytest.fixture
def dapr():
    return MagicMock()


def make_extractor(storage, dapr, path="/mounted-containers/case1/disk.dd", **meta):
    tracker = ContainerProgress()
    extractor = DDImageContainerExtractor(storage, dapr, tracker)
    metadata = {"agent_id": "a1", "project": "p1", "source": "host1", "path": path, **meta}
    extractor.set_container_info(CID, metadata)
    tracker.initialize(CID, 0, 0)
    return extractor


def published_paths(dapr) -> list[str]:
    import json

    return sorted(json.loads(c.kwargs["data"])["path"] for c in dapr.publish_event.call_args_list)


def user_files(paths: list[str]) -> list[str]:
    """Drop TSK's FAT virtual files ($MBR, $FAT1, $FAT2)."""
    return [p for p in paths if not os.path.basename(p).startswith("$")]


# --- Happy paths -------------------------------------------------------------------------


def test_bare_filesystem_image_extracts_files(tmp_path, storage, dapr):
    img = tmp_path / "disk.dd"
    img.write_bytes(build_fat12({"hello.txt": b"hello world", "a.bin": b"x" * 1500}))

    extractor = make_extractor(storage, dapr)
    count, _size = extractor.estimate_container_contents(img)
    processed = extractor.extract_and_process(img)

    assert processed == count
    assert user_files(published_paths(dapr)) == ["case1/A.BIN", "case1/HELLO.TXT"]
    contents = {os.path.basename(p): c for p, c in storage.uploaded}
    assert extractor.filter_stats["files_skipped_by_error"] == 0
    assert b"hello world" in contents.values()
    assert b"x" * 1500 in contents.values()
    # Temp files are cleaned up
    assert all(not os.path.exists(p) for p, _ in storage.uploaded)


def test_partitioned_image_single_partition_has_no_prefix(tmp_path, storage, dapr):
    img = tmp_path / "disk.dd"
    img.write_bytes(build_mbr_image([{"hello.txt": b"hello"}]))

    extractor = make_extractor(storage, dapr)
    count, _ = extractor.estimate_container_contents(img)
    processed = extractor.extract_and_process(img)

    assert count > 0
    assert processed == count
    assert user_files(published_paths(dapr)) == ["case1/HELLO.TXT"]


def test_partitioned_image_multiple_partitions_prefixed(tmp_path, storage, dapr):
    img = tmp_path / "disk.dd"
    img.write_bytes(build_mbr_image([{"one.txt": b"first"}, None, {"two.txt": b"second"}]))

    extractor = make_extractor(storage, dapr)
    processed = extractor.extract_and_process(img)

    paths = user_files(published_paths(dapr))
    assert processed >= 2
    assert len(paths) == 2
    assert any(p.endswith("/ONE.TXT") and "/partition" in p for p in paths)
    assert any(p.endswith("/TWO.TXT") and "/partition" in p for p in paths)
    # The two files come from different partition prefixes
    assert len({p.rsplit("/", 1)[0] for p in paths}) == 2


def test_filter_skips_not_double_counted(tmp_path, storage, dapr):
    img = tmp_path / "disk.dd"
    img.write_bytes(build_fat12({"keep.txt": b"keep", "skip.log": b"skip"}))

    extractor = make_extractor(storage, dapr, file_filters={"pattern_type": "regex", "exclude": [r"\.log$"]})
    extractor.estimate_container_contents(img)
    extractor.extract_and_process(img)

    assert user_files(published_paths(dapr)) == ["case1/KEEP.TXT"]
    # SKIP.LOG counted once (not once in the estimate and again during extraction)
    assert extractor.filter_stats["files_skipped_by_filter"] == 1


def test_windows_container_path_is_normalized(tmp_path, storage, dapr):
    img = tmp_path / "disk.dd"
    img.write_bytes(build_fat12({"hello.txt": b"hello"}))

    extractor = make_extractor(storage, dapr, path="C:\\Evidence\\disk.dd")
    extractor.extract_and_process(img)

    assert "/C:/Evidence/HELLO.TXT" in published_paths(dapr)


# --- Unhappy paths ------------------------------------------------------------------------


def test_unreadable_image_raises_instead_of_returning_zero(tmp_path, storage, dapr):
    img = tmp_path / "garbage.dd"
    img.write_bytes(os.urandom(64 * SECTOR))

    extractor = make_extractor(storage, dapr)
    assert extractor.estimate_container_contents(img) == (0, 0)
    with pytest.raises(ContainerExtractionError):
        extractor.extract_and_process(img)
    storage.upload_file.assert_not_called()


def test_partition_table_without_readable_filesystem_raises(tmp_path, storage, dapr):
    img = tmp_path / "disk.dd"
    img.write_bytes(build_mbr_image([None]))

    extractor = make_extractor(storage, dapr)
    with pytest.raises(ContainerExtractionError, match="No readable filesystem"):
        extractor.extract_and_process(img)


def test_root_dir_failure_raises(storage, dapr):
    extractor = make_extractor(storage, dapr)
    fs = MagicMock()
    fs.open_dir.side_effect = OSError("bad root")
    with (
        patch("web_api.large_containers.pytsk3.Img_Info"),
        patch.object(DDImageContainerExtractor, "_open_filesystems", return_value=[("", fs)]),
        pytest.raises(ContainerExtractionError, match="root directory"),
    ):
        extractor.extract_and_process(Path("/nonexistent.dd"))


def test_open_filesystems_skips_unallocated_partitions(storage, dapr):
    extractor = make_extractor(storage, dapr)
    alloc = MagicMock(flags=1, start=2048, addr=2)  # TSK_VS_PART_FLAG_ALLOC == 1
    unalloc = MagicMock(flags=2, start=0, addr=0)
    volume = MagicMock()
    volume.info.block_size = 512
    volume.__iter__.return_value = iter([unalloc, alloc])
    fs = MagicMock()

    def fake_fs_info(img, offset=0):
        if offset == 0:
            raise OSError("no fs at 0")
        assert offset == 2048 * 512
        return fs

    with (
        patch("web_api.large_containers.pytsk3.FS_Info", side_effect=fake_fs_info) as fs_info,
        patch("web_api.large_containers.pytsk3.Volume_Info", return_value=volume),
    ):
        result = extractor._open_filesystems(MagicMock())

    assert result == [("", fs)]
    assert fs_info.call_count == 2


def test_upload_failure_cleans_temp_file_and_counts_error(tmp_path, storage, dapr):
    img = tmp_path / "disk.dd"
    img.write_bytes(build_fat12({"hello.txt": b"hello"}))
    temp_paths = []

    def failing_upload(path):
        temp_paths.append(path)
        raise ConnectionError("seaweedfs down")

    storage.upload_file.side_effect = failing_upload
    extractor = make_extractor(storage, dapr)
    processed = extractor.extract_and_process(img)

    assert processed == 0
    assert temp_paths
    assert all(not os.path.exists(p) for p in temp_paths)
    assert extractor.filter_stats["files_skipped_by_error"] == len(temp_paths)
    dapr.publish_event.assert_not_called()


def test_publish_failure_deletes_uploaded_object(tmp_path, storage, dapr):
    img = tmp_path / "disk.dd"
    img.write_bytes(build_fat12({"hello.txt": b"hello"}))
    dapr.publish_event.side_effect = RuntimeError("pubsub down")

    extractor = make_extractor(storage, dapr)
    processed = extractor.extract_and_process(img)

    assert processed == 0
    deleted = sorted(c.args[0] for c in storage.delete_object.call_args_list)
    assert deleted == sorted(UUID(int=i + 1) for i in range(len(storage.uploaded)))
    assert all(not os.path.exists(p) for p, _ in storage.uploaded)

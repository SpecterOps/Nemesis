"""Files extracted by container_contents carry their member times/ownership from the archive listing."""

import contextlib
import io
import json
import os
import tarfile
import zipfile
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import py7zr
import pytest
from common import data_issues
from common.models import FileEnriched
from file_enrichment_modules.container_contents.containers import ContainerExtractor, archive_member_details


@pytest.fixture
def logged(monkeypatch):
    calls = []
    monkeypatch.setattr(data_issues, "logger", type("L", (), {"warning": lambda self, event, **kw: calls.append(kw)})())
    return calls


def make_zip(path):
    with zipfile.ZipFile(path, "w") as zf:
        info = zipfile.ZipInfo("dir/a.txt", date_time=(2024, 3, 4, 5, 6, 8))
        info.create_system = 3
        info.external_attr = 0o100600 << 16
        zf.writestr(info, b"alpha")
        zf.writestr(zipfile.ZipInfo("dir/", date_time=(2024, 1, 1, 0, 0, 0)), b"")
    return path


def make_tar(path):
    with tarfile.open(path, "w") as tf:
        data = b"bravo"
        info = tarfile.TarInfo("dir/b.txt")
        info.size, info.mtime, info.uname, info.gname, info.mode = len(data), 1_700_000_000, "alice", "staff", 0o640
        tf.addfile(info, io.BytesIO(data))
    return path


def make_7z(tmp_path):
    source = tmp_path / "c.txt"
    source.write_bytes(b"charlie")
    os.utime(source, (1_700_000_000, 1_700_000_000))
    path = tmp_path / "t.7z"
    with py7zr.SevenZipFile(path, "w") as sz:
        sz.write(source, "dir/c.txt")
    return path


def test_zip_member_details_and_utc_assumption_logged_once(tmp_path, logged):
    object_id = uuid4()
    details = archive_member_details(str(make_zip(tmp_path / "t.zip")), object_id=object_id)
    assert list(details) == ["dir/a.txt"]
    assert details["dir/a.txt"]["modification_time"] == datetime(2024, 3, 4, 5, 6, 8, tzinfo=UTC)
    assert details["dir/a.txt"]["security_info"] == {"mode": 0o100600}
    assert [c["kind"] for c in logged] == ["file_time_assumed_utc"]
    assert logged[0]["object_id"] == str(object_id) and logged[0]["files"] == 1


def test_tar_member_details(tmp_path, logged):
    details = archive_member_details(str(make_tar(tmp_path / "t.tar")))
    assert details["dir/b.txt"]["modification_time"] == datetime.fromtimestamp(1_700_000_000, UTC)
    assert details["dir/b.txt"]["security_info"] == {"owner": "alice", "group": "staff", "mode": 0o640}
    assert logged == []  # tar times are real UTC epochs


def test_7z_member_details(tmp_path):
    details = archive_member_details(str(make_7z(tmp_path)))
    assert details["dir/c.txt"] == {"modification_time": datetime.fromtimestamp(1_700_000_000, UTC)}


def test_unreadable_archive_gives_no_details(tmp_path):
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"not an archive")
    assert archive_member_details(str(bad)) == {}


class FakeStorage:
    def __init__(self, archive):
        self.archive = archive
        self.count = 0

    @contextlib.contextmanager
    def download(self, _object_id):
        with open(self.archive, "rb") as handle:
            yield handle

    def upload_file(self, _path):
        self.count += 1
        return UUID(int=self.count)


def file_enriched(path: str) -> FileEnriched:
    now = datetime.now(UTC)
    return FileEnriched(
        object_id=uuid4(),
        agent_id="a",
        source="host://ws01",
        project="p",
        timestamp=now,
        expiration=now + timedelta(days=1),
        path=path,
        file_name=path.rsplit("/", 1)[-1],
        size=1,
        hashes={"md5": "m", "sha1": "s", "sha256": "h"},
        magic_type="archive",
        mime_type="application/x-tar",
        is_plaintext=False,
        is_container=True,
    )


@pytest.mark.asyncio
async def test_extracted_files_published_with_member_details(tmp_path):
    archive = make_zip(tmp_path / "t.zip")
    dapr = AsyncMock()
    extractor = ContainerExtractor(FakeStorage(archive), dapr, extracted_archive_size_limit=10**9)
    await extractor.extract(file_enriched("/loot/t.zip"))

    message = json.loads(dapr.publish_event.await_args.kwargs["data"])
    assert message["path"] == "/loot/dir/a.txt"
    assert datetime.fromisoformat(message["modification_time"]) == datetime(2024, 3, 4, 5, 6, 8, tzinfo=UTC)
    assert message["security_info"]["mode"] == 0o100600

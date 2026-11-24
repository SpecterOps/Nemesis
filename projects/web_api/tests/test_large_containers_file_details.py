"""Files extracted from large containers carry their times and ownership from the archive or disk image."""

import json
import zipfile
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import UUID

import pytest
from common import data_issues
from common.file_details import tsk_meta_details
from web_api.large_containers import ContainerProgress, ZipContainerExtractor

CID = UUID(int=0xC1D)


@pytest.fixture
def storage():
    s = MagicMock()
    counter = iter(range(1, 1000))
    s.upload_file.side_effect = lambda _path: UUID(int=next(counter))
    return s


@pytest.fixture
def logged(monkeypatch):
    calls = []
    monkeypatch.setattr(data_issues, "logger", type("L", (), {"warning": lambda self, event, **kw: calls.append(kw)})())
    return calls


def extractor(storage, dapr):
    zip_extractor = ZipContainerExtractor(storage, dapr, ContainerProgress())
    zip_extractor.set_container_info(CID, {"agent_id": "a", "project": "p", "source": "s", "path": "/loot/t.zip"})
    zip_extractor.progress_tracker.initialize(CID, 0, 0)
    return zip_extractor


def messages(dapr):
    return {m["path"]: m for m in (json.loads(c.kwargs["data"]) for c in dapr.publish_event.call_args_list)}


def test_zip_members_carry_modification_time_and_unix_mode(tmp_path, storage, logged):
    path = tmp_path / "t.zip"
    with zipfile.ZipFile(path, "w") as zf:
        unix = zipfile.ZipInfo("docs/a.txt", date_time=(2024, 3, 4, 5, 6, 8))
        unix.create_system = 3
        unix.external_attr = 0o100600 << 16
        zf.writestr(unix, b"alpha")
        zf.writestr(zipfile.ZipInfo("b.txt", date_time=(2023, 1, 2, 3, 4, 6)), b"bravo")
    dapr = MagicMock()
    assert extractor(storage, dapr).extract_and_process(path) == 2

    published = messages(dapr)
    a, b = published["/loot/docs/a.txt"], published["/loot/b.txt"]
    assert datetime.fromisoformat(a["modification_time"]) == datetime(2024, 3, 4, 5, 6, 8, tzinfo=UTC)
    assert a["security_info"]["mode"] == 0o100600
    assert datetime.fromisoformat(b["modification_time"]) == datetime(2023, 1, 2, 3, 4, 6, tzinfo=UTC)
    # The UTC assumption is logged once for the archive, not per member
    assumed = [c for c in logged if c["kind"] == "file_time_assumed_utc"]
    assert len(assumed) == 1 and assumed[0]["files"] == 2 and assumed[0]["container_id"] == str(CID)


def test_publish_passes_disk_image_details(storage, tmp_path):
    dapr = MagicMock()
    zip_extractor = extractor(storage, dapr)
    member = tmp_path / "m"
    member.write_bytes(b"x")
    meta = SimpleNamespace(crtime=1_600_000_000, atime=1_700_000_100, mtime=1_700_000_000, uid=0, gid=0, mode=0o644)
    zip_extractor.publish_file_message(str(member), UUID(int=7), "/loot/Windows/x.dll", tsk_meta_details(meta))
    message = json.loads(dapr.publish_event.call_args.kwargs["data"])
    assert datetime.fromisoformat(message["creation_time"]) == datetime.fromtimestamp(1_600_000_000, UTC)
    assert datetime.fromisoformat(message["access_time"]) == datetime.fromtimestamp(1_700_000_100, UTC)
    assert message["security_info"] == {"owner": "0", "group": "0", "mode": 0o644}


def test_publish_without_details_has_no_original_fields(storage, tmp_path):
    dapr = MagicMock()
    member = tmp_path / "m"
    member.write_bytes(b"x")
    extractor(storage, dapr).publish_file_message(str(member), UUID(int=8), "/loot/x")
    message = json.loads(dapr.publish_event.call_args.kwargs["data"])
    assert not {"creation_time", "access_time", "modification_time", "security_info"} & message.keys()

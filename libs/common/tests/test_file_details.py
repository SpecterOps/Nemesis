"""File times and ownership from archives/disk images, and their path through the File models and DB reads."""

import io
import tarfile
import zipfile
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from common.file_details import (
    sevenzip_member_details,
    tar_member_details,
    tsk_meta_details,
    zip_member_details,
)
from common.models import File, FileEnriched
from common.models2.api import FileMetadata, SecurityInfo
from common.state_helpers import _transform_file_enriched_data
from pydantic import ValidationError

# --- archive and disk-image entries --------------------------------------------------------------------------


def test_zip_member_time_read_as_utc_and_unix_mode():
    info = zipfile.ZipInfo("dir/a.txt", date_time=(2024, 3, 4, 5, 6, 8))
    info.create_system = 3
    info.external_attr = 0o100640 << 16
    details = zip_member_details(info)
    assert details["modification_time"] == datetime(2024, 3, 4, 5, 6, 8, tzinfo=UTC)
    assert details["security_info"] == {"mode": 0o100640}


def test_zip_member_from_windows_has_no_mode():
    info = zipfile.ZipInfo("a.txt", date_time=(2024, 1, 1, 0, 0, 0))
    info.create_system = 0
    info.external_attr = 0x20  # DOS archive bit
    assert "security_info" not in zip_member_details(info)


def test_tar_member_details():
    info = tarfile.TarInfo("a.txt")
    info.mtime = 1_700_000_000
    info.uid, info.gid, info.uname, info.gname, info.mode = 1000, 100, "alice", "", 0o644
    details = tar_member_details(info)
    assert details["modification_time"] == datetime.fromtimestamp(1_700_000_000, UTC)
    assert details["security_info"] == {"owner": "alice", "group": "100", "mode": 0o644}


def test_tar_member_without_mtime_has_no_time():
    info = tarfile.TarInfo("a.txt")
    info.mtime = 0
    assert "modification_time" not in tar_member_details(info)


def test_sevenzip_member_details():
    when = datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)
    assert sevenzip_member_details(when) == {"modification_time": when}
    assert sevenzip_member_details(None) == {}
    assert sevenzip_member_details(datetime(2023, 1, 1)) == {}  # never store a naive time


def test_tsk_meta_details():
    meta = SimpleNamespace(crtime=1_600_000_000, atime=0, mtime=1_700_000_000, uid=0, gid=5, mode=0o755)
    details = tsk_meta_details(meta)
    assert details["creation_time"] == datetime.fromtimestamp(1_600_000_000, UTC)
    assert details["modification_time"] == datetime.fromtimestamp(1_700_000_000, UTC)
    assert "access_time" not in details  # 0 means unset
    assert details["security_info"] == {"owner": "0", "group": "5", "mode": 0o755}


def test_tsk_meta_with_out_of_range_time_is_skipped():
    meta = SimpleNamespace(crtime=10**20, atime=None, mtime=None, uid=None, gid=None, mode=None)
    assert tsk_meta_details(meta) == {}


# --- models ---------------------------------------------------------------------------------------------------


def file_fields(**overrides):
    now = datetime.now(UTC)
    return {
        "object_id": uuid4(),
        "agent_id": "a",
        "source": "host://ws01",
        "project": "p",
        "timestamp": now,
        "expiration": now + timedelta(days=1),
        "path": "/x",
    } | overrides


@pytest.mark.parametrize("model", [FileMetadata, File])
def test_original_times_and_security_accepted(model):
    item = model(
        **file_fields(
            modification_time="2024-01-28T09:15:00+02:00",
            security_info={"owner": "alice", "group": "staff", "mode": 0o100644},
        )
    )
    assert item.modification_time == datetime(2024, 1, 28, 7, 15, tzinfo=UTC)
    assert item.security_info == SecurityInfo(owner="alice", group="staff", mode=0o100644)


@pytest.mark.parametrize("model", [FileMetadata, File])
@pytest.mark.parametrize("field", ["creation_time", "access_time", "modification_time"])
def test_naive_original_times_rejected(model, field):
    with pytest.raises(ValidationError):
        model(**file_fields(**{field: "2024-01-28T09:15:00"}))


@pytest.mark.parametrize(
    "security_info",
    [{"owner": "a", "unexpected": 1}, {"mode": -1}, {"mode": 0o1000000}, {"owner": "x" * 1001}],
)
def test_invalid_security_info_rejected(security_info):
    with pytest.raises(ValidationError):
        File(**file_fields(security_info=security_info))


def test_from_file_metadata_copies_original_details():
    metadata = FileMetadata(
        **file_fields(
            creation_time="2024-01-01T00:00:00Z",
            access_time="2024-01-03T00:00:00Z",
            modification_time="2024-01-02T00:00:00Z",
            security_info={"owner": "alice"},
        )
    )
    file = File.from_file_metadata(metadata, uuid4())
    assert file.creation_time == datetime(2024, 1, 1, tzinfo=UTC)
    assert file.access_time == datetime(2024, 1, 3, tzinfo=UTC)
    assert file.modification_time == datetime(2024, 1, 2, tzinfo=UTC)
    assert file.security_info == SecurityInfo(owner="alice")


def test_json_dump_keeps_timezone_and_security_info():
    dumped = File(**file_fields(modification_time="2024-01-02T00:00:00Z", security_info={"mode": 0o644})).model_dump(
        exclude_none=True
    )
    assert datetime.fromisoformat(dumped["modification_time"]) == datetime(2024, 1, 2, tzinfo=UTC)
    assert dumped["security_info"]["mode"] == 0o644


def test_db_row_maps_file_prefixed_columns_to_model_fields():
    row = {
        **file_fields(),
        "file_name": "x",
        "size": 1,
        "magic_type": "data",
        "mime_type": "application/octet-stream",
        "is_plaintext": False,
        "is_container": False,
        "hashes": '{"md5": "a", "sha1": "b", "sha256": "c"}',
        "file_creation_time": datetime(2024, 1, 1, tzinfo=UTC),
        "file_access_time": None,
        "file_modification_time": datetime(2024, 1, 2, tzinfo=UTC),
        "security_info": '{"owner": "alice", "mode": 420}',
    }
    enriched = FileEnriched.model_validate(_transform_file_enriched_data(row))
    assert enriched.creation_time == datetime(2024, 1, 1, tzinfo=UTC)
    assert enriched.access_time is None
    assert enriched.modification_time == datetime(2024, 1, 2, tzinfo=UTC)
    assert enriched.security_info == SecurityInfo(owner="alice", mode=420)


def test_zip_roundtrip_member_details():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        info = zipfile.ZipInfo("a.txt", date_time=(2020, 2, 29, 12, 0, 0))
        zf.writestr(info, b"x")
    with zipfile.ZipFile(buffer) as zf:
        assert zip_member_details(zf.infolist()[0])["modification_time"] == datetime(2020, 2, 29, 12, tzinfo=UTC)

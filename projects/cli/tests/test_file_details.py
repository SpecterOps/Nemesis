"""submit/monitor send each file's times and ownership; containers' own stat isn't sent."""

import os
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from cli import file_details
from cli.file_details import local_file_details
from cli.submit import create_metadata
from common.models2.api import FileMetadata


def fake_stat(**overrides):
    values = {
        "st_atime": 1_700_000_100.5,
        "st_mtime": 1_700_000_000.0,
        "st_mode": 0o100640,
        "st_uid": 1000,
        "st_gid": 100,
    } | overrides
    return SimpleNamespace(**values)


def test_details_are_utc_and_accepted_by_the_api_model(tmp_path, monkeypatch):
    target = tmp_path / "a.txt"
    target.write_text("x")
    monkeypatch.setattr(file_details.os, "stat", lambda _p: fake_stat(st_birthtime=1_600_000_000.0))
    details = local_file_details(target)
    assert datetime.fromisoformat(details["modification_time"]) == datetime.fromtimestamp(1_700_000_000, UTC)
    assert datetime.fromisoformat(details["creation_time"]) == datetime.fromtimestamp(1_600_000_000, UTC)
    assert details["security_info"]["mode"] == 0o100640
    metadata = FileMetadata(agent_id="a", project="p", path="/x", **details)
    assert metadata.creation_time is not None and metadata.creation_time.tzinfo is not None


def test_no_birthtime_means_no_creation_time(tmp_path, monkeypatch):
    monkeypatch.setattr(file_details.os, "stat", lambda _p: fake_stat())
    assert "creation_time" not in local_file_details(tmp_path)


def test_unknown_uid_and_gid_fall_back_to_numbers(tmp_path, monkeypatch):
    monkeypatch.setattr(file_details.os, "stat", lambda _p: fake_stat(st_uid=987654, st_gid=987654))

    def missing(_id):
        raise KeyError(_id)

    monkeypatch.setattr(file_details, "pwd", SimpleNamespace(getpwuid=missing))
    monkeypatch.setattr(file_details, "grp", SimpleNamespace(getgrgid=missing))
    monkeypatch.setattr(file_details.os, "name", "posix")
    security = local_file_details(tmp_path)["security_info"]
    assert security["owner"] == "987654" and security["group"] == "987654"


def test_names_resolved_when_known(tmp_path, monkeypatch):
    monkeypatch.setattr(file_details.os, "stat", lambda _p: fake_stat())
    monkeypatch.setattr(file_details, "pwd", SimpleNamespace(getpwuid=lambda _u: SimpleNamespace(pw_name="alice")))
    monkeypatch.setattr(file_details, "grp", SimpleNamespace(getgrgid=lambda _g: SimpleNamespace(gr_name="staff")))
    monkeypatch.setattr(file_details.os, "name", "posix")
    security = local_file_details(tmp_path)["security_info"]
    assert (security["owner"], security["group"]) == ("alice", "staff")


def test_windows_sends_only_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(file_details.os, "stat", lambda _p: fake_stat())
    monkeypatch.setattr(file_details.os, "name", "nt")
    assert local_file_details(tmp_path)["security_info"] == {"mode": 0o100640}


def test_create_metadata_includes_details_for_real_files(tmp_path):
    target = tmp_path / "a.txt"
    target.write_text("x")
    os.utime(target, (1_700_000_100, 1_700_000_000))
    metadata = create_metadata("/loot/a.txt", local_path=target)
    assert datetime.fromisoformat(metadata["modification_time"]) == datetime.fromtimestamp(1_700_000_000, UTC)
    assert "security_info" in metadata
    FileMetadata(**metadata)  # what the API will validate


def test_create_metadata_without_local_path_has_no_details():
    metadata = create_metadata("/loot/a.zip")
    assert not {"creation_time", "access_time", "modification_time", "security_info"} & metadata.keys()


def test_unreadable_file_still_submits(tmp_path, monkeypatch):
    def boom(_p):
        raise PermissionError("denied")

    monkeypatch.setattr(file_details.os, "stat", boom)
    metadata = create_metadata("/loot/a.txt", local_path=Path(tmp_path / "gone"))
    assert "modification_time" not in metadata

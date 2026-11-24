"""files_enriched.extension is VARCHAR(50): longer suffixes are treated as no extension, and logged."""

from uuid import uuid4

import pytest
from common import data_issues
from common.helpers import MAX_EXTENSION_LENGTH, get_file_extension
from common.models import FileEnriched
from pydantic import ValidationError


@pytest.fixture
def issues(monkeypatch):
    calls = []
    monkeypatch.setattr(data_issues, "logger", type("L", (), {"warning": lambda self, e, **kw: calls.append(kw)})())
    return calls


@pytest.mark.parametrize(
    ("path", "expected"),
    [("C:/x/report.txt", ".txt"), ("/a/b.tar.gz", ".gz"), ("/a/.bashrc", ""), ("/a/noext", ""), ("", "")],
)
def test_normal_extensions(path, expected, issues):
    assert get_file_extension(path) == expected
    assert issues == []


def test_extension_at_limit_is_kept(issues):
    ext = "." + "a" * (MAX_EXTENSION_LENGTH - 1)
    assert get_file_extension(f"/d/file{ext}") == ext
    assert issues == []


def test_long_suffix_is_dropped_and_logged(issues):
    object_id = uuid4()
    suffix = "2024-01-01_backup_copy_of_something_rather_long_indeed"
    assert get_file_extension(f"/d/report.{suffix}", object_id=object_id) == ""
    assert issues == [
        {
            "kind": "extension_too_long",
            "field": "files_enriched.extension",
            "object_id": str(object_id),
            "length": len(suffix) + 1,
            "limit": MAX_EXTENSION_LENGTH,
            "prefix": ("." + suffix)[:20],
        }
    ]


def enriched(extension):
    return {
        "object_id": str(uuid4()),
        "agent_id": "a",
        "source": "host://ws01",
        "project": "p",
        "timestamp": "2026-01-01T00:00:00Z",
        "expiration": "2027-01-01T00:00:00Z",
        "path": "/x",
        "file_name": "x",
        "extension": extension,
        "size": 1,
        "hashes": {"md5": "m", "sha1": "s", "sha256": "h"},
        "magic_type": "data",
        "mime_type": "application/octet-stream",
        "is_plaintext": False,
        "is_container": False,
    }


def test_model_accepts_extension_at_limit():
    ext = "." + "a" * (MAX_EXTENSION_LENGTH - 1)
    assert FileEnriched.model_validate(enriched(ext)).extension == ext


def test_model_rejects_oversized_extension():
    with pytest.raises(ValidationError, match="extension"):
        FileEnriched.model_validate(enriched("." + "a" * MAX_EXTENSION_LENGTH))

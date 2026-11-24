"""A path with an over-long suffix is enriched with no extension instead of failing the files_enriched insert."""

from unittest.mock import MagicMock, patch
from uuid import uuid4

from common import data_issues

with patch("common.storage.StorageS3", MagicMock()):
    from file_enrichment.activities.basic_analysis import process_basic_analysis


def test_long_suffix_enriches_with_no_extension(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(data_issues, "logger", type("L", (), {"warning": lambda self, e, **kw: calls.append(kw)})())
    sample = tmp_path / "sample"
    sample.write_text("hello world\n")
    object_id = str(uuid4())
    path = "C:/loot/report." + "x" * 80
    result = process_basic_analysis(str(sample), {"object_id": object_id, "path": path})
    assert result["extension"] == ""
    assert result["file_name"] == "report." + "x" * 80
    assert result["hashes"]["sha256"]
    assert calls and calls[0]["kind"] == "extension_too_long" and calls[0]["object_id"] == object_id


def test_normal_extension_kept(tmp_path):
    sample = tmp_path / "sample"
    sample.write_text("hello\n")
    assert process_basic_analysis(str(sample), {"object_id": str(uuid4()), "path": "/a/b.txt"})["extension"] == ".txt"

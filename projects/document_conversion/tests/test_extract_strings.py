"""extract_all_strings reads the `strings` output in chunks; the result must match a line-by-line filter."""

import io
import shutil
import subprocess
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

with patch("common.storage.StorageS3", MagicMock()):
    import document_conversion.activities.extract_strings as es

pytestmark = pytest.mark.skipif(shutil.which("strings") is None, reason="binutils `strings` not installed")


@pytest.fixture
def sample(tmp_path):
    """Binary with ASCII, UTF-16 LE and UTF-16 BE strings, long runs, and junk between them."""
    parts = [b"\x00\x01\x02"]
    for i in range(300):
        parts.append(f"ascii string number {i} with some padding".encode() + b"\x00\xff")
        parts.append(f"wide le {i}".encode("utf-16-le") + b"\x00\x00\x01")
        parts.append(f"wide be {i}".encode("utf-16-be") + b"\x00\x00\x02")
    parts.append(b"x" * 5000 + b"\x00")  # one line longer than a small chunk
    path = tmp_path / "sample.bin"
    path.write_bytes(b"".join(parts))
    return path


def _reference(path, min_len=5):
    """The previous behaviour: every non-blank output line of the three `strings` passes, in order."""
    out = []
    for enc in ([], ["-e", "l"], ["-e", "b"]):
        text = subprocess.run(["strings", "-a", "-n", str(min_len), *enc, str(path)], capture_output=True).stdout
        for line in text.decode("utf-8").split("\n"):
            line = line.rstrip("\r")
            if line and line.strip():
                out.append(line + "\n")
    return "".join(out)


@pytest.mark.asyncio
@pytest.mark.parametrize("chunk", [7, 64, 1024 * 1024])
async def test_output_matches_line_by_line_filtering(sample, monkeypatch, chunk):
    monkeypatch.setattr(es, "_READ_CHUNK", chunk)  # small chunks split lines across reads
    out = io.StringIO()
    await es.extract_all_strings(str(sample), out)
    expected = _reference(sample)
    assert "wide le 299" in expected and "wide be 299" in expected and "x" * 5000 in expected
    assert out.getvalue() == expected


@pytest.mark.asyncio
async def test_file_without_strings_writes_nothing(tmp_path):
    path = tmp_path / "empty.bin"
    path.write_bytes(b"\x00\x01\x02\x03" * 100)
    out = io.StringIO()
    await es.extract_all_strings(str(path), out)
    assert out.getvalue() == ""


def test_blank_lines_are_dropped():
    out = io.StringIO()
    es._write_strings(out, [b"keep me", b"   ", b"", b"also\r"])
    assert out.getvalue() == "keep me\nalso\n"


# --- the activity: what is uploaded, and temp files are cleaned up ---


class _Storage:
    """Serves a local file as the download and records the content of each upload (read from disk, by path)."""

    def __init__(self, source):
        self.source = source
        self.uploaded: list[str] = []
        self.upload_paths: list[str] = []

    @contextmanager
    def download(self, object_id):
        yield SimpleNamespace(name=str(self.source))

    def upload_file(self, path):
        self.upload_paths.append(path)
        self.uploaded.append(open(path, encoding="utf-8").read())
        return uuid4()


@pytest.fixture
def activity(monkeypatch, tmp_path):
    """Run the extract_strings activity on a local file; temp files go to tmp_path/tmp so leftovers can be seen."""
    import asyncio

    import common.workflows.setup as wf_setup

    temp_dir = tmp_path / "tmp"
    temp_dir.mkdir()
    monkeypatch.setattr(es.tempfile, "tempdir", str(temp_dir))
    tracking = SimpleNamespace(update_enrichment_results=AsyncMock())
    monkeypatch.setattr(es.global_vars, "tracking_service", tracking)
    monkeypatch.setattr(
        es, "get_file_enriched_async", AsyncMock(return_value=SimpleNamespace(object_id=uuid4(), is_container=False))
    )

    async def run(source):
        storage = _Storage(source)
        monkeypatch.setattr(es, "storage", storage)
        monkeypatch.setattr(wf_setup, "workflow_loop", asyncio.get_running_loop())
        ctx = SimpleNamespace(workflow_id="document_conversion.test")
        result = await es.extract_strings()(ctx, {"object_id": str(uuid4())})
        return result, storage, sorted(p.name for p in temp_dir.iterdir())

    return run


@pytest.mark.asyncio
async def test_small_output_is_uploaded_in_full(activity, tmp_path):
    """Output smaller than the write buffer used to read as an empty file and was dropped."""
    source = tmp_path / "small.bin"
    source.write_bytes(b"\x00\x01hello strings world\x00\x02another visible line\x00")
    result, storage, leftovers = await activity(source)
    assert result is not None and result["type"] == "extracted_strings"
    assert storage.uploaded == [_reference(source)]
    assert "hello strings world" in storage.uploaded[0]
    assert leftovers == []


@pytest.mark.asyncio
async def test_large_output_is_not_truncated(activity, sample):
    """The last write-buffer's worth of strings used to be missing from the upload."""
    result, storage, leftovers = await activity(sample)
    assert storage.uploaded == [_reference(sample)]
    assert storage.uploaded[0].endswith("x" * 5000 + "\n") or "wide be 299" in storage.uploaded[0].splitlines()[-1]
    assert leftovers == []


@pytest.mark.asyncio
async def test_file_without_strings_uploads_nothing_and_cleans_up(activity, tmp_path):
    source = tmp_path / "noise.bin"
    source.write_bytes(b"\x00\x01\x02\x03" * 100)
    result, storage, leftovers = await activity(source)
    assert result is None
    assert storage.uploaded == []
    assert leftovers == []

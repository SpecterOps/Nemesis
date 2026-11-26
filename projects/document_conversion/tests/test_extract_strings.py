"""extract_all_strings reads the `strings` output in chunks; the result must match a line-by-line filter."""

import io
import shutil
import subprocess
from unittest.mock import MagicMock, patch

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

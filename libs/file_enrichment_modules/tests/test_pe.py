# pyright: reportAttributeAccessIssue=false
import asyncio
import os
import time
from unittest.mock import MagicMock, patch

import lief
import pytest
from file_enrichment_modules.pe import analyzer as pe_analyzer
from file_enrichment_modules.pe.analyzer import PEAnalyzer, parse_pe_file, run_pydecipher

# Get the path to the fixtures directory
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "test_files")

# Test fixture: pyinstaller_packed.exe
# Source: https://github.com/pyinstxtractor/pyinstxtractor-test-binaries
# Binary: python2.7-pyinstaller2.1.exe
# This is a PyInstaller-packed Python 2.7 executable used for testing detection and unpacking.


class TestParsePeFile:
    """Tests for PE file parsing."""

    def test_parse_pe_file_pyinstaller(self):
        """Test parsing a PyInstaller-packed PE file."""
        test_file = os.path.join(FIXTURES_DIR, "pyinstaller_packed.exe")
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        result = parse_pe_file(test_file)

        assert result is not None
        assert isinstance(result, dict)
        assert "error" not in result, f"Unexpected error: {result.get('error')}"

        # Check general info
        assert result["general_info"]["is_32"] is True
        assert result["general_info"]["is_64"] is False
        assert result["general_info"]["has_imports"] is True
        assert result["general_info"]["has_resources"] is True

        # Check sections exist
        assert len(result["sections"]) > 0

        # Check imports exist
        assert len(result["imports"]) > 0


class TestPEAnalyzerPythonPacked:
    """Tests for PyInstaller/py2exe detection and unpacking."""

    @patch("file_enrichment_modules.pe.analyzer.StorageMinio")
    def test_is_python_packed_detects_pyinstaller(self, mock_storage_class):
        """Test that _is_python_packed detects PyInstaller executables."""
        mock_storage_class.return_value = MagicMock()

        test_file = os.path.join(FIXTURES_DIR, "pyinstaller_packed.exe")
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        analyzer = PEAnalyzer()

        # Read file bytes for YARA scanning
        with open(test_file, "rb") as f:
            file_bytes = f.read(1024 * 1024)  # Read up to 1MB

        is_packed = analyzer._is_python_packed(file_bytes)
        assert is_packed is True, "Should detect PyInstaller-packed executable"

    @patch("file_enrichment_modules.pe.analyzer.StorageMinio")
    def test_is_python_packed_rejects_normal_pe(self, mock_storage_class):
        """Test that _is_python_packed returns False for normal PE files."""
        mock_storage_class.return_value = MagicMock()

        analyzer = PEAnalyzer()

        # Create minimal PE header bytes (MZ header)
        # This is just enough to pass the uint16(0) == 0x5A4D check
        # but won't have PyInstaller/py2exe indicators
        minimal_pe = b"MZ" + b"\x00" * 1000

        is_packed = analyzer._is_python_packed(minimal_pe)
        assert is_packed is False, "Should not detect normal PE as Python-packed"

    @pytest.mark.asyncio
    @patch("file_enrichment_modules.pe.analyzer.StorageMinio")
    async def test_unpack_python_pe_extracts_files(self, mock_storage_class):
        """Test that _unpack_python_pe extracts Python files from PyInstaller executable."""
        mock_storage_class.return_value = MagicMock()

        test_file = os.path.join(FIXTURES_DIR, "pyinstaller_packed.exe")
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        analyzer = PEAnalyzer()
        log_file, py_files, output_dir = await analyzer._unpack_python_pe(test_file)

        try:
            # Should have a log file
            assert log_file is not None, "Should produce a log file"
            assert os.path.exists(log_file), "Log file should exist"

            # Should have extracted .py files (decompilation may fail for old Python versions,
            # but .py stub files are still created)
            assert len(py_files) > 0, "Should extract at least one .py file"

            # Output dir should exist
            assert output_dir is not None
            assert os.path.isdir(output_dir)

        finally:
            # Cleanup
            if output_dir:
                import shutil

                shutil.rmtree(output_dir, ignore_errors=True)

    @patch("file_enrichment_modules.pe.analyzer.StorageMinio")
    def test_create_unpacked_zip_creates_valid_zip(self, mock_storage_class):
        """Test that _create_unpacked_zip creates a valid zip file."""
        import tempfile
        import zipfile

        mock_storage_class.return_value = MagicMock()

        analyzer = PEAnalyzer()

        # Create temporary test files
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as log_f:
            log_f.write("Test log content")
            log_file = log_f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as py_f:
            py_f.write("print('hello')")
            py_file = py_f.name

        try:
            zip_path = analyzer._create_unpacked_zip(log_file, [py_file])

            assert zip_path is not None, "Should create zip file"
            assert os.path.exists(zip_path), "Zip file should exist"

            # Verify zip contents
            with zipfile.ZipFile(zip_path, "r") as zf:
                names = zf.namelist()
                assert len(names) == 2, "Zip should contain 2 files"
                assert os.path.basename(log_file) in names
                assert os.path.basename(py_file) in names

        finally:
            # Cleanup
            os.unlink(log_file)
            os.unlink(py_file)
            if zip_path and os.path.exists(zip_path):
                os.unlink(zip_path)

    @patch("file_enrichment_modules.pe.analyzer.StorageMinio")
    def test_create_unpacked_zip_returns_none_when_empty(self, mock_storage_class):
        """Test that _create_unpacked_zip returns None when no files provided."""
        mock_storage_class.return_value = MagicMock()

        analyzer = PEAnalyzer()

        zip_path = analyzer._create_unpacked_zip(None, [])
        assert zip_path is None, "Should return None when no files to zip"


class TestPEAnalyzerYaraRule:
    """Tests for the PE YARA detection rule."""

    @patch("file_enrichment_modules.pe.analyzer.StorageMinio")
    def test_yara_rule_detects_pe(self, mock_storage_class):
        """Test that the YARA rule detects valid PE files."""
        mock_storage_class.return_value = MagicMock()

        test_file = os.path.join(FIXTURES_DIR, "pyinstaller_packed.exe")
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        analyzer = PEAnalyzer()

        with open(test_file, "rb") as f:
            file_bytes = f.read(1000)

        matches = analyzer.yara_rule.scan(file_bytes).matching_rules
        assert len(matches) > 0, "Should detect as PE file"

    @patch("file_enrichment_modules.pe.analyzer.StorageMinio")
    def test_yara_rule_rejects_non_pe(self, mock_storage_class):
        """Test that the YARA rule rejects non-PE files."""
        mock_storage_class.return_value = MagicMock()

        analyzer = PEAnalyzer()

        # Plain text content
        non_pe_bytes = b"This is not a PE file, just plain text content."

        matches = analyzer.yara_rule.scan(non_pe_bytes).matching_rules
        assert len(matches) == 0, "Should not detect non-PE as PE file"


class TestPEFileLief:
    """Tests for LIEF PE parsing integration."""

    def test_lief_parses_pyinstaller_pe(self):
        """Test that LIEF can parse the PyInstaller PE file."""
        test_file = os.path.join(FIXTURES_DIR, "pyinstaller_packed.exe")
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        binary = lief.parse(test_file)

        assert binary is not None
        assert binary.header.machine == lief.PE.Header.MACHINE_TYPES.I386
        assert binary.has_imports
        assert binary.has_resources


# Stand-in for pydecipher: forks a worker (like its process pool) and both sleep; the worker writes its PID first
_HANGING_COMMAND = (
    "import os, sys, time\n"
    "pid = os.fork()\n"
    "if pid == 0:\n"
    "    open(sys.argv[3] + '/worker.pid', 'w').write(str(os.getpid()))\n"
    "time.sleep(60)\n"
)


def _wait_until_gone(pid: int, seconds: float = 5.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        try:  # reap if it is our child, otherwise it lingers as a zombie of init
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass
        time.sleep(0.05)
    return False


async def _worker_pid(output_dir, seconds: float = 5.0) -> int:
    path = output_dir / "worker.pid"
    for _ in range(int(seconds / 0.05)):
        if path.exists() and path.read_text():
            return int(path.read_text())
        await asyncio.sleep(0.05)
    raise AssertionError("worker never started")


class TestRunPydecipher:
    """pydecipher runs in its own process group so a hung unpack cannot block or outlive the caller."""

    @pytest.mark.asyncio
    async def test_timeout_kills_pydecipher_and_its_workers(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pe_analyzer, "_PYDECIPHER_COMMAND", _HANGING_COMMAND)
        run = asyncio.create_task(run_pydecipher("in.exe", str(tmp_path), timeout=2))
        worker = await _worker_pid(tmp_path)

        with pytest.raises(TimeoutError):
            await run
        assert _wait_until_gone(worker), "pool worker survived the timeout"

    @pytest.mark.asyncio
    async def test_cancellation_kills_pydecipher_and_its_workers(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pe_analyzer, "_PYDECIPHER_COMMAND", _HANGING_COMMAND)
        run = asyncio.create_task(run_pydecipher("in.exe", str(tmp_path), timeout=60))
        worker = await _worker_pid(tmp_path)

        run.cancel()
        with pytest.raises(asyncio.CancelledError):
            await run
        assert _wait_until_gone(worker), "pool worker survived cancellation"

    @pytest.mark.asyncio
    async def test_failure_raises_with_stderr(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pe_analyzer, "_PYDECIPHER_COMMAND", "import sys; sys.exit('not a PE file')")
        with pytest.raises(RuntimeError, match="code 1: not a PE file"):
            await run_pydecipher("in.exe", str(tmp_path), timeout=10)

    @pytest.mark.asyncio
    async def test_does_not_block_the_event_loop(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pe_analyzer, "_PYDECIPHER_COMMAND", "import time; time.sleep(1)")
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.05)
                ticks += 1

        tick_task = asyncio.create_task(ticker())
        await run_pydecipher("in.exe", str(tmp_path), timeout=10)
        tick_task.cancel()
        assert ticks >= 10

    @pytest.mark.asyncio
    @patch("file_enrichment_modules.pe.analyzer.StorageMinio")
    async def test_unpack_failure_returns_nothing_and_cleans_up(self, mock_storage_class, monkeypatch):
        mock_storage_class.return_value = MagicMock()
        made = []
        real_mkdtemp = pe_analyzer.tempfile.mkdtemp
        monkeypatch.setattr(pe_analyzer.tempfile, "mkdtemp", lambda **kw: made.append(real_mkdtemp(**kw)) or made[-1])

        async def failing(file_path, output_dir):
            raise TimeoutError

        monkeypatch.setattr(pe_analyzer, "run_pydecipher", failing)
        assert await PEAnalyzer()._unpack_python_pe("in.exe") == (None, [], None)
        assert not os.path.exists(made[0])

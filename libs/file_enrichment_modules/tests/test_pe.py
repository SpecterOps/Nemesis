# pyright: reportAttributeAccessIssue=false
import os
from unittest.mock import MagicMock, patch

import lief
from file_enrichment_modules.pe.analyzer import PEAnalyzer, parse_pe_file

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

    @patch("file_enrichment_modules.pe.analyzer.StorageMinio")
    def test_unpack_python_pe_extracts_files(self, mock_storage_class):
        """Test that _unpack_python_pe extracts Python files from PyInstaller executable."""
        mock_storage_class.return_value = MagicMock()

        test_file = os.path.join(FIXTURES_DIR, "pyinstaller_packed.exe")
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        analyzer = PEAnalyzer()
        log_file, py_files, output_dir = analyzer._unpack_python_pe(test_file)

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

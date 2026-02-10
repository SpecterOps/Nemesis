"""Tests for the Windows Prefetch analyzer module."""

import os

import pytest
from file_enrichment_modules.prefetch.analyzer import PrefetchAnalyzer

from tests.harness import FileEnrichedFactory, ModuleTestHarness

# Path to test fixtures
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "prefetch")

# Test files
CMD_PREFETCH = os.path.join(FIXTURES_DIR, "CMD.EXE-4A81B364.pf")  # Windows 8 (v26)


class TestPrefetchAnalyzer:
    """Tests for PrefetchAnalyzer."""

    @pytest.mark.asyncio
    async def test_should_process_pf_extension(self):
        """Test that should_process returns True for .pf files."""
        harness = ModuleTestHarness()

        harness.register_file(
            object_id="test-cmd-pf",
            local_path=CMD_PREFETCH,
            file_enriched=FileEnrichedFactory.create(
                object_id="test-cmd-pf",
                file_name="CMD.EXE-4A81B364.pf",
                size=os.path.getsize(CMD_PREFETCH),
                magic_type="data",
                mime_type="application/octet-stream",
            ),
        )

        async with harness.create_module(PrefetchAnalyzer) as module:
            result = await module.should_process("test-cmd-pf", CMD_PREFETCH)
            assert result is True

    @pytest.mark.asyncio
    async def test_should_process_yara_detection_no_extension(self):
        """Test that YARA detection works for files without .pf extension."""
        harness = ModuleTestHarness()

        # Register with a different extension to force YARA detection
        harness.register_file(
            object_id="test-no-ext",
            local_path=CMD_PREFETCH,
            file_enriched=FileEnrichedFactory.create(
                object_id="test-no-ext",
                file_name="suspicious_file.dat",  # No .pf extension
                size=os.path.getsize(CMD_PREFETCH),
                magic_type="data",
                mime_type="application/octet-stream",
            ),
        )

        async with harness.create_module(PrefetchAnalyzer) as module:
            result = await module.should_process("test-no-ext", CMD_PREFETCH)
            assert result is True

    @pytest.mark.asyncio
    async def test_should_not_process_unrelated_file(self):
        """Test that should_process returns False for non-prefetch files."""
        harness = ModuleTestHarness()

        # Create a simple text file for testing
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("This is not a prefetch file")
            temp_path = f.name

        try:
            harness.register_file(
                object_id="test-txt",
                local_path=temp_path,
                file_enriched=FileEnrichedFactory.create_plaintext_file(
                    object_id="test-txt",
                    file_name="readme.txt",
                ),
            )

            async with harness.create_module(PrefetchAnalyzer) as module:
                result = await module.should_process("test-txt", temp_path)
                assert result is False
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_process_windows8_prefetch(self):
        """Test processing Windows 8 uncompressed prefetch file."""
        harness = ModuleTestHarness()

        harness.register_file(
            object_id="test-cmd-pf",
            local_path=CMD_PREFETCH,
            file_enriched=FileEnrichedFactory.create(
                object_id="test-cmd-pf",
                file_name="CMD.EXE-4A81B364.pf",
                size=os.path.getsize(CMD_PREFETCH),
                magic_type="data",
                mime_type="application/octet-stream",
            ),
        )

        async with harness.create_module(PrefetchAnalyzer) as module:
            result = await module.process("test-cmd-pf", CMD_PREFETCH)

            assert result is not None
            assert result.module_name == "prefetch_analyzer"

            # Check parsed data
            assert result.results is not None
            assert result.results["executable_name"] == "CMD.EXE"
            assert result.results["format_version"] == 26
            assert result.results["prefetch_hash"] == "0x4a81b364"
            assert result.results["run_count"] == 2
            assert len(result.results["last_run_times"]) > 0
            assert len(result.results["volumes"]) > 0
            assert len(result.results["filenames"]) > 0

            # No findings should be generated (parse only)
            assert len(result.findings) == 0

            # Check transforms
            assert len(result.transforms) == 1
            assert result.transforms[0].type == "prefetch_analysis"

    @pytest.mark.asyncio
    async def test_results_contain_execution_data(self):
        """Test that the results contain proper execution data."""
        harness = ModuleTestHarness()

        harness.register_file(
            object_id="test-cmd-pf",
            local_path=CMD_PREFETCH,
            file_enriched=FileEnrichedFactory.create(
                object_id="test-cmd-pf",
                file_name="CMD.EXE-4A81B364.pf",
                size=os.path.getsize(CMD_PREFETCH),
            ),
        )

        async with harness.create_module(PrefetchAnalyzer) as module:
            result = await module.process("test-cmd-pf", CMD_PREFETCH)

            assert result is not None
            # No findings should be generated
            assert len(result.findings) == 0

            # Verify results contain expected fields
            assert "executable_name" in result.results
            assert "run_count" in result.results
            assert "last_run_times" in result.results
            assert "volumes" in result.results
            assert "filenames" in result.results

    @pytest.mark.asyncio
    async def test_volume_information_extracted(self):
        """Test that volume information is properly extracted."""
        harness = ModuleTestHarness()

        harness.register_file(
            object_id="test-cmd-pf",
            local_path=CMD_PREFETCH,
            file_enriched=FileEnrichedFactory.create(
                object_id="test-cmd-pf",
                file_name="CMD.EXE-4A81B364.pf",
                size=os.path.getsize(CMD_PREFETCH),
            ),
        )

        async with harness.create_module(PrefetchAnalyzer) as module:
            result = await module.process("test-cmd-pf", CMD_PREFETCH)

            assert result is not None
            volumes = result.results["volumes"]
            assert len(volumes) >= 1

            # Check volume structure
            vol = volumes[0]
            assert "device_path" in vol
            assert "serial_number" in vol
            assert vol["device_path"].startswith("\\DEVICE\\")

    @pytest.mark.asyncio
    async def test_filenames_extracted(self):
        """Test that accessed filenames are extracted."""
        harness = ModuleTestHarness()

        harness.register_file(
            object_id="test-cmd-pf",
            local_path=CMD_PREFETCH,
            file_enriched=FileEnrichedFactory.create(
                object_id="test-cmd-pf",
                file_name="CMD.EXE-4A81B364.pf",
                size=os.path.getsize(CMD_PREFETCH),
            ),
        )

        async with harness.create_module(PrefetchAnalyzer) as module:
            result = await module.process("test-cmd-pf", CMD_PREFETCH)

            assert result is not None
            filenames = result.results["filenames"]
            assert len(filenames) > 0

            # CMD.EXE should reference NTDLL.DLL and KERNEL32.DLL
            filenames_upper = [f.upper() for f in filenames]
            assert any("NTDLL.DLL" in f for f in filenames_upper)
            assert any("KERNEL32.DLL" in f for f in filenames_upper)


class TestPrefetchAnalyzerEdgeCases:
    """Edge case tests for PrefetchAnalyzer."""

    @pytest.mark.asyncio
    async def test_transform_created_with_markdown(self):
        """Test that a markdown transform is created."""
        harness = ModuleTestHarness()

        harness.register_file(
            object_id="test-cmd-pf",
            local_path=CMD_PREFETCH,
            file_enriched=FileEnrichedFactory.create(
                object_id="test-cmd-pf",
                file_name="CMD.EXE-4A81B364.pf",
                size=os.path.getsize(CMD_PREFETCH),
            ),
        )

        async with harness.create_module(PrefetchAnalyzer) as module:
            result = await module.process("test-cmd-pf", CMD_PREFETCH)

            assert result is not None
            assert len(result.transforms) == 1

            transform = result.transforms[0]
            assert transform.metadata["display_type_in_dashboard"] == "markdown"
            assert transform.metadata["default_display"] is True
            assert transform.metadata["file_name"].endswith("_analysis.md")

    @pytest.mark.asyncio
    async def test_windows_version_mapping(self):
        """Test that Windows version is correctly mapped from format version."""
        harness = ModuleTestHarness()

        # Test Windows 8 (v26)
        harness.register_file(
            object_id="test-v26",
            local_path=CMD_PREFETCH,
            file_enriched=FileEnrichedFactory.create(
                object_id="test-v26",
                file_name="CMD.EXE-4A81B364.pf",
                size=os.path.getsize(CMD_PREFETCH),
            ),
        )

        async with harness.create_module(PrefetchAnalyzer) as module:
            result = await module.process("test-v26", CMD_PREFETCH)
            assert result.results["windows_version"] == "Windows 8/8.1"

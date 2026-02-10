# tests/test_ccache.py
"""Tests for the Kerberos credential cache (ccache) analyzer module."""

import os

import pytest
from file_enrichment_modules.ccache.analyzer import CcacheAnalyzer

from tests.harness import FileEnrichedFactory, ModuleTestHarness

# Path to the test ccache file in fixtures
TEST_CCACHE_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "administrator.ccache")


class TestCcacheAnalyzer:
    """Tests for CcacheAnalyzer."""

    @pytest.fixture
    def ccache_file_enriched(self) -> dict:
        """Create file_enriched data for a ccache file."""
        return FileEnrichedFactory.create(
            object_id="test-ccache-uuid",
            file_name="administrator.ccache",
            extension=".ccache",
            size=1515,
            magic_type="data",
            mime_type="application/octet-stream",
        )

    @pytest.fixture
    def krb5cc_file_enriched(self) -> dict:
        """Create file_enriched data for a krb5cc_ prefixed file."""
        return FileEnrichedFactory.create(
            object_id="test-krb5cc-uuid",
            file_name="krb5cc_1000",
            extension=None,
            size=1515,
            magic_type="data",
            mime_type="application/octet-stream",
        )

    @pytest.fixture
    def plaintext_file_enriched(self) -> dict:
        """Create file_enriched data for an unrelated plaintext file."""
        return FileEnrichedFactory.create_plaintext_file(
            object_id="test-txt-uuid",
            file_name="readme.txt",
        )

    @pytest.mark.asyncio
    async def test_should_process_ccache_extension(self, ccache_file_enriched):
        """Test should_process returns True for .ccache files."""
        if not os.path.exists(TEST_CCACHE_PATH):
            pytest.skip(f"Test file not found: {TEST_CCACHE_PATH}")

        harness = ModuleTestHarness()
        harness.register_file(
            object_id="test-ccache-uuid",
            local_path=TEST_CCACHE_PATH,
            file_enriched=ccache_file_enriched,
        )

        async with harness.create_module(CcacheAnalyzer) as module:
            result = await module.should_process("test-ccache-uuid", TEST_CCACHE_PATH)
            assert result is True

    @pytest.mark.asyncio
    async def test_should_process_krb5cc_prefix(self, krb5cc_file_enriched):
        """Test should_process returns True for krb5cc_ prefixed files."""
        if not os.path.exists(TEST_CCACHE_PATH):
            pytest.skip(f"Test file not found: {TEST_CCACHE_PATH}")

        harness = ModuleTestHarness()
        harness.register_file(
            object_id="test-krb5cc-uuid",
            local_path=TEST_CCACHE_PATH,
            file_enriched=krb5cc_file_enriched,
        )

        async with harness.create_module(CcacheAnalyzer) as module:
            result = await module.should_process("test-krb5cc-uuid", TEST_CCACHE_PATH)
            assert result is True

    @pytest.mark.asyncio
    async def test_should_process_yara_detection(self):
        """Test should_process returns True via YARA magic bytes detection."""
        if not os.path.exists(TEST_CCACHE_PATH):
            pytest.skip(f"Test file not found: {TEST_CCACHE_PATH}")

        # File with non-standard name but ccache magic bytes
        file_enriched = FileEnrichedFactory.create(
            object_id="test-magic-uuid",
            file_name="mysterious_file",  # No extension, no krb5cc prefix
            extension=None,
            size=1515,
            magic_type="data",
            mime_type="application/octet-stream",
        )

        harness = ModuleTestHarness()
        harness.register_file(
            object_id="test-magic-uuid",
            local_path=TEST_CCACHE_PATH,
            file_enriched=file_enriched,
        )

        async with harness.create_module(CcacheAnalyzer) as module:
            result = await module.should_process("test-magic-uuid", TEST_CCACHE_PATH)
            assert result is True

    @pytest.mark.asyncio
    async def test_should_not_process_unrelated_file(self, plaintext_file_enriched, tmp_path):
        """Test should_process returns False for unrelated files."""
        # Create a temporary plaintext file
        txt_file = tmp_path / "readme.txt"
        txt_file.write_text("This is just a readme file.")

        harness = ModuleTestHarness()
        harness.register_file(
            object_id="test-txt-uuid",
            local_path=str(txt_file),
            file_enriched=plaintext_file_enriched,
        )

        async with harness.create_module(CcacheAnalyzer) as module:
            result = await module.should_process("test-txt-uuid", str(txt_file))
            assert result is False

    @pytest.mark.asyncio
    async def test_process_extracts_credentials(self, ccache_file_enriched):
        """Test process extracts credential information from ccache file."""
        if not os.path.exists(TEST_CCACHE_PATH):
            pytest.skip(f"Test file not found: {TEST_CCACHE_PATH}")

        harness = ModuleTestHarness()
        harness.register_file(
            object_id="test-ccache-uuid",
            local_path=TEST_CCACHE_PATH,
            file_enriched=ccache_file_enriched,
        )

        async with harness.create_module(CcacheAnalyzer) as module:
            result = await module.process("test-ccache-uuid", TEST_CCACHE_PATH)

            assert result is not None
            assert result.module_name == "ccache_analyzer"

            # Check results contain parsed data
            assert "principal" in result.results
            assert "credentials" in result.results
            assert result.results["total_credentials"] > 0

            # Verify principal is extracted
            principal = result.results["principal"]
            assert "administrator" in principal.lower() or "TESTDOMAIN" in principal.upper()

    @pytest.mark.asyncio
    async def test_process_creates_transform(self, ccache_file_enriched):
        """Test process creates markdown summary transform."""
        if not os.path.exists(TEST_CCACHE_PATH):
            pytest.skip(f"Test file not found: {TEST_CCACHE_PATH}")

        harness = ModuleTestHarness()
        harness.register_file(
            object_id="test-ccache-uuid",
            local_path=TEST_CCACHE_PATH,
            file_enriched=ccache_file_enriched,
        )

        async with harness.create_module(CcacheAnalyzer) as module:
            result = await module.process("test-ccache-uuid", TEST_CCACHE_PATH)

            assert result is not None
            assert len(result.transforms) > 0

            # Check transform metadata
            transform = result.transforms[0]
            assert transform.type == "finding_summary"
            assert transform.metadata["display_type_in_dashboard"] == "markdown"
            assert transform.metadata["default_display"] is True

    @pytest.mark.asyncio
    async def test_process_credential_details(self, ccache_file_enriched):
        """Test process extracts detailed credential information."""
        if not os.path.exists(TEST_CCACHE_PATH):
            pytest.skip(f"Test file not found: {TEST_CCACHE_PATH}")

        harness = ModuleTestHarness()
        harness.register_file(
            object_id="test-ccache-uuid",
            local_path=TEST_CCACHE_PATH,
            file_enriched=ccache_file_enriched,
        )

        async with harness.create_module(CcacheAnalyzer) as module:
            result = await module.process("test-ccache-uuid", TEST_CCACHE_PATH)

            assert result is not None

            # Check credential details
            credentials = result.results["credentials"]
            assert len(credentials) > 0

            cred = credentials[0]
            assert "client" in cred
            assert "server" in cred
            assert "encryption_type" in cred
            assert "encryption_type_name" in cred
            assert "endtime" in cred
            assert "flags" in cred
            assert "is_tgt" in cred

    @pytest.mark.asyncio
    async def test_hybrid_mode_finding_for_unexpired_tickets(self, ccache_file_enriched):
        """Test hybrid mode: findings generated only for unexpired tickets."""
        if not os.path.exists(TEST_CCACHE_PATH):
            pytest.skip(f"Test file not found: {TEST_CCACHE_PATH}")

        harness = ModuleTestHarness()
        harness.register_file(
            object_id="test-ccache-uuid",
            local_path=TEST_CCACHE_PATH,
            file_enriched=ccache_file_enriched,
        )

        async with harness.create_module(CcacheAnalyzer) as module:
            result = await module.process("test-ccache-uuid", TEST_CCACHE_PATH)

            assert result is not None

            # Check if there are unexpired credentials
            unexpired_count = result.results.get("unexpired_count", 0)

            if unexpired_count > 0:
                # Should have findings for unexpired tickets
                assert len(result.findings) > 0
                finding = result.findings[0]
                assert finding.category.value == "credential"
                assert finding.finding_name == "kerberos_ccache_active_tickets"
                assert finding.severity >= 6  # High severity
            else:
                # Expired tickets should not generate findings
                assert len(result.findings) == 0


class TestCcacheAnalyzerEdgeCases:
    """Edge case tests for CcacheAnalyzer."""

    @pytest.mark.asyncio
    async def test_invalid_file_content(self, tmp_path):
        """Test handling of invalid/corrupted ccache file."""
        # Create a file with ccache magic but corrupted content
        invalid_ccache = tmp_path / "invalid.ccache"
        invalid_ccache.write_bytes(b"\x05\x04" + b"\x00" * 100)  # Magic + garbage

        file_enriched = FileEnrichedFactory.create(
            object_id="test-invalid-uuid",
            file_name="invalid.ccache",
            extension=".ccache",
            size=102,
            magic_type="data",
            mime_type="application/octet-stream",
        )

        harness = ModuleTestHarness()
        harness.register_file(
            object_id="test-invalid-uuid",
            local_path=str(invalid_ccache),
            file_enriched=file_enriched,
        )

        async with harness.create_module(CcacheAnalyzer) as module:
            # Should process (has .ccache extension)
            should_run = await module.should_process("test-invalid-uuid", str(invalid_ccache))
            assert should_run is True

            # Process should handle error gracefully and return error transform
            result = await module.process("test-invalid-uuid", str(invalid_ccache))
            assert result is not None
            # Should have error transform
            assert len(result.transforms) > 0

    @pytest.mark.asyncio
    async def test_empty_file(self, tmp_path):
        """Test handling of empty file with .ccache extension."""
        empty_ccache = tmp_path / "empty.ccache"
        empty_ccache.write_bytes(b"")

        file_enriched = FileEnrichedFactory.create(
            object_id="test-empty-uuid",
            file_name="empty.ccache",
            extension=".ccache",
            size=0,
            magic_type="empty",
            mime_type="application/octet-stream",
        )

        harness = ModuleTestHarness()
        harness.register_file(
            object_id="test-empty-uuid",
            local_path=str(empty_ccache),
            file_enriched=file_enriched,
        )

        async with harness.create_module(CcacheAnalyzer) as module:
            # Should process (has .ccache extension)
            should_run = await module.should_process("test-empty-uuid", str(empty_ccache))
            assert should_run is True

            # Process should handle gracefully
            result = await module.process("test-empty-uuid", str(empty_ccache))
            assert result is not None

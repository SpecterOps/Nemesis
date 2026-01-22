"""Integration tests to verify the harness works with real enrichment modules."""

import os
import tempfile

import pytest

from .harness import FileEnrichedFactory, ModuleTestHarness


class TestHarnessWithGitCredentials:
    """Test the harness with the gitcredentials module."""

    @pytest.mark.asyncio
    async def test_should_process_git_credentials_file(self):
        """Test that gitcredentials module correctly identifies target files."""
        from file_enrichment_modules.gitcredentials.analyzer import GitCredentialsParser

        harness = ModuleTestHarness()

        # Create a test .git-credentials file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".git-credentials", delete=False) as f:
            f.write("https://user:token123@github.com\n")
            temp_path = f.name

        try:
            harness.register_file(
                object_id="test-git-creds",
                local_path=temp_path,
                file_enriched=FileEnrichedFactory.create_plaintext_file(
                    object_id="test-git-creds",
                    file_name=".git-credentials",
                    size=os.path.getsize(temp_path),
                ),
            )

            async with harness.create_module(GitCredentialsParser) as module:
                result = await module.should_process("test-git-creds")
                assert result is True
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_should_not_process_unrelated_file(self):
        """Test that gitcredentials module ignores unrelated files."""
        from file_enrichment_modules.gitcredentials.analyzer import GitCredentialsParser

        harness = ModuleTestHarness()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("just some text\n")
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

            async with harness.create_module(GitCredentialsParser) as module:
                result = await module.should_process("test-txt")
                assert result is False
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_process_extracts_credentials(self):
        """Test that gitcredentials module extracts credentials correctly."""
        from file_enrichment_modules.gitcredentials.analyzer import GitCredentialsParser

        harness = ModuleTestHarness()

        # Create a test .git-credentials file with actual credentials
        with tempfile.NamedTemporaryFile(mode="w", suffix=".git-credentials", delete=False) as f:
            f.write("https://testuser:secrettoken123@github.com\n")
            f.write("https://anotheruser:anothertoken@gitlab.com/path\n")
            temp_path = f.name

        try:
            harness.register_file(
                object_id="test-git-creds",
                local_path=temp_path,
                file_enriched=FileEnrichedFactory.create_plaintext_file(
                    object_id="test-git-creds",
                    file_name=".git-credentials",
                    size=os.path.getsize(temp_path),
                ),
            )

            async with harness.create_module(GitCredentialsParser) as module:
                result = await module.process("test-git-creds", temp_path)

                assert result is not None
                assert result.module_name == "git_credentials_parser"

                # Check findings
                assert len(result.findings) == 1
                finding = result.findings[0]
                assert finding.category.value == "credential"
                assert finding.severity == 7

                # Check raw data
                creds = finding.raw_data["credentials"]
                assert len(creds) == 2
                assert creds[0]["username"] == "testuser"
                assert creds[0]["token"] == "secrettoken123"
                assert creds[0]["target_server"] == "github.com"
                assert creds[1]["username"] == "anotheruser"

                # Check transforms were created
                assert len(result.transforms) == 1
                assert result.transforms[0].type == "displayable_parsed"

                # Verify a file was uploaded to mock storage
                uploaded = harness.get_uploaded_paths()
                assert len(uploaded) == 1

        finally:
            os.unlink(temp_path)


class TestHarnessWithContainer:
    """Test the harness with the container module."""

    @pytest.mark.asyncio
    async def test_should_process_zip_file(self):
        """Test that container module correctly identifies zip files."""
        from file_enrichment_modules.container.analyzer import ContainerAnalyzer

        harness = ModuleTestHarness()

        # Create a minimal valid zip file
        import zipfile

        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            temp_path = f.name

        try:
            with zipfile.ZipFile(temp_path, "w") as zf:
                zf.writestr("test.txt", "Hello, World!")

            harness.register_file(
                object_id="test-zip",
                local_path=temp_path,
                file_enriched=FileEnrichedFactory.create_zip_file(
                    object_id="test-zip",
                    file_name="archive.zip",
                    size=os.path.getsize(temp_path),
                ),
            )

            async with harness.create_module(ContainerAnalyzer) as module:
                result = await module.should_process("test-zip")
                assert result is True
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_process_lists_zip_contents(self):
        """Test that container module lists zip contents."""
        from file_enrichment_modules.container.analyzer import ContainerAnalyzer

        harness = ModuleTestHarness()

        import zipfile

        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            temp_path = f.name

        try:
            with zipfile.ZipFile(temp_path, "w") as zf:
                zf.writestr("file1.txt", "Content 1")
                zf.writestr("subdir/file2.txt", "Content 2")

            harness.register_file(
                object_id="test-zip",
                local_path=temp_path,
                file_enriched=FileEnrichedFactory.create_zip_file(
                    object_id="test-zip",
                    file_name="archive.zip",
                    size=os.path.getsize(temp_path),
                ),
            )

            async with harness.create_module(ContainerAnalyzer) as module:
                result = await module.process("test-zip", temp_path)

                assert result is not None
                assert result.module_name == "container_analyzer"

                # Container module creates a transform with the contents listing
                assert len(result.transforms) == 1
                assert result.transforms[0].type == "container_contents"
                assert "markdown" in result.transforms[0].metadata.get("display_type_in_dashboard", "")

        finally:
            os.unlink(temp_path)


class TestHarnessWithKeytab:
    """Test the harness with the keytab module (uses YARA detection)."""

    @pytest.mark.asyncio
    async def test_should_process_keytab_by_extension(self):
        """Test that keytab module detects files by extension."""
        from file_enrichment_modules.keytab.analyzer import KeytabAnalyzer

        harness = ModuleTestHarness()

        # Create a dummy file with .keytab extension
        with tempfile.NamedTemporaryFile(suffix=".keytab", delete=False) as f:
            f.write(b"\x00\x00\x00\x00")  # Not a valid keytab, but has the extension
            temp_path = f.name

        try:
            harness.register_file(
                object_id="test-keytab",
                local_path=temp_path,
                file_enriched=FileEnrichedFactory.create_keytab_file(
                    object_id="test-keytab",
                    file_name="krb5.keytab",
                    size=os.path.getsize(temp_path),
                ),
            )

            async with harness.create_module(KeytabAnalyzer) as module:
                # Should detect by extension alone
                result = await module.should_process("test-keytab")
                assert result is True
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_should_process_keytab_by_magic(self):
        """Test that keytab module detects files by YARA magic bytes."""
        from file_enrichment_modules.keytab.analyzer import KeytabAnalyzer

        harness = ModuleTestHarness()

        # Create a file with keytab magic bytes but wrong extension
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x05\x02")  # Keytab magic bytes
            f.write(b"\x00" * 100)  # Some padding
            temp_path = f.name

        try:
            harness.register_file(
                object_id="test-keytab-magic",
                local_path=temp_path,
                file_enriched=FileEnrichedFactory.create(
                    object_id="test-keytab-magic",
                    file_name="unknown.bin",
                    size=os.path.getsize(temp_path),
                ),
            )

            async with harness.create_module(KeytabAnalyzer) as module:
                # Should detect by YARA rule
                result = await module.should_process("test-keytab-magic", temp_path)
                assert result is True
        finally:
            os.unlink(temp_path)

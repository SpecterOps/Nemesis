"""Tests for publish_enriched activity functions."""

import sys
from datetime import datetime, timedelta
from unittest.mock import MagicMock

from common.models import FileEnriched, FileHashes

# Mock the global_vars module to avoid Dapr initialization during import
sys.modules["file_enrichment.global_vars"] = MagicMock()

from file_enrichment.activities.publish_enriched import should_convert_document  # noqa: E402


class TestShouldConvertDocument:
    """Test cases for should_convert_document function."""

    def create_file_enriched(
        self,
        is_plaintext: bool = False,
        originating_object_id: str | None = None,
        nesting_level: int | None = None,
    ) -> FileEnriched:
        """Helper to create a FileEnriched object for testing."""
        return FileEnriched(
            object_id="test-object-123",
            agent_id="test-agent",
            project="test-project",
            timestamp=datetime.now(),
            expiration=datetime.now() + timedelta(days=30),
            path="/test/path/file.txt",
            file_name="file.txt",
            extension="txt",
            size=1024,
            hashes=FileHashes(
                md5="d41d8cd98f00b204e9800998ecf8427e",
                sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
                sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            magic_type="text/plain",
            mime_type="text/plain",
            is_plaintext=is_plaintext,
            is_container=False,
            originating_object_id=originating_object_id,
            nesting_level=nesting_level,
        )

    def test_plaintext_file_should_not_convert(self):
        """Test that plaintext files are not converted."""
        file = self.create_file_enriched(is_plaintext=True)
        assert should_convert_document(file) is False

    def test_original_submission_without_originating_id_should_convert(self):
        """Test that original submissions (no originating_object_id) should be converted."""
        file = self.create_file_enriched(
            is_plaintext=False,
            originating_object_id=None,
        )
        assert should_convert_document(file) is True

    def test_derived_file_with_zero_nesting_level_should_not_convert(self):
        """
        Test that files with originating_object_id and nesting_level=0 should not convert.
        """
        file = self.create_file_enriched(
            is_plaintext=False,
            originating_object_id="parent-123",
            nesting_level=0,
        )
        assert should_convert_document(file) is False

    def test_extracted_file_with_positive_nesting_level_should_convert(self):
        """
        Test that files extracted from containers (nesting_level > 0) should be converted.
        """
        file = self.create_file_enriched(
            is_plaintext=False,
            originating_object_id="container-123",
            nesting_level=1,
        )
        assert should_convert_document(file) is True

    def test_deeply_nested_file_should_convert(self):
        """Test that deeply nested files (nesting_level > 1) should be converted."""
        file = self.create_file_enriched(
            is_plaintext=False,
            originating_object_id="container-123",
            nesting_level=3,
        )
        assert should_convert_document(file) is True

    def test_plaintext_takes_precedence_over_other_conditions(self):
        """
        Test that is_plaintext=True causes the function to return False
        regardless of other conditions.
        """
        # Even with nesting_level > 0, plaintext files should not convert
        file = self.create_file_enriched(
            is_plaintext=True,
            originating_object_id="container-123",
            nesting_level=2,
        )
        assert should_convert_document(file) is False

        # Even without originating_object_id, plaintext files should not convert
        file = self.create_file_enriched(
            is_plaintext=True,
            originating_object_id=None,
        )
        assert should_convert_document(file) is False

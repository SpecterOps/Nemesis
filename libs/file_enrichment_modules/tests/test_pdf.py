import os

from file_enrichment_modules.pdf.analyzer import parse_pdf_file

# Get the path to the fixtures directory
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "test_files")


class TestParsePdfFile:
    """Tests for PDF file parsing and metadata extraction."""

    def test_parse_pdf_file_unencrypted(self):
        """Test parsing an unencrypted PDF file with metadata."""
        # Arrange
        test_file = os.path.join(FIXTURES_DIR, "pdf_test.pdf")

        # Verify the test file exists
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        # Act
        result = parse_pdf_file(test_file)

        # Assert
        assert result is not None, "Result should not be None"
        assert isinstance(result, dict), "Result should be a dictionary"

        # Check basic properties
        assert result["is_encrypted"] is False, "PDF should not be encrypted"
        assert result["num_pages"] == 1, "PDF should have 1 page"
        assert result["pdf_version"] == "1.3", f"Expected PDF version 1.3, got {result['pdf_version']}"
        assert result["is_linearized"] is False, "PDF should not be linearized"
        assert result["encryption_hash"] is None, "Non-encrypted PDF should have no encryption hash"

        # Check metadata fields (nested in metadata dict)
        metadata = result["metadata"]
        assert metadata["title"] == "Microsoft Word - Document4", f"Expected title 'Microsoft Word - Document4', got {metadata['title']}"
        assert metadata["producer"] == "macOS Version 12.6 (Build 21G115) Quartz PDFContext", f"Expected specific producer, got {metadata['producer']}"
        assert metadata["creator"] == "Word", f"Expected creator 'Word', got {metadata['creator']}"

        # Check dates are properly parsed
        assert metadata["created"] is not None, "Created date should not be None"
        assert metadata["modified"] is not None, "Modified date should not be None"
        assert metadata["created"].startswith("2023-03-24"), f"Expected creation date to start with 2023-03-24, got {metadata['created']}"
        assert metadata["modified"].startswith("2023-03-24"), f"Expected modification date to start with 2023-03-24, got {metadata['modified']}"

        # Check page size
        assert result["page_size"] is not None, "Page size should not be None"
        assert "width" in result["page_size"], "Page size should have width"
        assert "height" in result["page_size"], "Page size should have height"
        assert result["page_size"]["unit"] == "points", "Page size unit should be points"
        # Standard US Letter size is 612x792 points
        assert result["page_size"]["width"] == 612.0, f"Expected width 612.0, got {result['page_size']['width']}"
        assert result["page_size"]["height"] == 792.0, f"Expected height 792.0, got {result['page_size']['height']}"

        # Check new extended metadata fields
        assert result["page_layout"] == "SinglePage", f"Expected page_layout 'SinglePage', got {result['page_layout']}"
        assert result["page_mode"] == "UseNone", f"Expected page_mode 'UseNone', got {result['page_mode']}"
        assert result["page_rotation"] == 0, f"Expected page_rotation 0, got {result['page_rotation']}"
        assert result["is_repaired"] is False, "PDF should not be repaired"

        # Check no error occurred
        assert "error" not in result, f"Unexpected error in result: {result.get('error')}"

    def test_parse_pdf_file_encrypted_v1_6(self):
        """Test parsing an encrypted PDF file (version 1.6)."""
        # Arrange
        test_file = os.path.join(FIXTURES_DIR, "enc_pdf_test.pdf")

        # Verify the test file exists
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        # Act
        result = parse_pdf_file(test_file)

        # Assert
        assert result is not None, "Result should not be None"
        assert isinstance(result, dict), "Result should be a dictionary"

        # Check encryption properties
        assert result["is_encrypted"] is True, "PDF should be encrypted"
        assert result["pdf_version"] == "1.6", f"Expected PDF version 1.6, got {result['pdf_version']}"
        assert result["is_linearized"] is False, "PDF should not be linearized"
        assert result["num_pages"] == 1, "PDF should have 1 page"

        # Check encryption hash is extracted
        assert result["encryption_hash"] is not None, "Encrypted PDF should have an encryption hash"
        assert isinstance(result["encryption_hash"], str), "Encryption hash should be a string"
        assert len(result["encryption_hash"]) > 0, "Encryption hash should not be empty"
        # PDF hashes typically start with "$pdf$" for hashcat format
        assert result["encryption_hash"].startswith("$pdf$"), (
            f"Expected hash to start with '$pdf$', got: {result['encryption_hash'][:20]}"
        )

        # Encrypted PDFs typically don't expose metadata without decryption
        # So these fields should be None or default values in the metadata dict
        metadata = result["metadata"]
        assert metadata["title"] is None, "Encrypted PDF should not expose title without decryption"
        assert metadata["author"] is None, "Encrypted PDF should not expose author without decryption"

    def test_parse_pdf_file_encrypted_v1_7(self):
        """Test parsing an encrypted PDF file (version 1.7)."""
        # Arrange
        test_file = os.path.join(FIXTURES_DIR, "enc_pdf_uncrackable.pdf")

        # Verify the test file exists
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        # Act
        result = parse_pdf_file(test_file)

        # Assert
        assert result is not None, "Result should not be None"
        assert isinstance(result, dict), "Result should be a dictionary"

        # Check encryption properties
        assert result["is_encrypted"] is True, "PDF should be encrypted"
        assert result["pdf_version"] == "1.7", f"Expected PDF version 1.7, got {result['pdf_version']}"
        assert result["is_linearized"] is False, "PDF should not be linearized"

        # Check encryption hash is extracted
        assert result["encryption_hash"] is not None, "Encrypted PDF should have an encryption hash"
        assert isinstance(result["encryption_hash"], str), "Encryption hash should be a string"
        assert len(result["encryption_hash"]) > 0, "Encryption hash should not be empty"

    def test_parse_pdf_file_all_required_fields_present(self):
        """Test that all expected fields are present in the result, regardless of encryption status."""
        # Test with an unencrypted PDF
        test_file = os.path.join(FIXTURES_DIR, "pdf_test.pdf")
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        result = parse_pdf_file(test_file)

        # All these fields should always be present in the result dictionary
        required_top_level_fields = [
            "is_encrypted",
            "encryption_hash",
            "num_pages",
            "pdf_version",
            "page_size",
            "page_layout",
            "page_mode",
            "language",
            "is_pdf_a",
            "is_linearized",
            "is_repaired",
            "has_embedded_files",
            "has_forms",
            "permissions",
            "page_rotation",
            "metadata",
        ]

        for field in required_top_level_fields:
            assert field in result, f"Required field '{field}' is missing from result"

        # Check metadata sub-fields
        required_metadata_fields = [
            "title",
            "author",
            "subject",
            "creator",
            "producer",
            "created",
            "modified",
            "keywords",
            "trapped",
            "encryption_method",
        ]

        for field in required_metadata_fields:
            assert field in result["metadata"], f"Required metadata field '{field}' is missing from result"

    def test_parse_pdf_file_nonexistent_file(self):
        """Test that the function handles non-existent files gracefully."""
        # Arrange
        nonexistent_file = os.path.join(FIXTURES_DIR, "nonexistent_file.pdf")

        # Act
        result = parse_pdf_file(nonexistent_file)

        # Assert
        assert result is not None, "Result should not be None even for non-existent file"
        assert isinstance(result, dict), "Result should be a dictionary"
        assert "error" in result, "Result should contain an error message"
        assert len(result["error"]) > 0, "Error message should not be empty"

    def test_parse_pdf_file_page_count(self):
        """Test that page count is correctly extracted."""
        # Test with unencrypted PDF (1 page)
        test_file = os.path.join(FIXTURES_DIR, "pdf_test.pdf")
        result = parse_pdf_file(test_file)
        assert result["num_pages"] == 1, f"Expected 1 page, got {result['num_pages']}"

        # Test with encrypted PDF v1.6 (1 page)
        test_file = os.path.join(FIXTURES_DIR, "enc_pdf_test.pdf")
        result = parse_pdf_file(test_file)
        assert result["num_pages"] == 1, f"Expected 1 page, got {result['num_pages']}"

    def test_parse_pdf_file_embedded_files_detection(self):
        """Test that embedded files detection works."""
        # Test with standard PDFs (should have no embedded files)
        test_file = os.path.join(FIXTURES_DIR, "pdf_test.pdf")
        result = parse_pdf_file(test_file)
        assert result["has_embedded_files"] is False, "Test PDF should not have embedded files"

    def test_parse_pdf_file_forms_detection(self):
        """Test that form detection works."""
        # Test with standard PDFs (should have no forms)
        test_file = os.path.join(FIXTURES_DIR, "pdf_test.pdf")
        result = parse_pdf_file(test_file)
        assert result["has_forms"] is False, "Test PDF should not have forms"

    def test_parse_pdf_file_page_layout_and_mode(self):
        """Test that page layout and mode are extracted correctly."""
        test_file = os.path.join(FIXTURES_DIR, "pdf_test.pdf")
        result = parse_pdf_file(test_file)

        # Check page layout
        assert result["page_layout"] is not None, "Page layout should not be None"
        assert result["page_layout"] == "SinglePage", f"Expected 'SinglePage', got {result['page_layout']}"

        # Check page mode
        assert result["page_mode"] is not None, "Page mode should not be None"
        assert result["page_mode"] == "UseNone", f"Expected 'UseNone', got {result['page_mode']}"

    def test_parse_pdf_file_page_rotation(self):
        """Test that page rotation is extracted correctly."""
        test_file = os.path.join(FIXTURES_DIR, "pdf_test.pdf")
        result = parse_pdf_file(test_file)

        assert result["page_rotation"] is not None, "Page rotation should not be None"
        assert result["page_rotation"] == 0, f"Expected rotation 0, got {result['page_rotation']}"

    def test_parse_pdf_file_date_parsing(self):
        """Test that PDF dates are correctly parsed to ISO format."""
        test_file = os.path.join(FIXTURES_DIR, "pdf_test.pdf")
        result = parse_pdf_file(test_file)
        metadata = result["metadata"]

        # Check created date
        assert metadata["created"] is not None, "Created date should not be None"
        # ISO format: YYYY-MM-DDTHH:MM:SS
        assert "T" in metadata["created"], "Created date should be in ISO format with 'T' separator"
        assert metadata["created"].startswith("2023-03-24"), "Created date should start with 2023-03-24"

        # Check modified date
        assert metadata["modified"] is not None, "Modified date should not be None"
        assert "T" in metadata["modified"], "Modified date should be in ISO format with 'T' separator"
        assert metadata["modified"].startswith("2023-03-24"), "Modified date should start with 2023-03-24"

    def test_parse_pdf_file_metadata_empty_strings_converted_to_none(self):
        """Test that empty string metadata values are converted to None."""
        # The pdf_test.pdf has empty author, subject, keywords fields
        test_file = os.path.join(FIXTURES_DIR, "pdf_test.pdf")
        result = parse_pdf_file(test_file)
        metadata = result["metadata"]

        # These fields are empty strings in the PDF metadata, should be None in result
        assert metadata["author"] is None, f"Empty author should be None, got {metadata['author']!r}"
        assert metadata["subject"] is None, f"Empty subject should be None, got {metadata['subject']!r}"
        assert metadata["keywords"] is None, f"Empty keywords should be None, got {metadata['keywords']!r}"
        assert metadata["trapped"] is None, f"Empty trapped should be None, got {metadata['trapped']!r}"

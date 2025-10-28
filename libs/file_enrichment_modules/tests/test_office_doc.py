import os

from file_enrichment_modules.office_doc.office2john import extract_file_encryption_hash

# Get the path to the fixtures directory
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "test_files")


class TestOfficeDocEncryption:
    """Tests for Office document encryption hash extraction."""

    def test_extract_file_encryption_hash_encrypted_docx(self):
        """Test extracting encryption hash from an encrypted Office document."""
        # Arrange
        test_file = os.path.join(FIXTURES_DIR, "office_doc_new_enc.docx")
        expected_hash = "$office$*2013*100000*256*16*5737313473fee96e0bf6e5f0a31d09f9*5506e78339987281759794f16789f16c*029c2593df752e87a4d32174690672dd66a77fb78faeb8905e09dda24e8849cb"

        # Verify the test file exists
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        # Act
        encryption_hash = extract_file_encryption_hash(test_file)

        # Assert
        assert encryption_hash is not None, "Encryption hash should not be None"
        assert isinstance(encryption_hash, str), "Encryption hash should be a string"
        assert len(encryption_hash) > 0, "Encryption hash should not be empty"

        # Office document hashes in hashcat format typically start with "$office$"
        assert encryption_hash.startswith("$office$") or encryption_hash.startswith("$o"), \
            f"Expected hash to start with '$office$' or '$o', got: {encryption_hash[:20]}"

        # Verify the exact hash value
        assert encryption_hash == expected_hash, \
            f"Expected hash:\n{expected_hash}\nGot:\n{encryption_hash}"

    def test_extract_file_encryption_hash_with_hashcat_format(self):
        """Test extracting encryption hash with explicit hashcat format parameter."""
        # Arrange
        test_file = os.path.join(FIXTURES_DIR, "office_doc_new_enc.docx")

        # Act
        encryption_hash = extract_file_encryption_hash(test_file, hashcat_format=True)

        # Assert
        assert encryption_hash is not None
        assert isinstance(encryption_hash, str)
        assert len(encryption_hash) > 0
        assert encryption_hash.startswith("$office$") or encryption_hash.startswith("$o")

    def test_extract_file_encryption_hash_encrypted_ole_doc(self):
        """Test extracting encryption hash from an encrypted OLE format Office document."""
        # Arrange
        test_file = os.path.join(FIXTURES_DIR, "office_doc_ole_enc.doc")
        expected_hash = "$oldoffice$4*c7e570b71025429fe6c1ca66659e1db1*886ce474ec4b5d0c82d1c3fbfac542e9*c9baa372b56d889700d9bd39e42136dcbae8de20"

        # Verify the test file exists
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        # Act
        encryption_hash = extract_file_encryption_hash(test_file)

        # Assert
        assert encryption_hash is not None, "Encryption hash should not be None"
        assert isinstance(encryption_hash, str), "Encryption hash should be a string"
        assert len(encryption_hash) > 0, "Encryption hash should not be empty"

        # OLE Office document hashes start with "$oldoffice$"
        assert encryption_hash.startswith("$oldoffice$") or encryption_hash.startswith("$o"), \
            f"Expected hash to start with '$oldoffice$' or '$o', got: {encryption_hash[:20]}"

        # Verify the exact hash value
        assert encryption_hash == expected_hash, \
            f"Expected hash:\n{expected_hash}\nGot:\n{encryption_hash}"

    def test_extract_file_encryption_hash_nonexistent_file(self):
        """Test that the function handles non-existent files by returning empty string."""
        # Arrange
        nonexistent_file = os.path.join(FIXTURES_DIR, "nonexistent_file.docx")

        # Act
        encryption_hash = extract_file_encryption_hash(nonexistent_file)

        # Assert - The function returns an empty string for non-existent files
        assert encryption_hash == "", "Expected empty string for non-existent file"

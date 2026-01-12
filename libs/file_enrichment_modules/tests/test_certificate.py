import os
from unittest.mock import patch

from file_enrichment_modules.certificate.analyzer import CertificateAnalyzer

# Get the path to the fixtures directory
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "test_files")


def get_analyzer():
    """Helper to create a CertificateAnalyzer instance without Dapr dependency."""
    with patch('file_enrichment_modules.certificate.analyzer.StorageMinio'):
        return CertificateAnalyzer()


class TestCertificateAnalyzer:
    """Tests for certificate file parsing and metadata extraction."""

    def test_parse_certificate_with_upn_san(self):
        """Test parsing a certificate with a UPN (User Principal Name) in the Subject Alternative Names."""
        # Arrange
        test_file = os.path.join(FIXTURES_DIR, "cert_with_san.pem")

        # Verify the test file exists
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        analyzer = get_analyzer()

        # Act
        result = analyzer.analyze_certificate_file(test_file)

        # Assert
        assert result is not None, "Result should not be None"
        assert isinstance(result, dict), "Result should be a dictionary"

        # Check that certificates were extracted
        assert "certificates" in result, "Result should contain certificates"
        assert len(result["certificates"]) > 0, "Should have at least one certificate"

        cert = result["certificates"][0]

        # Check basic certificate properties
        assert "subject" in cert, "Certificate should have a subject"
        assert "user@domain.com" in cert["subject"], f"Subject should contain 'user@domain.com', got {cert['subject']}"

        assert "issuer" in cert, "Certificate should have an issuer"
        assert "not_valid_before" in cert, "Certificate should have not_valid_before"
        assert "not_valid_after" in cert, "Certificate should have not_valid_after"

        # Check that extensions were extracted
        assert "extensions" in cert, "Certificate should have extensions"
        extensions = cert["extensions"]
        assert isinstance(extensions, list), "Extensions should be a list"

        # Find the subjectAltName extension
        san_ext = None
        for ext in extensions:
            if ext.get("name") == "subjectAltName":
                san_ext = ext
                break

        assert san_ext is not None, "Certificate should have a subjectAltName extension"
        assert "subject_alternative_names" in san_ext, "subjectAltName extension should have subject_alternative_names"

        sans = san_ext["subject_alternative_names"]
        assert isinstance(sans, list), "Subject Alternative Names should be a list"
        assert len(sans) > 0, "Certificate should have at least one SAN"

        # Find the UPN in the SANs
        upn_sans = [san for san in sans if san.get("type") == "UPN"]
        assert len(upn_sans) > 0, f"Certificate should have at least one UPN SAN. Found SANs: {sans}"

        # Verify the UPN value
        upn = upn_sans[0]
        assert "value" in upn, "UPN SAN should have a value"
        assert upn["value"] == "user@domain.com", f"Expected UPN 'user@domain.com', got {upn['value']}"

        # Verify the UPN has the correct OID
        assert "type_id" in upn, "UPN SAN should have a type_id"
        assert upn["type_id"] == "1.3.6.1.4.1.311.20.2.3", (
            f"UPN should have OID 1.3.6.1.4.1.311.20.2.3, got {upn['type_id']}"
        )

    def test_parse_certificate_with_private_key(self):
        """Test parsing a certificate file that also contains a private key."""
        # Arrange
        test_file = os.path.join(FIXTURES_DIR, "cert_with_san.pem")

        # Verify the test file exists
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        analyzer = get_analyzer()

        # Act
        result = analyzer.analyze_certificate_file(test_file)

        # Assert
        assert result is not None, "Result should not be None"
        assert isinstance(result, dict), "Result should be a dictionary"

        # Check that private key was extracted
        assert "private_keys" in result, "Result should contain private_keys"
        assert len(result["private_keys"]) > 0, "Should have at least one private key"

        private_key = result["private_keys"][0]

        # Check private key properties
        assert "key_type" in private_key, "Private key should have a key_type"
        assert private_key["key_type"] in ["RSAPrivateKey", "_RSAPrivateKey"], (
            f"Expected RSA private key, got {private_key['key_type']}"
        )

        assert "key_size_bits" in private_key or "key_size" in private_key, (
            "Private key should have key_size or key_size_bits"
        )

    def test_parse_certificate_extended_key_usage(self):
        """Test that Extended Key Usage is extracted correctly."""
        # Arrange
        test_file = os.path.join(FIXTURES_DIR, "cert_with_san.pem")

        # Verify the test file exists
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        analyzer = get_analyzer()

        # Act
        result = analyzer.analyze_certificate_file(test_file)

        # Assert
        assert result is not None, "Result should not be None"
        assert len(result["certificates"]) > 0, "Should have at least one certificate"

        cert = result["certificates"][0]

        # Check that extensions were extracted
        assert "extensions" in cert, "Certificate should have extensions"
        assert isinstance(cert["extensions"], list), "Extensions should be a list"

        # Find the Extended Key Usage extension
        eku_ext = None
        for ext in cert["extensions"]:
            if ext.get("name") == "extendedKeyUsage":
                eku_ext = ext
                break

        # If there's an extendedKeyUsage extension, verify it has the right structure
        if eku_ext:
            assert "extended_key_usages" in eku_ext, "extendedKeyUsage extension should have extended_key_usages"
            ekus = eku_ext["extended_key_usages"]
            assert isinstance(ekus, list), "Extended key usages should be a list"
            # Verify each EKU has both OID and name
            for eku in ekus:
                assert "oid" in eku, "Each EKU should have an OID"
                assert "name" in eku, "Each EKU should have a name"

    def test_parse_certificate_validity(self):
        """Test that certificate validity dates and status are correctly extracted."""
        # Arrange
        test_file = os.path.join(FIXTURES_DIR, "cert_with_san.pem")

        # Verify the test file exists
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        analyzer = get_analyzer()

        # Act
        result = analyzer.analyze_certificate_file(test_file)

        # Assert
        assert result is not None, "Result should not be None"
        assert len(result["certificates"]) > 0, "Should have at least one certificate"

        cert = result["certificates"][0]

        # Check validity fields
        assert "not_valid_before" in cert, "Certificate should have not_valid_before"
        assert "not_valid_after" in cert, "Certificate should have not_valid_after"
        assert "is_valid" in cert, "Certificate should have is_valid field"

        # Verify dates are in ISO format
        assert "T" in cert["not_valid_before"] or "2026" in cert["not_valid_before"], (
            "not_valid_before should be in ISO format or contain year"
        )
        assert "T" in cert["not_valid_after"] or "2027" in cert["not_valid_after"], (
            "not_valid_after should be in ISO format or contain year"
        )

        # The test certificate should be valid (created in 2026, expires in 2027)
        assert isinstance(cert["is_valid"], bool), "is_valid should be a boolean"

    def test_parse_certificate_public_key_info(self):
        """Test that public key information is correctly extracted."""
        # Arrange
        test_file = os.path.join(FIXTURES_DIR, "cert_with_san.pem")

        # Verify the test file exists
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        analyzer = get_analyzer()

        # Act
        result = analyzer.analyze_certificate_file(test_file)

        # Assert
        assert result is not None, "Result should not be None"
        assert len(result["certificates"]) > 0, "Should have at least one certificate"

        cert = result["certificates"][0]

        # Check public key info
        assert "public_key_info" in cert, "Certificate should have public_key_info"
        pub_key = cert["public_key_info"]

        assert "key_type" in pub_key, "Public key should have a key_type"
        # RSA key type can vary based on cryptography version
        assert "RSA" in pub_key["key_type"], f"Expected RSA key type, got {pub_key['key_type']}"

        # RSA keys should have key size
        assert "key_size" in pub_key or "key_size_bits" in pub_key, (
            "RSA public key should have key_size or key_size_bits"
        )

    def test_parse_certificate_serial_number(self):
        """Test that certificate serial number is extracted."""
        # Arrange
        test_file = os.path.join(FIXTURES_DIR, "cert_with_san.pem")

        # Verify the test file exists
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        analyzer = get_analyzer()

        # Act
        result = analyzer.analyze_certificate_file(test_file)

        # Assert
        assert result is not None, "Result should not be None"
        assert len(result["certificates"]) > 0, "Should have at least one certificate"

        cert = result["certificates"][0]

        # Check serial number
        assert "serial_number" in cert, "Certificate should have a serial_number"
        assert isinstance(cert["serial_number"], str), "Serial number should be a string"
        assert len(cert["serial_number"]) > 0, "Serial number should not be empty"

    def test_encryption_info_for_unencrypted_cert(self):
        """Test that encryption info is correctly set for unencrypted certificate."""
        # Arrange
        test_file = os.path.join(FIXTURES_DIR, "cert_with_san.pem")

        # Verify the test file exists
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        analyzer = get_analyzer()

        # Act
        result = analyzer.analyze_certificate_file(test_file)

        # Assert
        assert result is not None, "Result should not be None"
        assert "encryption_info" in result, "Result should contain encryption_info"

        enc_info = result["encryption_info"]
        assert "decryption_successful" in enc_info, "Encryption info should have decryption_successful"

        # The test file contains an unencrypted private key, so decryption should succeed
        assert enc_info["decryption_successful"] is True, "Decryption should be successful for unencrypted file"

    def test_parse_encrypted_pfx_with_common_password(self):
        """Test parsing an encrypted PFX file with a common password."""
        # Arrange
        test_file = os.path.join(FIXTURES_DIR, "cert_with_san.pfx")

        # Verify the test file exists
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        analyzer = get_analyzer()

        # Act
        result = analyzer.analyze_certificate_file(test_file)

        # Assert
        assert result is not None, "Result should not be None"
        assert isinstance(result, dict), "Result should be a dictionary"

        # Check encryption info
        assert "encryption_info" in result, "Result should contain encryption_info"
        enc_info = result["encryption_info"]

        # The PFX file is encrypted with password "password"
        assert enc_info["is_encrypted"] is True, "PFX file should be encrypted"
        assert enc_info["decryption_successful"] is True, "Decryption should succeed with common password"
        assert enc_info["password_found"] == "password", f"Expected password 'password', got {enc_info['password_found']}"

        # Verify certificate was extracted
        assert "certificates" in result, "Result should contain certificates"
        assert len(result["certificates"]) > 0, "Should have at least one certificate"

        cert = result["certificates"][0]

        # Verify basic certificate properties
        assert "subject" in cert, "Certificate should have a subject"
        assert "user@domain.com" in cert["subject"], f"Subject should contain 'user@domain.com', got {cert['subject']}"

        # Verify private key was extracted
        assert "private_keys" in result, "Result should contain private_keys"
        assert len(result["private_keys"]) > 0, "Should have at least one private key"

        # Verify the UPN is still present in the certificate
        extensions = cert["extensions"]
        san_ext = None
        for ext in extensions:
            if ext.get("name") == "subjectAltName":
                san_ext = ext
                break

        assert san_ext is not None, "Certificate should have a subjectAltName extension"
        sans = san_ext["subject_alternative_names"]
        upn_sans = [san for san in sans if san.get("type") == "UPN"]
        assert len(upn_sans) > 0, "Certificate should have UPN SAN"
        assert upn_sans[0]["value"] == "user@domain.com", "UPN value should be user@domain.com"

    def test_parse_encrypted_pfx_with_unknown_password(self):
        """Test parsing an encrypted PFX file where the password is not in the common list."""
        # Arrange
        test_file = os.path.join(FIXTURES_DIR, "cert_encrypted_unknown_pass.pfx")

        # Verify the test file exists
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        analyzer = get_analyzer()

        # Act
        result = analyzer.analyze_certificate_file(test_file)

        # Assert
        assert result is not None, "Result should not be None"
        assert isinstance(result, dict), "Result should be a dictionary"

        # Check encryption info
        assert "encryption_info" in result, "Result should contain encryption_info"
        enc_info = result["encryption_info"]

        # The PFX file is encrypted with an unknown password
        assert enc_info["is_encrypted"] is True, "PFX file should be encrypted"
        assert enc_info["decryption_successful"] is False, "Decryption should fail with unknown password"
        assert enc_info["password_found"] is None, "No password should be found"

        # Verify that certificates and keys are empty since decryption failed
        assert "certificates" in result, "Result should contain certificates"
        assert len(result["certificates"]) == 0, "Should have no certificates when decryption fails"

        assert "private_keys" in result, "Result should contain private_keys"
        assert len(result["private_keys"]) == 0, "Should have no private keys when decryption fails"

    def test_parse_windows_exported_pfx_aes(self):
        """Test parsing a Windows-exported PFX file with AES encryption."""
        # Arrange
        test_file = os.path.join(FIXTURES_DIR, "pfx_enc_aes.pfx")

        # Verify the test file exists
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        analyzer = get_analyzer()

        # Act
        result = analyzer.analyze_certificate_file(test_file)

        # Assert
        assert result is not None, "Result should not be None"
        assert isinstance(result, dict), "Result should be a dictionary"

        # Check encryption info
        assert "encryption_info" in result, "Result should contain encryption_info"
        enc_info = result["encryption_info"]

        # Windows-exported PFX with AES encryption should decrypt
        assert enc_info["is_encrypted"] is True, "PFX file should be encrypted"
        assert enc_info["decryption_successful"] is True, "Decryption should succeed"
        assert enc_info["password_found"] == "password", f"Expected password 'password', got {enc_info['password_found']}"

        # Verify certificate was extracted
        assert "certificates" in result, "Result should contain certificates"
        assert len(result["certificates"]) > 0, "Should have at least one certificate"

        cert = result["certificates"][0]

        # Verify certificate properties
        assert "subject" in cert, "Certificate should have a subject"
        assert "CN=example.com" in cert["subject"], f"Subject should contain 'CN=example.com', got {cert['subject']}"

        # Verify private key was extracted
        assert "private_keys" in result, "Result should contain private_keys"
        assert len(result["private_keys"]) > 0, "Should have at least one private key"

        # Verify SANs were extracted (this cert has DNS names, not UPNs)
        extensions = cert["extensions"]
        san_ext = None
        for ext in extensions:
            if ext.get("name") == "subjectAltName":
                san_ext = ext
                break

        assert san_ext is not None, "Certificate should have a subjectAltName extension"
        sans = san_ext["subject_alternative_names"]
        assert len(sans) >= 3, f"Certificate should have at least 3 SANs, got {len(sans)}"

        # Check for expected DNS names
        dns_values = [san["value"] for san in sans if san.get("type") == "DNSName"]
        assert "example.com" in dns_values, "Should contain example.com"
        assert "www.example.com" in dns_values, "Should contain www.example.com"
        assert "api.example.com" in dns_values, "Should contain api.example.com"

    def test_parse_windows_exported_pfx_tripledes(self):
        """Test parsing a Windows-exported PFX file with TripleDES encryption."""
        # Arrange
        test_file = os.path.join(FIXTURES_DIR, "pfx_enc_tripledes.pfx")

        # Verify the test file exists
        assert os.path.exists(test_file), f"Test file not found: {test_file}"

        analyzer = get_analyzer()

        # Act
        result = analyzer.analyze_certificate_file(test_file)

        # Assert
        assert result is not None, "Result should not be None"
        assert isinstance(result, dict), "Result should be a dictionary"

        # Check encryption info
        assert "encryption_info" in result, "Result should contain encryption_info"
        enc_info = result["encryption_info"]

        # Windows-exported PFX with TripleDES encryption should decrypt
        assert enc_info["is_encrypted"] is True, "PFX file should be encrypted"
        assert enc_info["decryption_successful"] is True, "Decryption should succeed"
        assert enc_info["password_found"] == "password", f"Expected password 'password', got {enc_info['password_found']}"

        # Verify certificate was extracted
        assert "certificates" in result, "Result should contain certificates"
        assert len(result["certificates"]) > 0, "Should have at least one certificate"

        cert = result["certificates"][0]

        # Verify certificate properties
        assert "subject" in cert, "Certificate should have a subject"
        assert "CN=example.com" in cert["subject"], f"Subject should contain 'CN=example.com', got {cert['subject']}"

        # Verify private key was extracted
        assert "private_keys" in result, "Result should contain private_keys"
        assert len(result["private_keys"]) > 0, "Should have at least one private key"

        # Verify Extended Key Usage was extracted with both OID and name
        eku_ext = None
        for ext in cert["extensions"]:
            if ext.get("name") == "extendedKeyUsage":
                eku_ext = ext
                break

        assert eku_ext is not None, "Certificate should have extendedKeyUsage extension"
        ekus = eku_ext["extended_key_usages"]
        assert len(ekus) >= 2, "Should have at least 2 EKUs"

        # Verify each EKU has both OID and name
        for eku in ekus:
            assert "oid" in eku, "Each EKU should have an OID"
            assert "name" in eku, "Each EKU should have a name"

        # Check for expected EKUs
        eku_names = [eku["name"] for eku in ekus]
        assert "serverAuth" in eku_names or "clientAuth" in eku_names, "Should have serverAuth or clientAuth"

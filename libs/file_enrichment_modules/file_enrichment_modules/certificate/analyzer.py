# enrichment_modules/certificate/analyzer.py
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from common.logger import get_logger
from common.models import EnrichmentResult, Transform
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)


class CertificateAnalyzer(EnrichmentModule):
    def __init__(self):
        super().__init__("certificate_analyzer")
        self.storage = StorageMinio()
        self.workflows = ["default"]

        # Valid certificate file extensions
        self.valid_extensions = {".pem", ".crt", ".cer", ".der", ".p7b", ".p7c", ".pfx", ".p12"}

        # Common passwords to try for encrypted certificates/keys
        self.common_passwords = [
            "",
            "12345",
            "123456",
            "12345678",
            "123456789",
            "password",
            "password123",
            "qwerty123",
            "qwerty1",
            "secret",
            "123123",
        ]

    def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run."""
        file_enriched = get_file_enriched(object_id)

        # Check if it's a certificate-related file by extension or magic type
        file_extension = Path(file_enriched.file_name).suffix.lower()
        magic_type = file_enriched.magic_type.lower()

        return (
            file_extension in self.valid_extensions
            or "certificate" in magic_type
            or "pkcs" in magic_type
            or "x.509" in magic_type
            or "pem" in magic_type
        )

    def _try_decrypt_with_passwords(self, data: bytes, file_extension: str) -> dict:
        """Try to decrypt encrypted certificate/key with common passwords."""
        decrypt_results = {"is_encrypted": False, "password_found": None, "decryption_successful": False}

        # First check if the file is encrypted at all by trying to load without password
        try:
            if file_extension in {".pfx", ".p12"}:
                # Try PKCS#12 without password first
                try:
                    pkcs12.load_key_and_certificates(data, None)
                    decrypt_results.update(
                        {"is_encrypted": False, "password_found": None, "decryption_successful": True}
                    )
                    return decrypt_results
                except ValueError:
                    # File is encrypted, continue with password attempts
                    decrypt_results["is_encrypted"] = True
            else:
                # Try PEM private key without password
                try:
                    serialization.load_pem_private_key(data, None)
                    decrypt_results.update(
                        {"is_encrypted": False, "password_found": None, "decryption_successful": True}
                    )
                    return decrypt_results
                except (ValueError, TypeError):
                    # May be encrypted or may not be a private key, continue checking
                    pass
        except Exception:
            pass

        # Try with passwords if potentially encrypted
        for password in self.common_passwords:
            try:
                password_bytes = password.encode("utf-8")

                # Try PKCS#12 (PFX/P12) format
                if file_extension in {".pfx", ".p12"}:
                    try:
                        pkcs12.load_key_and_certificates(data, password_bytes)
                        decrypt_results.update(
                            {"is_encrypted": True, "password_found": password, "decryption_successful": True}
                        )
                        return decrypt_results
                    except ValueError:
                        decrypt_results["is_encrypted"] = True
                        continue

                # Try encrypted private key
                try:
                    serialization.load_pem_private_key(data, password_bytes)
                    decrypt_results.update(
                        {"is_encrypted": True, "password_found": password, "decryption_successful": True}
                    )
                    return decrypt_results
                except ValueError:
                    decrypt_results["is_encrypted"] = True
                    continue

            except Exception:
                continue

        return decrypt_results

    def _parse_certificate_data(self, data: bytes, file_extension: str) -> dict:
        """Parse certificate data and extract metadata."""
        result = {"certificates": [], "private_keys": [], "public_keys": [], "errors": [], "encryption_info": {}}

        # Try password decryption first
        decrypt_info = self._try_decrypt_with_passwords(data, file_extension)
        result["encryption_info"] = decrypt_info

        # Parse different certificate formats
        try:
            # Try PKCS#12 first (PFX/P12)
            if file_extension in {".pfx", ".p12"}:
                password = None
                if decrypt_info["decryption_successful"] and decrypt_info["password_found"] is not None:
                    password = decrypt_info["password_found"].encode("utf-8")

                try:
                    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(data, password)

                    if certificate:
                        result["certificates"].append(self._extract_certificate_info(certificate))

                    if additional_certificates:
                        for cert in additional_certificates:
                            result["certificates"].append(self._extract_certificate_info(cert))

                    if private_key:
                        result["private_keys"].append(self._extract_private_key_info(private_key))

                except Exception as e:
                    result["errors"].append(f"PKCS#12 parsing error: {str(e)}")

            # Try DER format
            elif file_extension == ".der":
                try:
                    cert = x509.load_der_x509_certificate(data)
                    result["certificates"].append(self._extract_certificate_info(cert))
                except Exception as e:
                    result["errors"].append(f"DER certificate parsing error: {str(e)}")

            # Try PEM format (default for most text-based formats)
            else:
                # Try to load as certificate
                try:
                    cert = x509.load_pem_x509_certificate(data)
                    result["certificates"].append(self._extract_certificate_info(cert))
                except Exception:
                    pass

                # Try to load as private key
                password = None
                if decrypt_info["decryption_successful"] and decrypt_info["password_found"] is not None:
                    password = decrypt_info["password_found"].encode("utf-8")

                try:
                    private_key = serialization.load_pem_private_key(data, password)
                    result["private_keys"].append(self._extract_private_key_info(private_key))
                except Exception:
                    pass

                # Try to load as public key
                try:
                    public_key = serialization.load_pem_public_key(data)
                    result["public_keys"].append(self._extract_public_key_info(public_key))
                except Exception:
                    pass

        except Exception as e:
            result["errors"].append(f"General parsing error: {str(e)}")

        return result

    def _extract_certificate_info(self, cert: x509.Certificate) -> dict:
        """Extract detailed information from a certificate."""
        now = datetime.now(UTC)

        info = {
            "version": cert.version.value,
            "serial_number": str(cert.serial_number),
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "is_valid": cert.not_valid_before_utc <= now <= cert.not_valid_after_utc,
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "public_key_info": self._extract_public_key_info(cert.public_key()),
            "extensions": [],
            "extended_key_usage": [],
        }

        # Extract extensions
        for ext in cert.extensions:
            ext_info = {"name": ext.oid._name, "critical": ext.critical, "value": str(ext.value)}

            # Special handling for Extended Key Usage
            if isinstance(ext.value, x509.ExtendedKeyUsage):
                ext_info["extended_key_usage_oids"] = [eku.dotted_string for eku in ext.value]
                info["extended_key_usage"] = [eku._name for eku in ext.value]

            info["extensions"].append(ext_info)

        return info

    def _extract_private_key_info(self, private_key) -> dict:
        """Extract information from a private key."""
        key_type = type(private_key).__name__

        info = {"key_type": key_type, "key_size": getattr(private_key, "key_size", None)}

        # Add algorithm-specific information
        if hasattr(private_key, "curve"):
            info["curve"] = private_key.curve.name
        elif hasattr(private_key, "key_size"):
            info["key_size_bits"] = private_key.key_size

        return info

    def _extract_public_key_info(self, public_key) -> dict:
        """Extract information from a public key."""
        key_type = type(public_key).__name__

        info = {"key_type": key_type, "key_size": getattr(public_key, "key_size", None)}

        # Add algorithm-specific information
        if hasattr(public_key, "curve"):
            info["curve"] = public_key.curve.name
        elif hasattr(public_key, "key_size"):
            info["key_size_bits"] = public_key.key_size

        return info

    def _generate_report(self, analysis_result: dict, file_name: str) -> str:
        """Generate a human-readable report."""
        report_lines = [f"Certificate Analysis Report for: {file_name}", "=" * 50, ""]

        # Encryption info
        encryption_info = analysis_result["encryption_info"]
        if encryption_info.get("is_encrypted") is not None:
            report_lines.append("ENCRYPTION STATUS:")
            if encryption_info["is_encrypted"]:
                report_lines.append("  - File is encrypted: YES")
                if encryption_info["decryption_successful"]:
                    password = encryption_info["password_found"]
                    report_lines.append(f"  - Password found: '{password}'")
                else:
                    report_lines.append("  - Password cracking: FAILED (none of the common passwords worked)")
            else:
                report_lines.append("  - File is encrypted: NO")
                if encryption_info["decryption_successful"]:
                    report_lines.append("  - File loaded successfully without password")
            report_lines.append("")

        # Certificates
        if analysis_result["certificates"]:
            report_lines.append("CERTIFICATES:")
            for i, cert in enumerate(analysis_result["certificates"], 1):
                report_lines.append(f"  Certificate #{i}:")
                report_lines.append(f"    - Version: {cert['version']}")
                report_lines.append(f"    - Serial Number: {cert['serial_number']}")
                report_lines.append(f"    - Subject: {cert['subject']}")
                report_lines.append(f"    - Issuer: {cert['issuer']}")
                report_lines.append(f"    - Valid From: {cert['not_valid_before']}")
                report_lines.append(f"    - Valid Until: {cert['not_valid_after']}")
                report_lines.append(f"    - Currently Valid: {'YES' if cert['is_valid'] else 'NO'}")
                report_lines.append(f"    - Signature Algorithm: {cert['signature_algorithm']}")
                report_lines.append(f"    - Public Key Type: {cert['public_key_info']['key_type']}")
                if cert["public_key_info"].get("key_size_bits"):
                    report_lines.append(f"    - Key Size: {cert['public_key_info']['key_size_bits']} bits")
                if cert["public_key_info"].get("curve"):
                    report_lines.append(f"    - Curve: {cert['public_key_info']['curve']}")

                if cert["extended_key_usage"]:
                    report_lines.append("    - Extended Key Usage:")
                    for eku in cert["extended_key_usage"]:
                        report_lines.append(f"      * {eku}")

                if cert["extensions"]:
                    report_lines.append("    - Extensions:")
                    for ext in cert["extensions"]:
                        critical_text = " (CRITICAL)" if ext["critical"] else ""
                        report_lines.append(f"      * {ext['name']}{critical_text}")
                        if ext.get("extended_key_usage_oids"):
                            report_lines.append(f"        OIDs: {', '.join(ext['extended_key_usage_oids'])}")

                report_lines.append("")

        # Private keys
        if analysis_result["private_keys"]:
            report_lines.append("PRIVATE KEYS:")
            for i, key in enumerate(analysis_result["private_keys"], 1):
                report_lines.append(f"  Private Key #{i}:")
                report_lines.append(f"    - Key Type: {key['key_type']}")
                if key.get("key_size_bits"):
                    report_lines.append(f"    - Key Size: {key['key_size_bits']} bits")
                if key.get("curve"):
                    report_lines.append(f"    - Curve: {key['curve']}")
                report_lines.append("")

        # Public keys
        if analysis_result["public_keys"]:
            report_lines.append("PUBLIC KEYS:")
            for i, key in enumerate(analysis_result["public_keys"], 1):
                report_lines.append(f"  Public Key #{i}:")
                report_lines.append(f"    - Key Type: {key['key_type']}")
                if key.get("key_size_bits"):
                    report_lines.append(f"    - Key Size: {key['key_size_bits']} bits")
                if key.get("curve"):
                    report_lines.append(f"    - Curve: {key['curve']}")
                report_lines.append("")

        # Errors
        if analysis_result["errors"]:
            report_lines.append("ERRORS:")
            for error in analysis_result["errors"]:
                report_lines.append(f"  - {error}")
            report_lines.append("")

        return "\n".join(report_lines)

    def _analyze_certificate(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze certificate file and generate enrichment result."""
        enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

        try:
            with open(file_path, "rb") as f:
                data = f.read()

            file_extension = Path(file_enriched.file_name).suffix.lower()
            analysis_result = self._parse_certificate_data(data, file_extension)

            enrichment_result.results = analysis_result

            # Generate human-readable report
            report = self._generate_report(analysis_result, file_enriched.file_name)

            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as tmp_file:
                tmp_file.write(report)
                tmp_file.flush()

                object_id = self.storage.upload_file(tmp_file.name)

                displayable_parsed = Transform(
                    type="displayable_parsed",
                    object_id=f"{object_id}",
                    metadata={
                        "file_name": f"{file_enriched.file_name}_analysis.txt",
                        "display_type_in_dashboard": "monaco",
                        "default_display": True,
                    },
                )

            enrichment_result.transforms = [displayable_parsed]
            return enrichment_result

        except Exception as e:
            logger.exception(e, message=f"Error analyzing certificate file for {file_enriched.file_name}")
            return None

    def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process certificate file."""
        try:
            file_enriched = get_file_enriched(object_id)

            if file_path:
                return self._analyze_certificate(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_certificate(temp_file.name, file_enriched)

        except Exception as e:
            logger.exception(e, message="Error processing certificate file", file_object_id=object_id)
            return None


def create_enrichment_module() -> EnrichmentModule:
    return CertificateAnalyzer()

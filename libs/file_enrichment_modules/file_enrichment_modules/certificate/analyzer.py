# enrichment_modules/certificate/analyzer.py
import csv
import tempfile
from datetime import UTC, datetime

import structlog
import yara_x
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12
from cryptography.x509.oid import ExtensionOID, NameOID

from file_enrichment_modules.module_loader import EnrichmentModule

logger = structlog.get_logger(module=__name__)


class CertificateAnalyzer(EnrichmentModule):
    def __init__(self):
        super().__init__("certificate_analyzer")
        self.storage = StorageMinio()

        # the workflows this module should automatically run in
        self.workflows = ["default"]

        # Yara rule to check for certificate content
        self.yara_rule = yara_x.compile("""
rule Certificate_File
{
    meta:
        description = "Detects certificate files (PEM/CRT/P7B) and private keys"

    strings:
        $pem_begin_cert = "-----BEGIN CERTIFICATE-----"
        $pem_begin_pkcs7 = "-----BEGIN PKCS7-----"
        $der_cert_magic = { 30 82 ?? ?? 30 82 ?? ?? A0 03 02 01 }  // Common DER cert header pattern
        $pem_begin_private_key = /-----BEGIN (RSA |DSA |EC |ECDSA |EdDSA |)?PRIVATE KEY-----/
        $pem_begin_encrypted_private_key = /-----BEGIN ENCRYPTED PRIVATE KEY-----/

    condition:
        ($pem_begin_cert at 0) or
        ($pem_begin_pkcs7 at 0) or
        ($der_cert_magic at 0) or
        ($pem_begin_private_key at 0) or
        ($pem_begin_encrypted_private_key at 0)
}
        """)

    def should_process(self, object_id: str) -> bool:
        """Determine if this module should run."""
        file_enriched = get_file_enriched(object_id)

        # Check file extension first
        cert_extensions = [".pem", ".crt", ".cer", ".der", ".p7b", ".p7c", ".pfx", ".p12"]
        if any(file_enriched.file_name.lower().endswith(ext) for ext in cert_extensions):
            return True

        # Check MIME type
        cert_mime_types = [
            "application/x-x509-ca-cert",
            "application/pkix-cert",
            "application/x-pkcs7-certificates",
            "application/x-pem-file",
        ]
        if any(mime_type in file_enriched.mime_type.lower() for mime_type in cert_mime_types):
            return True

        # Check magic type
        cert_magic_types = ["certificate", "x509", "pkcs7"]
        if any(magic_type in file_enriched.magic_type.lower() for magic_type in cert_magic_types):
            return True

        # Check using Yara rule as a fallback
        file_bytes = self.storage.download_bytes(file_enriched.object_id)
        should_run = len(self.yara_rule.scan(file_bytes).matching_rules) > 0

        logger.debug(f"CertificateAnalyzer should_run: {should_run}")
        return should_run

    def _format_extension_value(self, ext_name, ext_value):
        """Format extension values in a human-readable way."""
        ext_str = str(ext_value)

        # Handle specific common extensions
        if ext_name == "keyUsage":
            # Parse keyUsage into component parts
            try:
                parts = ext_str.strip("<KeyUsage(").rstrip(")>").split("=")
                usages = []
                for part in parts:
                    clean_part = part.strip().rstrip(",")
                    if "=" in clean_part:
                        key, value = clean_part.split("=")
                        if value.lower() == "true":
                            usages.append(key)
                    elif clean_part and clean_part != ")" and ">" not in clean_part:
                        usages.append(clean_part)
                return ", ".join(usages)
            except Exception:
                pass

        elif ext_name == "extendedKeyUsage":
            # Parse OIDs into known extended key usages
            try:
                oid_mapping = {
                    "1.3.6.1.5.5.7.3.1": "serverAuth",
                    "1.3.6.1.5.5.7.3.2": "clientAuth",
                    "1.3.6.1.5.5.7.3.3": "codeSigning",
                    "1.3.6.1.5.5.7.3.4": "emailProtection",
                    "1.3.6.1.5.5.7.3.8": "timeStamping",
                    "1.3.6.1.5.5.7.3.9": "OCSPSigning",
                    "1.3.6.1.4.1.311.10.3.4": "Microsoft Document Encryption",
                    # Add more mappings as needed
                }

                # Extract OIDs from string like <ExtendedKeyUsage([<ObjectIdentifier(oid=1.3.6...
                oids = []
                parts = ext_str.split("oid=")
                for part in parts[1:]:  # Skip the first part before the first "oid="
                    oid = part.split(",")[0].strip()
                    name = oid_mapping.get(oid, f"OID {oid}")
                    oids.append(name)

                return ", ".join(oids)
            except Exception:
                pass

        elif ext_name == "basicConstraints":
            # Format basic constraints clearly
            try:
                is_ca = "CA:TRUE" if "CA=True" in ext_str else "CA:FALSE"
                path_len = ""
                if "path_length=" in ext_str:
                    path_len_match = ext_str.split("path_length=")[1].split(")")[0]
                    path_len = f", pathlen:{path_len_match}"
                return f"{is_ca}{path_len}"
            except Exception:
                pass

        elif ext_name == "authorityKeyIdentifier" or ext_name == "subjectKeyIdentifier":
            # Format key identifiers as hex strings
            try:
                if "keyid:" in ext_str:
                    keyid = ext_str.split("keyid:")[1].split()[0]
                    return f"keyid:{keyid}"
                return ext_str.replace(":", "")
            except Exception:
                pass

        elif ext_name == "cRLDistributionPoints":
            # Format CRL distribution points as clickable URLs
            try:
                urls = []
                parts = ext_str.split("value=")
                for part in parts[1:]:
                    url = part.split("'")[1].split("'")[0]
                    urls.append(url)
                return "\n  - " + "\n  - ".join(urls)
            except Exception:
                pass

        # For unknown extensions or if specific formatting fails
        # Clean up common patterns and break long strings
        ext_str = ext_str.replace("<", "").replace(">", "")

        # If the extension value is too long, format with line breaks every 80 chars
        if len(ext_str) > 80:
            formatted = ""
            for i in range(0, len(ext_str), 80):
                if i > 0:
                    formatted += "\n  "
                formatted += ext_str[i : i + 80]
            return formatted

        return ext_str

    def _load_certificates(self, file_path):
        """Load certificates from file in various formats."""
        with open(file_path, "rb") as f:
            file_data = f.read()

        certificates = []
        used_password = None

        # Try PEM format first (most common)
        try:
            certs = self._load_pem_certificates(file_data)
            if certs:
                return certs, used_password
        except Exception as e:
            logger.debug(f"Not a valid PEM certificate: {str(e)}")

        # Try DER format
        try:
            cert = x509.load_der_x509_certificate(file_data, default_backend())
            return [cert], used_password
        except Exception as e:
            logger.debug(f"Not a valid DER certificate: {str(e)}")

        # Try PKCS#7 format
        try:
            # First try PEM encoded PKCS#7
            try:
                pkcs7_data = pkcs7.load_pem_pkcs7_certificates(file_data)
                if pkcs7_data:
                    return pkcs7_data, used_password
            except Exception:
                # Then try DER encoded PKCS#7
                pkcs7_data = pkcs7.load_der_pkcs7_certificates(file_data)
                if pkcs7_data:
                    return pkcs7_data, used_password
        except Exception as e:
            logger.debug(f"Not a valid PKCS#7 certificate store: {str(e)}")

        # Try PKCS#12 format (PFX/P12) with various passwords
        passwords_to_try = [
            None,
            b"",
            b"12345",
            b"123456",
            b"12345678",
            b"123456789",
            b"password",
            b"password123",
            b"qwerty123",
            b"qwerty1",
            b"secret",
            b"123123",
        ]

        for password in passwords_to_try:
            try:
                # Handle None password case
                if password is None:
                    pkcs12_data = load_pkcs12(file_data, password=None)
                else:
                    # Ensure password is bytes
                    if isinstance(password, str):
                        password = password.encode("utf-8")
                    pkcs12_data = load_pkcs12(file_data, password=password)

                certificates = []

                # Get the main certificate
                if pkcs12_data.cert:
                    certificates.append(pkcs12_data.cert.certificate)

                # Get any additional certificates in the chain
                if pkcs12_data.additional_certs:
                    for cert in pkcs12_data.additional_certs:
                        certificates.append(cert.certificate)

                if certificates:
                    # Record which password worked
                    if password is None:
                        used_password = "None"
                    elif password == b"":
                        used_password = "Empty string"
                    else:
                        used_password = password.decode("utf-8")

                    logger.info(f"Successfully loaded PKCS#12 file with password: {used_password}")
                    return certificates, used_password

            except Exception as e:
                logger.debug(f"Failed to load PKCS#12 with password {password}: {str(e)}")
                continue

        # If we get here, we couldn't parse the certificate
        logger.error("Could not parse certificate file in any known format!")

    def _load_pem_certificates(self, data):
        """Load one or more PEM certificates from data."""
        certs = []

        # Split by BEGIN/END markers to handle multiple PEM certs in one file
        pem_sections = []
        current_section = ""
        in_cert = False

        for line in data.decode("utf-8", errors="replace").splitlines():
            if "-----BEGIN CERTIFICATE-----" in line:
                current_section = line + "\n"
                in_cert = True
            elif "-----END CERTIFICATE-----" in line and in_cert:
                current_section += line + "\n"
                pem_sections.append(current_section)
                current_section = ""
                in_cert = False
            elif in_cert:
                current_section += line + "\n"

        # Process each PEM section
        for pem_data in pem_sections:
            try:
                cert = x509.load_pem_x509_certificate(pem_data.encode("utf-8"), default_backend())
                certs.append(cert)
            except Exception as e:
                logger.debug(f"Failed to parse PEM certificate section: {str(e)}")

        return certs

    def _get_cert_info(self, cert):
        """Extract information from a certificate."""
        try:
            # Create a base info dictionary with safe defaults
            info = {
                "subject": "",
                "issuer": "",
                "serial_number": "",
                "not_valid_before": "",
                "not_valid_after": "",
                "signature_algorithm": "",
                "version": "",
                "public_key_type": "",
                "key_size": "",
                "is_valid_now": False,
                "extensions": {},
                "fingerprint_sha1": "",
                "fingerprint_sha256": "",
            }

            # Fill in certificate details
            try:
                info["subject"] = self._format_name(cert.subject)
            except:
                pass
            info["issuer"] = self._format_name(cert.issuer)
            info["serial_number"] = f"{cert.serial_number:x}"

            # Use UTC-aware datetime properties
            try:
                info["not_valid_before"] = cert.not_valid_before_utc.isoformat()
                info["not_valid_after"] = cert.not_valid_after_utc.isoformat()
            except AttributeError:
                # Fallback for older cryptography versions
                info["not_valid_before"] = cert.not_valid_before.isoformat()
                info["not_valid_after"] = cert.not_valid_after.isoformat()

            # Handle potential missing attributes with try-except
            try:
                info["signature_algorithm"] = cert.signature_algorithm_oid._name
            except (AttributeError, TypeError):
                info["signature_algorithm"] = "Unknown"

            try:
                info["version"] = cert.version.name
            except (AttributeError, TypeError):
                info["version"] = "Unknown"

            # Get public key info
            try:
                info["public_key_type"] = self._get_public_key_type(cert.public_key())
                info["key_size"] = self._get_key_size(cert.public_key())
            except Exception as e:
                logger.debug(f"Error getting public key info: {str(e)}")
                info["public_key_type"] = "Unknown"
                info["key_size"] = "Unknown"

            # Check validity
            info["is_valid_now"] = self._is_certificate_valid(cert)

            # Get extensions and fingerprints
            try:
                info["extensions"] = self._get_extensions(cert)
            except Exception as e:
                logger.debug(f"Error getting extensions: {str(e)}")

            try:
                info["fingerprint_sha1"] = self._get_fingerprint(cert, "sha1")
                info["fingerprint_sha256"] = self._get_fingerprint(cert, "sha256")
            except Exception as e:
                logger.debug(f"Error getting fingerprints: {str(e)}")

            # Add SANs if available
            try:
                sans = self._get_subject_alternative_names(cert)
                if sans:
                    info["subject_alternative_names"] = sans
            except Exception as e:
                logger.debug(f"Error getting SANs: {str(e)}")

            return info
        except Exception as e:
            logger.error(f"Error extracting certificate info: {str(e)}")
            # Return a minimal valid dictionary with error information
            return {"error": str(e), "is_valid_now": False}

    def _format_name(self, name):
        """Format a certificate name (subject or issuer)."""
        name_parts = []
        for attribute in name:
            oid = attribute.oid
            if oid == NameOID.COMMON_NAME:
                name_parts.append(f"CN={attribute.value}")
            elif oid == NameOID.ORGANIZATION_NAME:
                name_parts.append(f"O={attribute.value}")
            elif oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                name_parts.append(f"OU={attribute.value}")
            elif oid == NameOID.COUNTRY_NAME:
                name_parts.append(f"C={attribute.value}")
            elif oid == NameOID.STATE_OR_PROVINCE_NAME:
                name_parts.append(f"ST={attribute.value}")
            elif oid == NameOID.LOCALITY_NAME:
                name_parts.append(f"L={attribute.value}")
            else:
                name_parts.append(f"{oid._name}={attribute.value}")
        return ", ".join(name_parts)

    def _get_public_key_type(self, public_key):
        """Get the type of the public key."""
        if isinstance(public_key, rsa.RSAPublicKey):
            return "RSA"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return f"EC ({public_key.curve.name})"
        elif isinstance(public_key, dsa.DSAPublicKey):
            return "DSA"
        else:
            return "Unknown"

    def _get_key_size(self, public_key):
        """Get the size of the public key."""
        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                return public_key.key_size
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                return public_key.key_size
            elif isinstance(public_key, dsa.DSAPublicKey):
                return public_key.key_size
            else:
                return "Unknown"
        except Exception:
            return "Unknown"

    def _is_certificate_valid(self, cert):
        """Check if the certificate is currently valid (not expired)."""
        try:
            now = datetime.now(UTC)

            # Use UTC-aware datetime properties
            try:
                not_valid_before = cert.not_valid_before_utc
                not_valid_after = cert.not_valid_after_utc
            except AttributeError:
                # Fallback for older cryptography versions
                not_valid_before = cert.not_valid_before
                not_valid_after = cert.not_valid_after

                # Ensure both dates are timezone-aware for fallback
                if not_valid_before.tzinfo is None:
                    not_valid_before = not_valid_before.replace(tzinfo=UTC)
                if not_valid_after.tzinfo is None:
                    not_valid_after = not_valid_after.replace(tzinfo=UTC)

            return not_valid_before <= now <= not_valid_after
        except Exception as e:
            logger.error(f"Error checking certificate validity: {str(e)}")
            return False

    def _get_extensions(self, cert):
        """Get certificate extensions."""
        extensions = {}
        for ext in cert.extensions:
            try:
                extensions[ext.oid._name] = str(ext.value)
            except Exception:
                extensions[ext.oid._name] = "Unable to parse extension value"
        return extensions

    def _get_subject_alternative_names(self, cert):
        """Get Subject Alternative Names."""
        try:
            san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            if san_extension:
                san_value = san_extension.value

                sans = []
                for name in san_value:
                    if isinstance(name, x509.DNSName):
                        sans.append(f"DNS:{name.value}")
                    elif isinstance(name, x509.IPAddress):
                        sans.append(f"IP:{name.value}")
                    elif isinstance(name, x509.RFC822Name):  # RFC822Name is for email addresses
                        sans.append(f"email:{name.value}")
                    elif isinstance(name, x509.UniformResourceIdentifier):  # For URIs
                        sans.append(f"URI:{name.value}")
                    else:
                        sans.append(f"Other:{name}")

                return sans
        except x509.ExtensionNotFound:
            return []
        except Exception as e:
            logger.error(f"Error getting SANs: {str(e)}")
            return []

    def _get_fingerprint(self, cert, hash_algorithm):
        """Get certificate fingerprint using specified hash algorithm."""
        try:
            if hash_algorithm == "sha1":
                from cryptography.hazmat.primitives.hashes import SHA1

                digest = SHA1()
            elif hash_algorithm == "sha256":
                from cryptography.hazmat.primitives.hashes import SHA256

                digest = SHA256()
            else:
                return "Unsupported hash algorithm"

            fingerprint = cert.fingerprint(digest)
            return ":".join(f"{b:02x}" for b in fingerprint)
        except Exception as e:
            logger.error(f"Error getting fingerprint: {str(e)}")
            return "Unknown"

    def process(self, object_id: str) -> EnrichmentResult | None:
        """Process certificate file."""
        try:
            file_enriched = get_file_enriched(object_id)
            enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)
            transforms = []
            findings = []

            with self.storage.download(file_enriched.object_id) as temp_file:
                try:
                    certificates, used_password = self._load_certificates(temp_file.name)
                    cert_info_list = []
                    expired_certs = []

                    for cert in certificates:
                        try:
                            cert_info = self._get_cert_info(cert)
                            # Ensure is_valid_now exists in the cert_info dict
                            if "is_valid_now" not in cert_info:
                                cert_info["is_valid_now"] = False
                            cert_info_list.append(cert_info)

                            # Check if certificate is expired
                            if not cert_info.get("is_valid_now", False):
                                expired_certs.append(cert_info)
                        except Exception as e:
                            logger.error(f"Error processing certificate: {str(e)}")
                            # Add a minimal cert_info with error details
                            cert_info_list.append({"error": str(e), "is_valid_now": False})

                    # Generate summary report
                    report_lines = []
                    report_lines.append("# Certificate Analysis Summary")
                    report_lines.append(f"\nFile name: {file_enriched.file_name}")
                    report_lines.append(f"\nTotal certificates: {len(cert_info_list)}")
                    report_lines.append(f"\nValid certificates: {len(cert_info_list) - len(expired_certs)}")
                    report_lines.append(f"\nExpired certificates: {len(expired_certs)}")

                    # Add password info if it's a PKCS#12 file
                    if used_password is not None:
                        report_lines.append(
                            f"\n**Note**: Successfully decrypted PKCS#12/PFX file using password: '{used_password}'"
                        )

                    # Certificate details
                    for i, cert_info in enumerate(cert_info_list, 1):
                        eku = ""
                        report_lines.append(f"\n## Certificate {i}")

                        # Handle error case
                        if "error" in cert_info and "subject" not in cert_info:
                            report_lines.append(f"\n**ERROR**: {cert_info['error']}")
                            continue

                        # Format subject and issuer with line breaks for readability
                        report_lines.append(f"\n**Subject**:  \n{cert_info['subject']}")
                        report_lines.append(f"\n**Issuer**:  \n{cert_info['issuer']}")

                        # Basic certificate details
                        report_lines.append(f"\n**Serial Number**: {cert_info['serial_number']}")
                        report_lines.append(f"\n**Valid From**: {cert_info['not_valid_before']}")
                        report_lines.append(f"\n**Valid To**: {cert_info['not_valid_after']}")
                        report_lines.append(
                            f"\n**Status**: {'Valid' if cert_info.get('is_valid_now', False) else 'Expired or Not Yet Valid'}"
                        )
                        report_lines.append(f"\n**Version**: {cert_info['version']}")
                        report_lines.append(f"\n**Signature Algorithm**: {cert_info['signature_algorithm']}")
                        report_lines.append(
                            f"\n**Public Key**: {cert_info['public_key_type']} ({cert_info['key_size']} bits)"
                        )

                        # Fingerprints with better formatting
                        if cert_info["fingerprint_sha1"]:
                            report_lines.append(f"\n**SHA-1 Fingerprint**:  \n{cert_info['fingerprint_sha1']}")
                        if cert_info["fingerprint_sha256"]:
                            report_lines.append(f"\n**SHA-256 Fingerprint**:  \n{cert_info['fingerprint_sha256']}")

                        # Subject Alternative Names with better formatting
                        if "subject_alternative_names" in cert_info and cert_info["subject_alternative_names"]:
                            report_lines.append("\n**Subject Alternative Names**:")
                            for san in cert_info["subject_alternative_names"]:
                                # Extract the SAN value and format it properly
                                san_type = san.split(":", 1)[0] if ":" in san else "Other"
                                san_value = san.split(":", 1)[1] if ":" in san else san

                                # Format as a list item with link if it's a domain or email
                                if san_type == "DNS" or san_type == "email":
                                    # Make email addresses and domains clickable if possible
                                    if san_type == "DNS":
                                        report_lines.append(f"- **{san_type}**: [{san_value}](https://{san_value})")
                                    elif san_type == "email":
                                        report_lines.append(f"- **{san_type}**: [{san_value}](mailto:{san_value})")
                                    else:
                                        report_lines.append(f"- **{san_type}**: {san_value}")
                                else:
                                    report_lines.append(f"- **{san_type}**: {san_value}")

                        # Extensions with better formatting
                        if cert_info["extensions"]:
                            report_lines.append("\n**Key Extensions**:")
                            for ext_name, ext_value in cert_info["extensions"].items():
                                # Skip displaying SANs here as we already showed them above
                                if ext_name != "subjectAltName":
                                    # Format the extension value in a readable way
                                    try:
                                        formatted_value = self._format_extension_value(ext_name, ext_value)
                                    except Exception as e:
                                        logger.error(f"Error formatting extension {ext_name}: {str(e)}")
                                        formatted_value = str(ext_value)

                                    report_lines.append(f"- **{ext_name}**:  \n  {formatted_value}")
                                    if ext_name == "extendedKeyUsage":
                                        eku = formatted_value

                    # Update the raw_data to include password information if a PKCS#12 file was loaded
                    raw_data = {"certificates": cert_info_list}
                    if used_password is not None:
                        raw_data["pkcs12_password"] = used_password

                    # Create summary report transform
                    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_report:
                        tmp_report.write("\n".join(report_lines))
                        tmp_report.flush()
                        report_id = self.storage.upload_file(tmp_report.name)

                        transforms.append(
                            Transform(
                                type="finding_summary",
                                object_id=f"{report_id}",
                                metadata={
                                    "file_name": f"{file_enriched.file_name}_analysis.md",
                                    "display_type_in_dashboard": "markdown",
                                    "default_display": True,
                                },
                            )
                        )

                    # Export certificate info to CSV
                    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="") as tmp_csv:
                        fieldnames = [
                            "subject",
                            "issuer",
                            "serial_number",
                            "not_valid_before",
                            "not_valid_after",
                            "is_valid_now",
                            "version",
                            "signature_algorithm",
                            "public_key_type",
                            "key_size",
                            "fingerprint_sha1",
                            "fingerprint_sha256",
                        ]

                        # Add pkcs12_password field if applicable
                        if used_password is not None:
                            fieldnames.append("pkcs12_password")

                        writer = csv.DictWriter(tmp_csv, fieldnames=fieldnames)
                        writer.writeheader()

                        for cert_info in cert_info_list:
                            # Create a row with only the fields we want
                            row = {field: cert_info[field] for field in fieldnames if field in cert_info}
                            # Add password information if available
                            if used_password is not None and "pkcs12_password" in fieldnames:
                                row["pkcs12_password"] = used_password
                            writer.writerow(row)

                        tmp_csv.flush()
                        csv_id = self.storage.upload_file(tmp_csv.name)

                        transforms.append(
                            Transform(
                                type="certificate_info.csv",
                                object_id=f"{csv_id}",
                                metadata={
                                    "file_name": f"{file_enriched.file_name}_certificates.csv",
                                    "offer_as_download": True,
                                },
                            )
                        )

                    # Create finding for valid certificates
                    valid_certs = [cert for cert in cert_info_list if cert.get("is_valid_now", False)]
                    if valid_certs:
                        finding_data = []

                        # Create a summary of valid certificates
                        valid_summary = "## Valid Certificates Detected\n\n"
                        valid_summary += "The following certificates are currently valid:\n\n"

                        for i, cert in enumerate(valid_certs, 1):
                            valid_summary += f"**Certificate {i}**\n"
                            valid_summary += f"- **Subject:** {cert['subject']}\n"
                            if eku:
                                valid_summary += f"- **EKU:** {eku}\n"
                            valid_summary += f"- **Issuer:** {cert['issuer']}\n"
                            valid_summary += f"- **Valid From:** {cert['not_valid_before']}\n"
                            valid_summary += f"- **Valid To:** {cert['not_valid_after']}\n\n"

                        # Add password information if a PKCS#12 file was loaded
                        if used_password is not None:
                            valid_summary += f"\n**Note**: Successfully decrypted PKCS#12/PFX file using password: '{used_password}'\n"

                        # Add the valid cert summary as a finding
                        display_data = FileObject(type="finding_summary", metadata={"summary": valid_summary})
                        finding_data.append(display_data)

                        # Include password information in the finding if applicable
                        finding_raw_data = {"valid_certificates": valid_certs}
                        if used_password is not None:
                            finding_raw_data["pkcs12_password"] = used_password

                        finding = Finding(
                            category=FindingCategory.CREDENTIAL,
                            finding_name="valid_certificates",
                            origin_type=FindingOrigin.ENRICHMENT_MODULE,
                            origin_name=self.name,
                            object_id=file_enriched.object_id,
                            severity=5,
                            raw_data=finding_raw_data,
                            data=finding_data,
                        )

                        findings.append(finding)

                    # Create additional finding for PKCS#12 password if one was found
                    if used_password is not None and used_password not in ["None", "Empty string"]:
                        password_finding_summary = "## PKCS#12/PFX Password Discovered\n\n"
                        password_finding_summary += (
                            f"Successfully decrypted PKCS#12/PFX file using password: **'{used_password}'**\n\n"
                        )
                        password_finding_summary += "This password may be used for other encrypted files or systems."

                        password_display_data = FileObject(
                            type="finding_summary", metadata={"summary": password_finding_summary}
                        )

                        password_finding = Finding(
                            category=FindingCategory.CREDENTIAL,
                            finding_name="pkcs12_password_found",
                            origin_type=FindingOrigin.ENRICHMENT_MODULE,
                            origin_name=self.name,
                            object_id=file_enriched.object_id,
                            severity=7,  # Higher severity for password discovery
                            raw_data={"pkcs12_password": used_password},
                            data=[password_display_data],
                        )

                        findings.append(password_finding)

                    # Add the results to the enrichment result
                    enrichment_result.transforms = transforms
                    enrichment_result.findings = findings
                    enrichment_result.results = raw_data

                    return enrichment_result

                except Exception as e:
                    logger.exception(e, message=f"Error processing certificate file: {file_enriched.file_name}")

                    # Create an error report
                    error_report = (
                        f"# Certificate Analysis Error\n\nFailed to analyze {file_enriched.file_name}: {str(e)}"
                    )

                    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_error:
                        tmp_error.write(error_report)
                        tmp_error.flush()
                        error_id = self.storage.upload_file(tmp_error.name)

                        transforms.append(
                            Transform(
                                type="finding_summary",
                                object_id=f"{error_id}",
                                metadata={
                                    "file_name": f"{file_enriched.file_name}_analysis_error.md",
                                    "display_type_in_dashboard": "markdown",
                                    "default_display": True,
                                },
                            )
                        )

                        enrichment_result.transforms = transforms
                        return enrichment_result

        except Exception as e:
            logger.exception(e, message="Error in certificate analyzer")


def create_enrichment_module() -> EnrichmentModule:
    return CertificateAnalyzer()

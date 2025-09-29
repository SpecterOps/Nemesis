# enrichment_modules/keytab/analyzer.py
import binascii
import tempfile
from datetime import UTC, datetime
from struct import unpack

import yara_x
from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)


class KeytabAnalyzer(EnrichmentModule):
    def __init__(self):
        super().__init__("keytab_analyzer")
        self.storage = StorageMinio()

        # the workflows this module should automatically run in
        self.workflows = ["default"]

        self.size_limit = 50000000  # only check the first 50 megs for DPAPI blobs, for performance

        # Key types mapping for readable output
        self.key_types = {
            1: "DES-CBC-CRC",
            2: "DES-CBC-MD4",
            3: "DES-CBC-MD5",
            4: "DES-CBC-RAW",
            5: "DES3-CBC-SHA1",
            6: "DES3-CBC-RAW",
            16: "DES3-CBC-SHA1-KD",
            17: "AES-128-CTS-HMAC-SHA1-96",
            18: "AES-256-CTS-HMAC-SHA1-96",
            23: "RC4-HMAC",
            24: "RC4-HMAC-EXP",
            25: "CAMELLIA-128-CTS-CMAC",
            26: "CAMELLIA-256-CTS-CMAC",
        }

        # Yara rule to check for keytab files
        self.yara_rule = yara_x.compile("""
rule Keytab_File
{
    meta:
        description = "Detects Kerberos keytab files"

    strings:
        $keytab_header = { 05 02 }  // Keytab format version 0x502 (version 2)

    condition:
        $keytab_header at 0
}
        """)

    def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run."""
        file_enriched = get_file_enriched(object_id)

        # Check file extension first
        if file_enriched.file_name.lower().endswith(".keytab"):
            return True

        if file_path:
            # Use provided file path - read only the needed bytes
            with open(file_path, "rb") as f:
                num_bytes = min(file_enriched.size, self.size_limit)
                file_bytes = f.read(num_bytes)
        else:
            # Fallback to downloading the file itself
            num_bytes = file_enriched.size if file_enriched.size < self.size_limit else self.size_limit
            file_bytes = self.storage.download_bytes(file_enriched.object_id, length=num_bytes)

        should_run = len(self.yara_rule.scan(file_bytes).matching_rules) > 0
        return should_run

    def _parse_keytab_entry(self, entry_data):
        """Parse a single keytab entry."""
        try:
            offset = 0

            # Number of components (2 bytes)
            if offset + 2 > len(entry_data):
                return None
            num_components = unpack(">h", entry_data[offset : offset + 2])[0]
            offset += 2

            # Realm length and value
            if offset + 2 > len(entry_data):
                return None
            realm_len = unpack(">h", entry_data[offset : offset + 2])[0]
            offset += 2

            if offset + realm_len > len(entry_data):
                return None
            realm = entry_data[offset : offset + realm_len].decode("utf-8", errors="replace")
            offset += realm_len

            # Components (principal parts)
            components = []
            for i in range(num_components):
                if offset + 2 > len(entry_data):
                    return None
                comp_len = unpack(">h", entry_data[offset : offset + 2])[0]
                offset += 2

                if offset + comp_len > len(entry_data):
                    return None
                component = entry_data[offset : offset + comp_len].decode("utf-8", errors="replace")
                components.append(component)
                offset += comp_len

            principal = "/".join(components)

            # Name type (4 bytes)
            if offset + 4 > len(entry_data):
                return None
            name_type = unpack(">I", entry_data[offset : offset + 4])[0]
            offset += 4

            # Timestamp (4 bytes)
            if offset + 4 > len(entry_data):
                return None
            timestamp = unpack(">I", entry_data[offset : offset + 4])[0]
            offset += 4

            # KVNO (1 byte)
            if offset + 1 > len(entry_data):
                return None
            kvno = entry_data[offset]
            offset += 1

            # Key type (2 bytes)
            if offset + 2 > len(entry_data):
                return None
            key_type = unpack(">H", entry_data[offset : offset + 2])[0]
            offset += 2

            # Key length (2 bytes)
            if offset + 2 > len(entry_data):
                return None
            key_length = unpack(">H", entry_data[offset : offset + 2])[0]
            offset += 2

            # Key data
            if offset + key_length > len(entry_data):
                return None
            key_data = entry_data[offset : offset + key_length]

            # Format timestamp
            if timestamp > 0:
                timestamp_dt = datetime.fromtimestamp(timestamp, tz=UTC).isoformat()
            else:
                timestamp_dt = "N/A"

            return {
                "realm": realm,
                "principal": principal,
                "key_type": key_type,
                "key_type_name": self.key_types.get(key_type, f"Unknown ({key_type})"),
                "key_length": key_length * 8,  # Convert to bits
                "key": binascii.hexlify(key_data).decode("ascii"),
                "timestamp": timestamp_dt,
                "kvno": kvno,
                "name_type": name_type,
            }

        except Exception as e:
            logger.error(f"Error parsing keytab entry: {e}")
            return None

    def _parse_keytab_manual(self, file_data):
        """Manual keytab parsing implementation."""
        entries = []

        # Check version
        if len(file_data) < 2:
            return [{"error": "File too small"}]

        version = unpack(">H", file_data[0:2])[0]
        if version != 0x0502:
            entries.append({"error": f"Unexpected keytab version: 0x{version:x}"})
            return entries

        offset = 2

        while offset < len(file_data):
            try:
                # Read entry size
                if offset + 4 > len(file_data):
                    break

                entry_size = unpack(">I", file_data[offset : offset + 4])[0]
                offset += 4

                if entry_size == 0 or offset + entry_size > len(file_data):
                    break

                entry_data = file_data[offset : offset + entry_size]
                offset += entry_size

                # Parse entry
                entry = self._parse_keytab_entry(entry_data)
                if entry:
                    entries.append(entry)

            except Exception as e:
                logger.error(f"Error parsing keytab entry at offset {offset}: {e}")
                break

        return entries

    def _parse_keytab(self, file_data):
        """Parse a keytab file and extract key information."""
        return self._parse_keytab_manual(file_data)

    def _analyze_keytab_file(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze keytab file and generate enrichment result.

        Args:
            file_path: Path to the keytab file to analyze
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)
        transforms = []
        findings = []

        try:
            # Read the keytab file
            with open(file_path, "rb") as f:
                file_data = f.read()

            # Parse the keytab file
            keytab_entries = self._parse_keytab(file_data)

            # Generate summary report
            report_lines = []
            report_lines.append("# Keytab Analysis Summary")
            report_lines.append(f"\nFile name: {file_enriched.file_name}")

            # Count valid entries vs error entries
            valid_entries = [entry for entry in keytab_entries if "error" not in entry]
            error_entries = [entry for entry in keytab_entries if "error" in entry]

            report_lines.append(f"Total entries found: {len(keytab_entries)}")
            report_lines.append(f"Valid entries: {len(valid_entries)}")
            if error_entries:
                report_lines.append(f"Entries with errors: {len(error_entries)}")

            # Add extraction method note if present
            extraction_methods = set()
            for entry in valid_entries:
                if "note" in entry and "extracted" in entry["note"].lower():
                    extraction_methods.add(entry["note"])

            if extraction_methods:
                report_lines.append("\n## Extraction Notes")
                for method in extraction_methods:
                    report_lines.append(f"- {method}")

            # Entry details
            for i, entry in enumerate(keytab_entries, 1):
                report_lines.append(f"\n## Entry {i}")

                # Handle error case
                if "error" in entry:
                    report_lines.append(f"\n**ERROR**: {entry['error']}")
                    continue

                # Add note if present
                if "note" in entry:
                    report_lines.append(f"\n**Note**: {entry['note']}")

                # Basic entry details
                report_lines.append(f"\n**Principal**: `{entry['principal']}@{entry['realm']}`")
                report_lines.append(f"\n**Key Version Number (KVNO)**: {entry['kvno']}")
                report_lines.append(f"\n**Timestamp**: {entry['timestamp']}")
                report_lines.append(f"\n**Key Type**: {entry['key_type_name']} ({entry['key_type']})")
                report_lines.append(f"\n**Key Length**: {entry['key_length']} bits")

                # Format key with better readability
                key_hex = entry["key"]
                formatted_key = " ".join([key_hex[i : i + 8] for i in range(0, len(key_hex), 8)])
                report_lines.append(f"\n**Key (Hex)**:  \n{formatted_key}")

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

            # Create finding ONLY if there are valid entries with non-null keys
            valid_keys = [entry for entry in valid_entries if entry.get("key") and entry["key"] != ""]
            if valid_keys:
                finding_data = []

                # Create a summary of encryption keys found
                key_summary = "## Kerberos Encryption Keys Detected\n\n"

                # Add extraction method note if present
                if extraction_methods:
                    key_summary += "**Note**: Some keys were extracted using fallback methods due to parsing issues. "
                    key_summary += "See the analysis report for details.\n\n"

                key_summary += "The following Kerberos encryption keys were found in the keytab file:\n\n"

                for i, entry in enumerate(valid_keys, 1):
                    key_summary += f"**Entry {i}**\n"
                    key_summary += f"- **Principal:** `{entry['principal']}@{entry['realm']}`\n"
                    key_summary += f"- **Key Type:** {entry['key_type_name']}\n"
                    key_summary += f"- **Key Length:** {entry['key_length']} bits\n"
                    key_summary += f"- **KVNO:** {entry['kvno']}\n"
                    if "note" in entry:
                        key_summary += f"- **Note:** {entry['note']}\n"
                    key_summary += "\n"

                # Add the key summary as a finding
                display_data = FileObject(type="finding_summary", metadata={"summary": key_summary})
                finding_data.append(display_data)

                finding = Finding(
                    category=FindingCategory.CREDENTIAL,
                    finding_name="kerberos_encryption_keys",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=file_enriched.object_id,
                    severity=7,  # Higher severity than certificates since these are actual keys
                    raw_data={"keytab_entries": valid_keys},
                    data=finding_data,
                )

                findings.append(finding)

            # Add the results to the enrichment result
            enrichment_result.transforms = transforms
            enrichment_result.findings = findings
            enrichment_result.results = {"keytab_entries": keytab_entries}

            return enrichment_result

        except Exception as e:
            logger.exception(e, message=f"Error processing keytab file: {file_enriched.file_name}")

            # Create an error report with more detailed information
            error_report = [
                "# Keytab Analysis Error",
                f"\nFailed to analyze {file_enriched.file_name}",
                "\n## Error Details",
                f"\n**Error Message**: {str(e)}",
                "\n**Possible Causes**:",
                "- The file may not be a valid Kerberos keytab file",
                "- The file format may be corrupted or malformed",
                "- The file may use an unsupported keytab format variation",
                "\n**Troubleshooting**:",
                "- Verify the file is a genuine keytab file",
                "- Check if the file was created correctly",
                "- Try opening the file with ktutil or a similar Kerberos utility",
            ]

            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_error:
                tmp_error.write("\n".join(error_report))
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

                # No finding is created for errors
                enrichment_result.transforms = transforms
                return enrichment_result

    def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process keytab file.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file

        Returns:
            EnrichmentResult or None if processing fails
        """
        try:
            file_enriched = get_file_enriched(object_id)

            # Use provided file_path if available, otherwise download
            if file_path:
                return self._analyze_keytab_file(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_keytab_file(temp_file.name, file_enriched)

        except Exception as e:
            logger.exception(e, message="Error in keytab analyzer")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return KeytabAnalyzer()

# enrichment_modules/keytab/analyzer.py
import binascii
import tempfile
from datetime import UTC, datetime
from struct import unpack

import structlog
import yara_x
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from impacket.structure import Structure

from file_enrichment_modules.module_loader import EnrichmentModule

logger = structlog.get_logger(module=__name__)


# Keytab structure classes
class KeyTab(Structure):
    structure = (("file_format_version", "H=517"), ("keytab_entry", ":"))

    def fromString(self, data):
        self.entries = []
        Structure.fromString(self, data)
        data = self["keytab_entry"]
        while len(data) != 0:
            ktentry = KeyTabEntry(data)
            data = data[len(ktentry.getData()) :]
            self.entries.append(ktentry)

    def getData(self):
        self["keytab_entry"] = b"".join([entry.getData() for entry in self.entries])
        data = Structure.getData(self)
        return data


class OctetString(Structure):
    structure = (("len", ">H-value"), ("value", ":"))


class KeyTabContentRest(Structure):
    structure = (
        ("name_type", ">I=1"),
        ("timestamp", ">I=0"),
        ("vno8", "B=2"),
        ("keytype", ">H"),
        ("keylen", ">H-key"),
        ("key", ":"),
    )


class KeyTabContent(Structure):
    structure = (
        ("num_components", ">h"),
        ("realmlen", ">h-realm"),
        ("realm", ":"),
        ("components", ":"),
        ("restdata", ":"),
    )

    def fromString(self, data):
        self.components = []
        Structure.fromString(self, data)
        data = self["components"]
        for i in range(self["num_components"]):
            ktentry = OctetString(data)
            data = data[ktentry["len"] + 2 :]
            self.components.append(ktentry)
        self.restfields = KeyTabContentRest(data)

    def getData(self):
        self["num_components"] = len(self.components)
        self["components"] = b"".join([component.getData() for component in self.components])
        self["restdata"] = self.restfields.getData()
        data = Structure.getData(self)
        return data


class KeyTabEntry(Structure):
    structure = (("size", ">I-content"), ("content", ":", KeyTabContent))


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

    def _parse_keytab(self, file_data):
        """Parse a keytab file and extract key information with robust error handling."""
        entries = []

        # Check for minimum keytab file size
        if len(file_data) < 4:
            entries.append({"error": "File too small to be a valid keytab"})
            return entries

        # Verify keytab version at the beginning of the file
        try:
            version = unpack("H", file_data[0:2])[0]
            if version != 0x502:
                entries.append({"error": f"Unexpected keytab version: 0x{version:x}"})
                # Continue processing anyway as best effort
        except Exception as e:
            entries.append({"error": f"Failed to parse keytab version: {str(e)}"})

        # Try the standard parsing approach first
        try:
            keytab = KeyTab()
            keytab.fromString(file_data)

            for entry in keytab.entries:
                try:
                    content = entry["content"]

                    # Extract realm
                    realm = content["realm"].decode("utf-8", errors="replace")

                    # Extract principal components
                    principal_components = []
                    for component in content.components:
                        principal_components.append(component["value"].decode("utf-8", errors="replace"))

                    principal = "/".join(principal_components)

                    # Extract key information
                    key_type = content.restfields["keytype"]
                    key_type_name = self.key_types.get(key_type, f"Unknown ({key_type})")
                    key = content.restfields["key"]
                    key_hex = binascii.hexlify(key).decode("ascii")

                    # Extract timestamp if available
                    timestamp = content.restfields["timestamp"]
                    if timestamp > 0:
                        timestamp_dt = datetime.fromtimestamp(timestamp, tz=UTC).isoformat()
                    else:
                        timestamp_dt = "N/A"

                    # Create entry information
                    entry_info = {
                        "realm": realm,
                        "principal": principal,
                        "key_type": key_type,
                        "key_type_name": key_type_name,
                        "key_length": len(key) * 8,  # Length in bits
                        "key": key_hex,
                        "timestamp": timestamp_dt,
                        "kvno": content.restfields["vno8"],
                    }

                    entries.append(entry_info)

                except Exception as e:
                    logger.error(f"Error parsing keytab entry: {str(e)}")
                    entries.append({"error": f"Error in entry: {str(e)}"})

            # If we got here and have entries, return them
            if entries:
                return entries

        except Exception as e:
            logger.error(f"Standard parsing approach failed: {str(e)}")
            # Continue to fallback parsing methods

        # Fallback: Manual parsing for common keytab format
        try:
            # Skip the 2-byte header
            data = file_data[2:]
            offset = 0

            while offset < len(data):
                try:
                    # Each entry starts with its size
                    if offset + 4 > len(data):
                        break

                    entry_size = unpack(">I", data[offset : offset + 4])[0]

                    # Sanity check on entry size
                    if entry_size <= 0 or entry_size > len(data) - offset:
                        offset += 4  # Skip this problematic entry
                        continue

                    # Get the raw entry data
                    entry_data = data[offset + 4 : offset + 4 + entry_size]
                    offset += 4 + entry_size

                    # Try to extract key data from the entry
                    # This is a simplified approach focusing on finding key material
                    if len(entry_data) >= 20:  # Minimum size for a meaningful entry
                        # Look for key type and key data markers
                        for i in range(len(entry_data) - 8):
                            # Check for patterns that might indicate key type and length fields
                            if i + 8 <= len(entry_data):
                                try:
                                    possible_key_type = unpack(">H", entry_data[i : i + 2])[0]
                                    possible_key_len = unpack(">H", entry_data[i + 2 : i + 4])[0]

                                    # Validate key type and length
                                    if possible_key_type in self.key_types and 8 <= possible_key_len <= 64:
                                        if i + 4 + possible_key_len <= len(entry_data):
                                            key_data = entry_data[i + 4 : i + 4 + possible_key_len]
                                            key_hex = binascii.hexlify(key_data).decode("ascii")

                                            entry_info = {
                                                "realm": "Unknown (manual extraction)",
                                                "principal": "Unknown (manual extraction)",
                                                "key_type": possible_key_type,
                                                "key_type_name": self.key_types.get(
                                                    possible_key_type, f"Unknown ({possible_key_type})"
                                                ),
                                                "key_length": possible_key_len * 8,
                                                "key": key_hex,
                                                "timestamp": "Unknown (manual extraction)",
                                                "kvno": 0,  # Unknown in this fallback method
                                                "note": "Extracted using fallback method - limited metadata available",
                                            }
                                            entries.append(entry_info)
                                except Exception:
                                    # Continue searching through the entry data
                                    continue
                except Exception as e:
                    logger.error(f"Error in fallback parsing of entry at offset {offset}: {str(e)}")
                    # Continue to next potential entry

            # If we found some entries using the fallback method
            if entries:
                return entries

        except Exception as e:
            logger.error(f"Fallback parsing method failed: {str(e)}")

        # If we got here with no entries, check for hex patterns that might be keys
        if not entries:
            try:
                # Last-resort attempt: look for hex patterns that might be keys
                # Common key sizes: RC4 (16 bytes), AES-128 (16 bytes), AES-256 (32 bytes)
                key_candidates = []

                # Convert to hex for pattern searching
                hex_data = binascii.hexlify(file_data).decode("ascii")

                # Look for 32-character (16 bytes) and 64-character (32 bytes) hex sequences
                # that might be keys (excluding long sequences of zeros or repeated characters)
                for length in [32, 64]:  # Hex characters, representing 16 or 32 bytes
                    for i in range(0, len(hex_data) - length, 2):
                        segment = hex_data[i : i + length]

                        # Skip if it's all zeros or a single repeated character
                        if segment == "0" * length or all(c == segment[0] for c in segment):
                            continue

                        # Check for sufficient entropy in the potential key
                        unique_chars = len(set(segment))
                        if unique_chars > 10:  # Require some entropy
                            key_candidates.append(segment)

                # Add found potential keys
                for i, key in enumerate(key_candidates):
                    entries.append(
                        {
                            "realm": "Unknown (hex pattern extraction)",
                            "principal": f"Potential key {i + 1}",
                            "key_type": 0,
                            "key_type_name": "Unknown (hex pattern extraction)",
                            "key_length": len(key) * 4,  # Hex characters × 4 bits
                            "key": key,
                            "timestamp": "Unknown (hex pattern extraction)",
                            "kvno": 0,
                            "note": "Potential key extracted by hex pattern matching - use with caution",
                        }
                    )
            except Exception as e:
                logger.error(f"Pattern-based extraction failed: {str(e)}")

        # If we still found nothing, add an error entry
        if not entries:
            entries.append({"error": "Failed to parse keytab file using all available methods"})

        return entries

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
                report_lines.append(f"\n**Principal**: {entry['principal']}@{entry['realm']}")
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
                    key_summary += f"- **Principal:** {entry['principal']}@{entry['realm']}\n"
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

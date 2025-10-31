import base64
import binascii

from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule
from file_enrichment_modules.yara.yara_manager import YaraRuleManager

logger = get_logger(__name__)


def yara_match_to_markdown(match):
    markdown = [
        f"# Yara Rule: {match['rule_name']}",
    ]
    try:
        if "rule_description" in match and match["rule_description"]:
            markdown.append(f"{match['rule_description']}\n")

        markdown.append('### Matches\nMatching strings in the form of "<offset>: <matched data>".')

        for string_match in match["rule_string_matches"]:
            markdown.append(f"\n**Yara Rule Identifier:** `{string_match['identifier']}`\n```text")
            for instance in string_match["yara_string_match_instances"]:
                if "matched_data_text" in instance:
                    markdown.extend([f"0x{instance['offset']:08x}: {instance['matched_data_text']}"])
                elif "matched_data_hex" in instance:
                    markdown.extend([f"0x{instance['offset']:08x}: {instance['matched_data_hex']}"])
                else:
                    markdown.extend([f"0x{instance['offset']:08x}: {instance['matched_data_b64']}"])

        markdown.append("```\n")

        if "rule_text" in match and match["rule_text"]:
            markdown.extend(["# Rule Text", f"```yara\n{match['rule_text']}"])
        else:
            markdown.extend(["# Rule Text", "```text\n*Rule text not available*"])

        markdown.append("```")
    except Exception as e:
        markdown.append(f"\n**Error in building markdown from Yara-x match in `yara` file_enrichment module:** {e}")
    return "\n".join(markdown)


def format_hex_like_xxd(data):
    """Format binary data as hex string similar to xxd output."""
    hex_str = binascii.hexlify(data).decode("ascii")
    # Group hex bytes in pairs of 4 (8 characters)
    return " ".join(hex_str[i : i + 8] for i in range(0, len(hex_str), 8))


class YaraScanner(EnrichmentModule):
    name: str = "yara_scanner"
    dependencies: list[str] = []

    def __init__(self):
        self.storage = StorageMinio()

        self.asyncpg_pool = None  # type: ignore
        self.rule_manager = YaraRuleManager()
        # the workflows this module should automatically run in
        self.workflows = ["default"]

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Always returns True as Yara scanning should run on all files."""
        return True

    def _analyze_yara(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze file using Yara rules and generate enrichment result.

        Args:
            file_path: Path to the file to analyze with Yara
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        # Get scan results
        scan_results = self.rule_manager.match(file_path)

        enrichment_result = EnrichmentResult(module_name=self.name)

        yara_matches = []
        for rule in scan_results:
            rule_text = self.rule_manager.get_rule_content(rule.identifier)
            yara_match = {"rule_name": rule.identifier, "rule_string_matches": [], "rule_text": rule_text}

            # Add metadata if available
            metadata_dict = dict(rule.metadata)
            if "description" in metadata_dict:
                yara_match["rule_description"] = metadata_dict["description"]

            # Process patterns (strings in yara-x)
            for pattern in rule.patterns:
                if pattern.matches:  # Only process patterns that had matches
                    string_match = {
                        "identifier": pattern.identifier,
                        "yara_string_match_instances": [],
                    }

                    for match in pattern.matches:
                        if match.length < 1000:
                            # Read the matched data from the file
                            with open(file_path, "rb") as f:
                                f.seek(match.offset)
                                matched_data = f.read(match.length)

                                string_match_instance = {
                                    "offset": match.offset,
                                    "length": match.length,
                                }

                                # Always include base64 representation for compatibility
                                string_match_instance["matched_data_b64"] = base64.b64encode(matched_data).decode(
                                    "utf-8"
                                )

                                # Format differently based on file type
                                if hasattr(file_enriched, "is_plaintext") and file_enriched.is_plaintext:
                                    try:
                                        # Try to decode as UTF-8
                                        string_match_instance["matched_data_text"] = matched_data.decode("utf-8")
                                    except UnicodeDecodeError:
                                        try:
                                            # Fallback to a more lenient encoding
                                            string_match_instance["matched_data_text"] = matched_data.decode(
                                                "unicode_escape"
                                            )
                                        except:
                                            # If both decodings fail, use hex format
                                            string_match_instance["matched_data_hex"] = format_hex_like_xxd(
                                                matched_data
                                            )
                                else:
                                    # Binary file - format as hex
                                    string_match_instance["matched_data_hex"] = format_hex_like_xxd(matched_data)
                        else:
                            logger.warning(
                                f"Yara match for rule '{rule.identifier}' is length {match.length}, not including in base64 data"
                            )
                            string_match_instance = {
                                "offset": match.offset,
                                "length": match.length,
                            }
                        string_match["yara_string_match_instances"].append(string_match_instance)

                    yara_match["rule_string_matches"].append(string_match)

                    summary_markdown = yara_match_to_markdown(yara_match)
                    display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

                    finding = Finding(
                        category=FindingCategory.YARA_MATCH,
                        finding_name="yara_match",
                        origin_type=FindingOrigin.ENRICHMENT_MODULE,
                        origin_name=self.name,
                        object_id=file_enriched.object_id,
                        severity=8,
                        raw_data={"match": yara_match},
                        data=[display_data],
                    )

                    if not enrichment_result.findings:
                        enrichment_result.findings = []

                    enrichment_result.findings.append(finding)

            yara_matches.append(yara_match)

        if yara_matches:
            enrichment_result.results = {"yara_matches": yara_matches}
            return enrichment_result
        return None

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process file using Yara scanning.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file

        Returns:
            EnrichmentResult or None if processing fails
        """
        try:
            # Get the current file_enriched from the database backend
            file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

            # Use provided file_path if available, otherwise download
            if file_path:
                return self._analyze_yara(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_yara(temp_file.name, file_enriched)

        except Exception:
            logger.exception(message="Error in process()")


def create_enrichment_module() -> EnrichmentModule:
    return YaraScanner()

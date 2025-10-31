# enrichment_modules/pii/analyzer.py
import tempfile
import threading
from pathlib import Path

import yara_x
from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)


class PIIAnalyzer(EnrichmentModule):
    name: str = "pii_analyzer"
    dependencies: list[str] = []
    _thread_local = threading.local()

    def __init__(self):
        self.storage = StorageMinio()

        self.asyncpg_pool = None  # type: ignore
        self.size_limit = 50_000_000  # 50MB size limit
        # the workflows this module should automatically run in
        self.workflows = ["default"]

        # Compile the rules once during initialization
        self._compiler = yara_x.Compiler()
        self._compiler.add_source(r"""
rule detect_pii
{
    meta:
        description = "Detects various types of PII including credit cards, SSNs, crypto addresses, and passport numbers"
        date = "2025-01-28"

    strings:
        // UK NHS Number
        $nhs = /[0-9]{3}\\s[0-9]{3}\\s[0-9]{4}/ fullword

        // UK National Insurance Number
        $nino = /[A-CE-HJ-PR-T-WYZ][A-CE-HJ-PR-T-WYZ][0-9]{6}[A-CFHJ-NPR-TW-Z]/ fullword

        // Credit Card Numbers
        $cc1 = /4[0-9]{12}(?:[0-9]{3})?/ fullword  // Visa
        $cc2 = /5[1-5][0-9]{14}/ fullword           // MasterCard
        $cc3 = /3[47][0-9]{13}/ fullword            // American Express
        $cc4 = /6(?:011|5[0-9]{2})[0-9]{12}/ fullword  // Discover

        // US Social Security Numbers
        $ssn = /([0-6][0-9]{2}|7[0-6][0-9]|77[0-9]|8[0-8][0-9]|89[0-9])-([0-9][1-9]|[1-9][0-9])-[1-9][0-9]{3}/ fullword

        // Crypto Addresses
        //$btc1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ fullword
        //$btc2 = /bc1[a-zA-HJ-NP-Z0-9]{25,39}/ fullword
        //$eth = /0x[a-fA-F0-9]{40}/ fullword

        // US Passport Numbers
        //$passport = /[0-9]{9}|[A-Z][0-9]{8}/ fullword

    condition:
        any of ($cc*) or
        $ssn or
        //any of ($btc*) or
        //$eth or
        //$passport or
        $nhs or
        $nino
}
        """)
        self._compiled_rules = self._compiler.build()

    def _get_scanner(self) -> yara_x.Scanner | None:
        """Get or create thread-local scanner instance."""
        if not hasattr(self._thread_local, "scanner"):
            if self._compiled_rules:
                self._thread_local.scanner = yara_x.Scanner(self._compiled_rules)
                self._thread_local.scanner.set_timeout(60)
            else:
                return None
        return self._thread_local.scanner

    def _clear_scanner(self):
        """Clear the thread-local scanner if it exists."""
        if hasattr(self._thread_local, "scanner"):
            delattr(self._thread_local, "scanner")

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if file should be processed based on size and content."""
        file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

        if file_enriched.is_plaintext:
            if file_enriched.size > self.size_limit:
                logger.warning(
                    f"[pii_analyzer] file {file_enriched.path} ({file_enriched.object_id} / {file_enriched.size} bytes) exceeds the size limit of {self.size_limit} bytes, only analyzing the first {self.size_limit} bytes"
                )

            if file_path:
                # Use provided file path - read only the needed bytes
                with open(file_path, "rb") as f:
                    num_bytes = min(file_enriched.size, self.size_limit)
                    file_bytes = f.read(num_bytes)
            else:
                # Fallback to downloading the file itself
                num_bytes = file_enriched.size if file_enriched.size < self.size_limit else self.size_limit
                file_bytes = self.storage.download_bytes(file_enriched.object_id, length=num_bytes)

            scanner = self._get_scanner()
            if not scanner:
                logger.warning("No Yara rules compiled")
                return False

            matches = scanner.scan(file_bytes)
            should_run = len(list(matches.matching_rules)) > 0

            return should_run
        else:
            return False

    def _get_match_context(self, content: str, offset: int, length: int, context_size: int = 50) -> str:
        """Get surrounding context for a match position."""
        start = max(0, offset - context_size)
        end = min(len(content), offset + length + context_size)
        return content[start:end]

    def _categorize_match(self, pattern_id: str) -> str:
        """Categorize the type of PII based on the pattern identifier."""
        # Pattern IDs come directly from the Yara rule identifiers
        if pattern_id in ["cc1", "cc2", "cc3", "cc4"]:
            return "Credit Card Number"
        elif pattern_id == "ssn":
            return "Social Security Number"
        elif pattern_id in ["btc1", "btc2"]:
            return "Bitcoin Address"
        elif pattern_id == "eth":
            return "Ethereum Address"
        elif pattern_id == "passport":
            return "US Passport Number"
        elif pattern_id == "nhs":
            return "NHS Number"
        elif pattern_id == "nino":
            return "National Insurance Number"
        return "Unknown"

    def _create_finding_summary(self, findings_by_type: dict[str, list[dict]]) -> str:
        """Create a markdown summary of PII findings."""
        summary = "# Detected PII\n\n"
        summary += "## Executive Summary\n\n"

        total_findings = sum(len(matches) for matches in findings_by_type.values())
        summary += f"Total PII instances detected: {total_findings}\n\n"

        # Add table header
        summary += "### Types of PII Found\n\n"
        summary += "| Type | Instances |\n"
        summary += "|------|----------:|\n"

        for pii_type, matches in findings_by_type.items():
            summary += f"| {pii_type} | {len(matches)} |\n"

        summary += "\n## Detailed Findings\n\n"

        for pii_type, matches in findings_by_type.items():
            summary += f"### {pii_type}\n"
            summary += f"Total instances found: {len(matches)}\n\n"

            if matches:
                summary += "| Location | Context |\n"
                summary += "|----------|----------|\n"
                # Show up to 3 examples with context
                for match in matches[:3]:
                    context = match["context"].replace("\n", " ").strip()
                    summary += f"| Offset {match['offset']} | ...{context}... |\n"
                summary += "\n"

        summary += "*Note: This report shows up to 3 examples per category. Additional instances may exist.*\n"

        return summary

    def _analyze_pii(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze file for PII and generate enrichment result.

        Args:
            file_path: Path to the file to analyze for PII
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

        scanner = self._get_scanner()
        if not scanner:
            logger.warning("No Yara rules compiled")
            return None

        try:
            content = Path(file_path).read_text(encoding="utf-8")
            file_bytes = content.encode("utf-8")

            scan_results = scanner.scan(file_bytes)
            findings_by_type = {}

            for rule in scan_results.matching_rules:
                for pattern in rule.patterns:
                    if pattern.matches:
                        # Get the pattern name directly from the identifier
                        # Remove the $ prefix that Yara adds to pattern names
                        pattern_name = pattern.identifier.lstrip("$")
                        pii_type = self._categorize_match(pattern_name)

                        if pii_type not in findings_by_type:
                            findings_by_type[pii_type] = []

                        for match in pattern.matches:
                            if match.length < 1000:
                                value = content[match.offset : match.offset + match.length]
                                context = self._get_match_context(content, match.offset, match.length)

                                findings_by_type[pii_type].append(
                                    {
                                        "value": value,
                                        "context": context,
                                        "offset": match.offset,
                                        "length": match.length,
                                        "pattern_id": pattern_name,  # Store the clean pattern name
                                    }
                                )

            if findings_by_type:
                # Create finding summary
                summary_markdown = self._create_finding_summary(findings_by_type)

                # Create display data
                display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

                # Create finding
                finding = Finding(
                    category=FindingCategory.PII,
                    finding_name="pii_detected",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=file_enriched.object_id,
                    severity=8,
                    raw_data={"findings": findings_by_type},
                    data=[display_data],
                )

                enrichment_result.findings = [finding]
                enrichment_result.results = {"pii_detected": findings_by_type}

                # Create a displayable version of the results
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_display_file:
                    display = "PII Analysis Results\n==================\n\n"
                    for pii_type, matches in findings_by_type.items():
                        display += f"{pii_type}:\n"
                        display += f"  Total instances: {len(matches)}\n"
                        display += "  Found Values:\n"
                        for match in matches:
                            display += f"    - Offset {match['offset']}: {match['value']}\n"
                        display += "\n"

                    tmp_display_file.write(display)
                    tmp_display_file.flush()

                    object_id = self.storage.upload_file(tmp_display_file.name)

                    displayable_parsed = Transform(
                        type="displayable_parsed",
                        object_id=f"{object_id}",
                        metadata={
                            "file_name": f"{file_enriched.file_name}_pii_analysis.txt",
                            "display_type_in_dashboard": "monaco",
                            "default_display": True,
                        },
                    )
                    enrichment_result.transforms = [displayable_parsed]

            return enrichment_result

        except Exception:
            logger.exception(message=f"Error analyzing PII for {file_enriched.file_name}")
            return None

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process file to detect PII using Yara rules.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file

        Returns:
            EnrichmentResult or None if processing fails
        """
        try:
            file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

            # Use provided file_path if available, otherwise download
            if file_path:
                return self._analyze_pii(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_pii(temp_file.name, file_enriched)

        except Exception:
            logger.exception(message="Error processing file for PII detection")
            return None


def create_enrichment_module() -> EnrichmentModule:
    """Factory function to create the PII analyzer module."""
    return PIIAnalyzer()

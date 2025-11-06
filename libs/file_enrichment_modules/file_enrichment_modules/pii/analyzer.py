# enrichment_modules/pii/analyzer.py
import os
import tempfile
import threading
from pathlib import Path

from presidio_analyzer import AnalyzerEngine
from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)

# PII entity configuration: maps Presidio entity types to display names
#   To add more entities, just add them to this dict and they'll be detected automatically
#   Entities are defined here: https://microsoft.github.io/presidio/supported_entities/
PII_ENTITY_CONFIG = {
    "CREDIT_CARD": "Credit Card Number",
    "US_SSN": "Social Security Number",
    "UK_NINO": "National Insurance Number",
}

# Entities to detect (derived from config)
SUPPORTED_PII_ENTITIES = list(PII_ENTITY_CONFIG.keys())

# Minimum confidence score for PII detection (configurable via environment)
PII_DETECTION_THRESHOLD = float(os.getenv("PII_DETECTION_THRESHOLD", "0.5"))


class PIIAnalyzer(EnrichmentModule):
    name: str = "pii_analyzer"
    dependencies: list[str] = []
    _thread_local = threading.local()

    def __init__(self):
        self.storage = StorageMinio()

        self.asyncpg_pool = None  # type: ignore
        self.size_limit = 10_000_000  # 10MB size limit
        # the workflows this module should automatically run in
        self.workflows = ["default"]

    def _get_analyzer(self) -> AnalyzerEngine:
        """Get or create thread-local AnalyzerEngine instance."""
        if not hasattr(self._thread_local, "analyzer"):
            self._thread_local.analyzer = AnalyzerEngine()
        return self._thread_local.analyzer

    def _clear_analyzer(self):
        """Clear the thread-local analyzer if it exists."""
        if hasattr(self._thread_local, "analyzer"):
            delattr(self._thread_local, "analyzer")

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if file should be processed based on plaintext detection.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file (unused in this implementation)

        Returns:
            True if the file is plaintext, False otherwise
        """
        file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

        if file_enriched.is_plaintext:
            if file_enriched.size > self.size_limit:
                logger.warning(
                    f"[pii_analyzer] file {file_enriched.path} ({file_enriched.object_id} / {file_enriched.size} bytes) exceeds the size limit of {self.size_limit} bytes, only analyzing the first {self.size_limit} bytes"
                )
            return True

        return False

    def _get_match_context(self, content: str, offset: int, length: int, context_size: int = 50) -> str:
        """Get surrounding context for a match position."""
        start = max(0, offset - context_size)
        end = min(len(content), offset + length + context_size)
        return content[start:end]

    def _categorize_match(self, entity_type: str) -> str:
        """Categorize the type of PII based on Presidio entity type.

        Args:
            entity_type: The Presidio entity type (e.g., "CREDIT_CARD", "US_SSN")

        Returns:
            Human-readable display name for the PII type
        """
        return PII_ENTITY_CONFIG.get(entity_type, entity_type)

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
        """Analyze file for PII using Presidio and generate enrichment result.

        Args:
            file_path: Path to the file to analyze for PII
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

        analyzer = self._get_analyzer()

        try:
            # Read file with size limit
            content = Path(file_path).read_text(encoding="utf-8")

            # Truncate content if it exceeds size limit
            if len(content.encode("utf-8")) > self.size_limit:
                # Find a safe truncation point (approximate character position)
                approx_chars = int(self.size_limit * len(content) / len(content.encode("utf-8")))
                content = content[:approx_chars]

            # Analyze with Presidio
            results = analyzer.analyze(
                text=content,
                entities=SUPPORTED_PII_ENTITIES,
                language='en'
            )

            # Filter by threshold and organize by type
            findings_by_type = {}

            for result in results:
                # Filter by confidence threshold
                if result.score < PII_DETECTION_THRESHOLD:
                    continue

                pii_type = self._categorize_match(result.entity_type)

                if pii_type not in findings_by_type:
                    findings_by_type[pii_type] = []

                # Extract the matched value and context
                value = content[result.start:result.end]
                length = result.end - result.start
                context = self._get_match_context(content, result.start, length)

                findings_by_type[pii_type].append(
                    {
                        "value": value,
                        "context": context,
                        "offset": result.start,
                        "length": length,
                        "score": result.score,
                        "entity_type": result.entity_type,
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
                    severity=4,
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
        """Process file to detect PII using Microsoft Presidio.

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

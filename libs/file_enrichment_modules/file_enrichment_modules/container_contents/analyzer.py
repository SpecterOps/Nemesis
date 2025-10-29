# enrichment_modules/container_contents/analyzer.py
import os
import tempfile

from common.helpers import is_container
from common.logger import get_logger
from common.models import EnrichmentResult, File, Transform
from common.storage import StorageMinio
from dapr.clients import DaprClient
from file_enrichment_modules.container_contents.containers import ContainerExtractor
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)


class ContainerContentsAnalyzer(EnrichmentModule):
    name: str = "container_contents_analyzer"
    dependencies: list[str] = []
    def __init__(self):
        self.storage = StorageMinio()

        # Configuration for container extraction
        self.extracted_archive_size_limit = 1_073_741_824  # 1GB default

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run."""
        file_enriched = await get_file_enriched_async(object_id)

        # Check if the file is a supported container type
        should_run = is_container(file_enriched.mime_type)

        logger.info(
            f"ContainerContentsAnalyzer should_run: {should_run}",
            mime_type=file_enriched.mime_type,
            path=file_enriched.path,
        )
        return should_run

    def _generate_container_summary(self, extracted_files):
        """Generate a markdown summary of extracted container contents."""
        summary_lines = []
        summary_lines.append("# Container Contents Summary")
        summary_lines.append(f"\nTotal files extracted: {len(extracted_files)}")

        # Group files by type
        file_types = {}
        for file in extracted_files:
            ext = os.path.splitext(file.path)[1].lower()
            if ext:
                file_types[ext] = file_types.get(ext, 0) + 1

        if file_types:
            summary_lines.append("\n## File Types")
            summary_lines.append("\n| Extension | Count |")
            summary_lines.append("| --------- | ----- |")
            for ext, count in sorted(file_types.items(), key=lambda x: x[1], reverse=True):
                summary_lines.append(f"| {ext} | {count} |")

        # List of extracted files
        summary_lines.append("\n## Extracted Files")
        summary_lines.append("\n| Path |")
        summary_lines.append("| ---- |")
        for file in sorted(extracted_files, key=lambda x: x.path):
            safe_path = file.path.replace("|", "\\|")
            summary_lines.append(f"| {safe_path} |")

        return "\n".join(summary_lines)

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process container file and extract its contents."""
        try:
            file_enriched = await get_file_enriched_async(object_id)
            enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)
            transforms = []
            extracted_files = []

            # Initialize DaprClient and ContainerExtractor
            with DaprClient() as dapr_client:
                # Create a subclass to capture extracted files
                class TrackingContainerExtractor(ContainerExtractor):
                    def publish_file_message(self, file_message: File):
                        extracted_files.append(file_message)
                        super().publish_file_message(file_message)

                tracking_extractor = TrackingContainerExtractor(
                    self.storage,
                    dapr_client,
                    self.extracted_archive_size_limit,
                )

                # Extract the container contents
                tracking_extractor.extract(file_enriched)

                # Generate and store the summary report
                summary_content = self._generate_container_summary(extracted_files)

                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_report:
                    tmp_report.write(summary_content)
                    tmp_report.flush()
                    summary_object_id = self.storage.upload_file(tmp_report.name)

                    transforms.append(
                        Transform(
                            type="extraction_summary",
                            object_id=str(summary_object_id),
                            metadata={
                                "file_name": "container_contents.md",
                                "display_type_in_dashboard": "markdown",
                                "default_display": True,
                            },
                        )
                    )

                enrichment_result.transforms = transforms
                return enrichment_result

        except Exception:
            logger.exception(message="Error processing container contents")
            raise


def create_enrichment_module() -> EnrichmentModule:
    return ContainerContentsAnalyzer()

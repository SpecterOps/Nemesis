# enrichment_modules/container/analyzer.py
import tarfile
import tempfile
import zipfile
from datetime import UTC, datetime

import py7zr
from common.helpers import is_container
from common.logger import get_logger
from common.models import EnrichmentResult, Transform
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)


class ContainerAnalyzer(EnrichmentModule):
    name: str = "container_analyzer"
    dependencies: list[str] = []
    def __init__(self):
        self.storage = StorageMinio()
        self.workflows = ["default"]

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file (not used by container analyzer)
        """
        file_enriched = get_file_enriched(object_id)
        return is_container(file_enriched.mime_type)

    def _format_size(self, size_in_bytes: int) -> str:
        """Convert size in bytes to human readable format."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_in_bytes < 1024:
                return f"{size_in_bytes:.2f} {unit}"
            size_in_bytes //= 1024
        return f"{size_in_bytes:.2f} TB"

    def _analyze_zip(self, file_path: str) -> list[tuple[str, int]]:
        """Get contents of a ZIP file without extraction."""
        with zipfile.ZipFile(file_path) as zf:
            return [(info.filename, info.file_size) for info in zf.filelist]

    def _analyze_7z(self, file_path: str) -> list[tuple[str, int]]:
        """Get contents of a 7z file without extraction."""
        with py7zr.SevenZipFile(file_path) as sz:
            files = []
            for filename, info in sz.files.items():
                # 7z files might not have size info for some files
                size = info.uncompressed if hasattr(info, "uncompressed") else 0
                files.append((filename, size))
            return files

    def _analyze_tar(self, file_path: str) -> list[tuple[str, int]]:
        """Get contents of a TAR file without extraction."""
        with tarfile.open(file_path) as tf:
            return [(member.name, member.size) for member in tf.getmembers() if member.isfile()]

    def _analyze_container(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze container file and generate enrichment result.

        Args:
            file_path: Path to the container file to analyze
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

        try:
            # Analyze based on file type
            if zipfile.is_zipfile(file_path):
                files = self._analyze_zip(file_path)
            elif py7zr.is_7zfile(file_path):
                files = self._analyze_7z(file_path)
            elif tarfile.is_tarfile(file_path):
                files = self._analyze_tar(file_path)
            else:
                logger.warning(f"Unsupported container format for {file_enriched.file_name}")
                return None

            # Generate the report
            report_lines = []
            report_lines.append(f"# Container Contents: {file_enriched.file_name}")
            report_lines.append(f"\nAnalysis timestamp: {datetime.now(UTC).isoformat()}")

            # Calculate summary
            total_size = sum(size for _, size in files)
            file_count = len(files)

            # Add summary
            report_lines.append("\n## Summary")
            report_lines.append(f"- Total files: {file_count}")
            report_lines.append(f"- Total size: {self._format_size(total_size)}")

            git_repo_count = 0
            for filepath, _size in sorted(files):
                if filepath.endswith(".git/config") or filepath.endswith(".git\\config"):
                    git_repo_count += 1
            if git_repo_count > 0:
                report_lines.append(f"- Contains {git_repo_count} .git repos")

            # Add file listing
            report_lines.append("\n## File Listing")
            report_lines.append("\n| File Path | Size |")
            report_lines.append("| --------- | ---- |")

            # Add each file to the table
            for filepath, size in sorted(files):
                # Escape any pipe characters in the path
                safe_path = filepath.replace("|", "\\|")
                report_lines.append(f"| {safe_path} | {self._format_size(size)} |")

            # Create the transform
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_report:
                tmp_report.write("\n".join(report_lines))
                tmp_report.flush()
                transform_object_id = self.storage.upload_file(tmp_report.name)

                enrichment_result.transforms = [
                    Transform(
                        type="container_contents",
                        object_id=f"{transform_object_id}",
                        metadata={
                            "file_name": f"{file_enriched.file_name}_contents.md",
                            "display_type_in_dashboard": "markdown",
                            "default_display": True,
                        },
                    )
                ]

        except Exception as e:
            logger.exception(e, message=f"Error analyzing container contents for {file_enriched.file_name}")
            return None

        return enrichment_result

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process container file and list its contents without extraction.

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
                return self._analyze_container(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_container(temp_file.name, file_enriched)

        except Exception as e:
            logger.exception(e, message="Error in container analyzer")


def create_enrichment_module() -> EnrichmentModule:
    return ContainerAnalyzer()

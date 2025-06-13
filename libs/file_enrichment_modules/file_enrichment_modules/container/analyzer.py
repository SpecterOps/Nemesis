# enrichment_modules/container/analyzer.py
import tempfile
from datetime import UTC, datetime
import zipfile
import py7zr
import tarfile

import structlog
from common.models import EnrichmentResult, Transform
from common.state_helpers import get_file_enriched
from common.helpers import is_container
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule

logger = structlog.get_logger(module=__name__)


class ContainerAnalyzer(EnrichmentModule):
    def __init__(self):
        super().__init__("container_analyzer")
        self.storage = StorageMinio()
        self.workflows = ["default"]

    def should_process(self, object_id: str) -> bool:
        """Determine if this module should run."""
        file_enriched = get_file_enriched(object_id)
        return is_container(file_enriched.mime_type)

    def _format_size(self, size_in_bytes: int) -> str:
        """Convert size in bytes to human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
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
                size = info.uncompressed if hasattr(info, 'uncompressed') else 0
                files.append((filename, size))
            return files

    def _analyze_tar(self, file_path: str) -> list[tuple[str, int]]:
        """Get contents of a TAR file without extraction."""
        with tarfile.open(file_path) as tf:
            return [(member.name, member.size) for member in tf.getmembers() if member.isfile()]

    def process(self, object_id: str) -> EnrichmentResult | None:
        """Process container file and list its contents without extraction."""
        try:
            file_enriched = get_file_enriched(object_id)
            enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

            with self.storage.download(file_enriched.object_id) as temp_file:
                # Analyze based on file type
                try:
                    if zipfile.is_zipfile(temp_file.name):
                        files = self._analyze_zip(temp_file.name)
                    elif py7zr.is_7zfile(temp_file.name):
                        files = self._analyze_7z(temp_file.name)
                    elif tarfile.is_tarfile(temp_file.name):
                        files = self._analyze_tar(temp_file.name)
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
                    report_lines.append(f"\n## Summary")
                    report_lines.append(f"- Total files: {file_count}")
                    report_lines.append(f"- Total size: {self._format_size(total_size)}")

                    git_repo_count = 0
                    for filepath, size in sorted(files):
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

        except Exception as e:
            logger.exception(e, message="Error in container analyzer")


def create_enrichment_module() -> EnrichmentModule:
    return ContainerAnalyzer()
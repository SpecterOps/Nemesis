# enrichment_modules/prefetch/analyzer.py
"""Windows Prefetch file analyzer module.

Parses Windows Prefetch files (.pf) to extract execution artifacts including:
- Executable name and prefetch hash
- Run count and last execution timestamps (up to 8 on Win8+)
- Volume information (device path, serial number, creation time)
- Files and directories accessed during execution

Supports all Windows versions: XP (v17), Vista/7 (v23), 8/8.1 (v26), 10/11 (v30/31).
Handles MAM-compressed prefetch files (Windows 10+) via libscca.
"""

import tempfile

import pyscca
import yara_x
from common.logger import get_logger
from common.models import EnrichmentResult, Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)

# Mapping of prefetch format versions to Windows versions
FORMAT_VERSION_MAP = {
    17: "Windows XP/2003",
    23: "Windows Vista/7",
    26: "Windows 8/8.1",
    30: "Windows 10",
    31: "Windows 10/11",
}


class PrefetchAnalyzer(EnrichmentModule):
    name: str = "prefetch_analyzer"
    dependencies: list[str] = []

    def __init__(self):
        self.storage = StorageMinio()
        self.asyncpg_pool = None  # type: ignore
        self.workflows = ["default"]

        # YARA rule to detect prefetch files by magic bytes
        # SCCA = uncompressed (Windows XP-8.1)
        # MAM\x04 = compressed (Windows 10+)
        self.yara_rule = yara_x.compile("""
rule Windows_Prefetch_File
{
    meta:
        description = "Detects Windows Prefetch files (SCCA and MAM formats)"

    strings:
        $scca_header = { ?? 00 00 00 53 43 43 41 }  // SCCA at offset 4
        $mam_header = { 4D 41 4D 04 }               // MAM compressed

    condition:
        $scca_header at 0 or $mam_header at 0
}
        """)

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should process the file."""
        file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

        # Check file extension first (fast path)
        if file_enriched.file_name.lower().endswith(".pf"):
            return True

        # Fall back to YARA detection for files without .pf extension
        if file_path:
            with open(file_path, "rb") as f:
                file_bytes = f.read(min(file_enriched.size, 1000))
        else:
            file_bytes = self.storage.download_bytes(object_id, length=min(file_enriched.size, 1000))

        return len(self.yara_rule.scan(file_bytes).matching_rules) > 0

    def _parse_prefetch(self, file_path: str) -> dict:
        """Parse a prefetch file using pyscca.

        Args:
            file_path: Path to the prefetch file

        Returns:
            Dict containing parsed prefetch data
        """
        pf = pyscca.file()
        pf.open(file_path)

        try:
            # Basic metadata
            data = {
                "format_version": pf.format_version,
                "windows_version": FORMAT_VERSION_MAP.get(pf.format_version, f"Unknown (v{pf.format_version})"),
                "executable_name": pf.executable_filename,
                "prefetch_hash": hex(pf.prefetch_hash) if pf.prefetch_hash else None,
                "run_count": pf.run_count,
                "last_run_times": [],
                "volumes": [],
                "filenames": [],
            }

            # Extract last run times (up to 8 on Windows 8+)
            for i in range(8):
                ts = pf.get_last_run_time(i)
                if ts and ts.year > 1601:  # Filter out null timestamps
                    data["last_run_times"].append(ts.isoformat())

            # Extract volume information
            for vol in pf.volumes:
                vol_data = {
                    "device_path": vol.device_path,
                    "serial_number": hex(vol.serial_number) if vol.serial_number else None,
                }
                # Get creation time if available
                try:
                    creation_time = vol.creation_time
                    if creation_time and creation_time.year > 1601:
                        vol_data["creation_time"] = creation_time.isoformat()
                except Exception:
                    pass
                data["volumes"].append(vol_data)

            # Extract filenames (files/DLLs accessed during execution)
            for filename in pf.filenames:
                if filename:
                    data["filenames"].append(filename)

            return data

        finally:
            pf.close()

    def _analyze_prefetch_file(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze prefetch file and generate enrichment result."""
        result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

        try:
            prefetch_data = self._parse_prefetch(file_path)

            # Generate markdown summary report
            report_lines = [
                "# Windows Prefetch Analysis",
                "",
                f"**File:** {file_enriched.file_name}",
                f"**Format Version:** {prefetch_data['format_version']} ({prefetch_data['windows_version']})",
                "",
                "## Execution Summary",
                "",
                f"**Executable:** `{prefetch_data['executable_name']}`",
                f"**Prefetch Hash:** `{prefetch_data['prefetch_hash']}`",
                f"**Run Count:** {prefetch_data['run_count']}",
                "",
            ]

            # Last run times
            if prefetch_data["last_run_times"]:
                report_lines.append("## Last Execution Times")
                report_lines.append("")
                for i, ts in enumerate(prefetch_data["last_run_times"]):
                    report_lines.append(f"{i + 1}. `{ts}`")
                report_lines.append("")

            # Volume information
            if prefetch_data["volumes"]:
                report_lines.append("## Volume Information")
                report_lines.append("")
                for i, vol in enumerate(prefetch_data["volumes"]):
                    report_lines.append(f"### Volume {i + 1}")
                    report_lines.append(f"- **Device Path:** `{vol['device_path']}`")
                    if vol.get("serial_number"):
                        report_lines.append(f"- **Serial Number:** `{vol['serial_number']}`")
                    if vol.get("creation_time"):
                        report_lines.append(f"- **Creation Time:** `{vol['creation_time']}`")
                    report_lines.append("")

            # Files accessed (show first 50 to avoid huge reports)
            if prefetch_data["filenames"]:
                report_lines.append("## Files Accessed")
                report_lines.append("")
                report_lines.append(f"Total files referenced: {len(prefetch_data['filenames'])}")
                report_lines.append("")

                display_count = min(50, len(prefetch_data["filenames"]))
                for filename in prefetch_data["filenames"][:display_count]:
                    report_lines.append(f"- `{filename}`")

                if len(prefetch_data["filenames"]) > display_count:
                    report_lines.append(f"- ... and {len(prefetch_data['filenames']) - display_count} more")
                report_lines.append("")

            # Create summary transform
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as tmp:
                tmp.write("\n".join(report_lines))
                tmp.flush()
                report_id = self.storage.upload_file(tmp.name)

            result.transforms.append(
                Transform(
                    type="prefetch_analysis",
                    object_id=str(report_id),
                    metadata={
                        "file_name": f"{file_enriched.file_name}_analysis.md",
                        "display_type_in_dashboard": "markdown",
                        "default_display": True,
                    },
                )
            )

            result.results = prefetch_data

            return result

        except Exception:
            logger.exception(message=f"Error analyzing prefetch file: {file_enriched.file_name}")
            return None

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process the prefetch file."""
        try:
            file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

            if file_path:
                return self._analyze_prefetch_file(file_path, file_enriched)
            else:
                with self.storage.download(object_id) as temp_file:
                    return self._analyze_prefetch_file(temp_file.name, file_enriched)

        except Exception:
            logger.exception(message="Error in prefetch analyzer")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return PrefetchAnalyzer()

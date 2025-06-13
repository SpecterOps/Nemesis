# enrichment_modules/chromium_history/analyzer.py
import csv
import sqlite3
import tempfile
from datetime import UTC, datetime, timedelta

import structlog
import yara_x
from common.models import EnrichmentResult, Transform
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio

from file_enrichment_modules.module_loader import EnrichmentModule

logger = structlog.get_logger(module=__name__)


class ChromeHistoryParser(EnrichmentModule):
    def __init__(self):
        super().__init__("chrome_history_parser")
        self.storage = StorageMinio()

        # the workflows this module should automatically run in
        self.workflows = ["default"]

        # Yara rule to check for Chrome History tables
        self.yara_rule = yara_x.compile("""
rule Chrome_Downloads_Tables
{
    meta:
        description = "Detects Chrome/Chromium downloads database tables"

    strings:
        $downloads_chain = "CREATE TABLE downloads_url_chains"
        $downloads_slice = "CREATE TABLE downloads_slices"

    condition:
        all of them
}
        """)

    def should_process(self, object_id: str) -> bool:
        """Determine if this module should run."""
        file_enriched = get_file_enriched(object_id)

        # Check if filename is exactly "History" and SQLite magic type
        if not (file_enriched.file_name == "History" and "sqlite 3.x database" in file_enriched.magic_type.lower()):
            return False

        # Verify Chrome history tables using Yara
        file_bytes = self.storage.download_bytes(file_enriched.object_id)
        should_run = len(self.yara_rule.scan(file_bytes).matching_rules) > 0

        logger.debug(f"ChromeHistoryParser should_run: {should_run}")
        return should_run

    def _chrome_time_to_iso(self, chrome_time: int) -> str:
        """Convert Chrome timestamp to ISO 8601."""
        if not chrome_time:
            return ""
        # Chrome stores timestamps as microseconds since 1601-01-01 UTC
        epoch = datetime(1601, 1, 1, tzinfo=UTC)
        dt = epoch + timedelta(microseconds=chrome_time)
        return dt.isoformat()

    def process(self, object_id: str) -> EnrichmentResult | None:
        """Process Chrome History database."""
        try:
            file_enriched = get_file_enriched(object_id)
            enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)
            transforms = []

            with self.storage.download(file_enriched.object_id) as temp_file:
                # Configure SQLite to handle non-UTF8 data
                def adapt_bytes(b):
                    return b.hex() if b is not None else None

                def convert_bytes(hex_str):
                    return bytes.fromhex(hex_str) if hex_str is not None else None

                sqlite3.register_adapter(bytes, adapt_bytes)
                sqlite3.register_converter("BLOB", convert_bytes)

                conn = sqlite3.connect(temp_file.name, detect_types=sqlite3.PARSE_DECLTYPES)
                # Set text factory to handle non-UTF8 strings
                conn.text_factory = lambda x: x.decode("utf-8", errors="replace")
                cursor = conn.cursor()

                # Generate summary report
                report_lines = []

                # URLs summary
                cursor.execute("SELECT COUNT(*) FROM urls")
                url_count = cursor.fetchone()[0]
                report_lines.append("# Chrome History Summary")
                report_lines.append(f"\nTotal URLs visited: {url_count}")

                # Top 10 visited URLs
                cursor.execute("""
                    SELECT url, visit_count
                    FROM urls
                    ORDER BY visit_count DESC
                    LIMIT 10
                """)
                report_lines.append("\n## Top 10 Most Visited URLs")
                report_lines.append("\n| URL | Visit Count |")
                report_lines.append("| --- | ----------- |")
                for url, count in cursor.fetchall():
                    report_lines.append(f"| {url} | {count} |")

                # Downloads summary
                cursor.execute("SELECT COUNT(*) FROM downloads")
                download_count = cursor.fetchone()[0]
                report_lines.append(f"\nTotal Downloads: {download_count}")

                # Recent downloads
                cursor.execute("""
                    SELECT target_path, tab_url, end_time
                    FROM downloads
                    ORDER BY end_time DESC
                    LIMIT 10
                """)
                report_lines.append("\n## Most Recent Downloads")
                report_lines.append("\n| Time | Path | Source URL |")
                report_lines.append("| ---- | ---- | ---------- |")
                for path, url, end_time in cursor.fetchall():
                    end_time_iso = self._chrome_time_to_iso(end_time)
                    # Escape pipe characters in paths and URLs to prevent table formatting issues
                    safe_path = path.replace("|", "\\|") if path else ""
                    safe_url = url.replace("|", "\\|") if url else ""
                    report_lines.append(f"| {end_time_iso} | {safe_path} | {safe_url} |")

                # Create summary report transform
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_report:
                    tmp_report.write("\n".join(report_lines))
                    tmp_report.flush()
                    object_id = self.storage.upload_file(tmp_report.name)

                    transforms.append(
                        Transform(
                            type="finding_summary",
                            object_id=f"{object_id}",
                            metadata={
                                "file_name": f"{file_enriched.file_name}.md",
                                "display_type_in_dashboard": "markdown",
                                "default_display": True,
                            },
                        )
                    )

                # Export URLs table
                cursor.execute("""
                    SELECT url, title, visit_count, last_visit_time
                    FROM urls
                """)
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="") as tmp_urls:
                    writer = csv.writer(tmp_urls)
                    writer.writerow(["url", "title", "visit_count", "last_visit_time"])
                    for row in cursor:
                        writer.writerow([row[0], row[1], row[2], self._chrome_time_to_iso(row[3])])
                    tmp_urls.flush()
                    object_id = self.storage.upload_file(tmp_urls.name)

                    transforms.append(
                        Transform(
                            type="chromium_urls",
                            object_id=f"{object_id}",
                            metadata={
                                "file_name": f"{file_enriched.file_name}_chromium_urls.csv",
                                "offer_as_download": True,
                            },
                        )
                    )

                # Export downloads table
                cursor.execute("""
                    SELECT target_path, total_bytes, end_time, tab_url, mime_type
                    FROM downloads
                """)
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="") as tmp_downloads:
                    writer = csv.writer(tmp_downloads)
                    writer.writerow(["target_path", "total_bytes", "end_time", "tab_url", "mime_type"])
                    for row in cursor:
                        writer.writerow([row[0], row[1], self._chrome_time_to_iso(row[2]), row[3], row[4]])
                    tmp_downloads.flush()
                    object_id = self.storage.upload_file(tmp_downloads.name)

                    transforms.append(
                        Transform(
                            type="chromium_downloads",
                            object_id=f"{object_id}",
                            metadata={
                                "file_name": f"{file_enriched.file_name}_chromium_downloads.csv",
                                "offer_as_download": True,
                            },
                        )
                    )

                conn.close()
                enrichment_result.transforms = transforms
                return enrichment_result

        except Exception as e:
            logger.exception(e, message="Error processing Chrome History database")


def create_enrichment_module() -> EnrichmentModule:
    return ChromeHistoryParser()

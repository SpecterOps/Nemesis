# enrichment_modules/chromium_history/analyzer.py
import csv
import sqlite3
import tempfile

import yara_x
from chromium import convert_chromium_timestamp, process_chromium_history
from common.logger import get_logger
from common.models import EnrichmentResult, Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)


class ChromeHistoryParser(EnrichmentModule):
    name: str = "chrome_history_parser"
    dependencies: list[str] = []
    def __init__(self):
        self.storage = StorageMinio()

        # the workflows this module should automatically run in
        self.workflows = ["default"]

        self.asyncpg_pool = None  # type: ignore

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

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file
        """

        file_enriched = await get_file_enriched_async(object_id)

        # Check if filename is exactly "History" and SQLite magic type
        if not (file_enriched.file_name == "History" and "sqlite 3.x database" in file_enriched.magic_type.lower()):
            return False

        if file_enriched.is_plaintext:
            return False

        if file_path:
            # Use provided file path
            with open(file_path, "rb") as f:
                file_bytes = f.read()
        else:
            # Fallback to downloading the file itself
            file_bytes = self.storage.download_bytes(file_enriched.object_id)

        # Verify Chrome history tables using Yara
        should_run = len(self.yara_rule.scan(file_bytes).matching_rules) > 0

        return should_run

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process Chrome History database.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file
        """
        try:
            file_enriched = await get_file_enriched_async(object_id)
            enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)
            transforms = []

            # Use the chromium library to process and insert into the database
            await process_chromium_history(object_id, file_path, self.asyncpg_pool)

            # Configure SQLite to handle non-UTF8 data for report generation
            def adapt_bytes(b):
                return b.hex() if b is not None else None

            def convert_bytes(hex_str):
                return bytes.fromhex(hex_str) if hex_str is not None else None

            sqlite3.register_adapter(bytes, adapt_bytes)
            sqlite3.register_converter("BLOB", convert_bytes)

            if file_path:
                # Use provided file path
                conn = sqlite3.connect(file_path, detect_types=sqlite3.PARSE_DECLTYPES)
            else:
                # Fallback to downloading the file itself
                with self.storage.download(file_enriched.object_id) as temp_file:
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
                end_time_iso = convert_chromium_timestamp(end_time, True)
                # Escape pipe characters in paths and URLs to prevent table formatting issues
                safe_path = path.replace("|", "\\|") if path else ""
                safe_url = url.replace("|", "\\|") if url else ""
                report_lines.append(f"| {end_time_iso} | {safe_path} | {safe_url} |")

            # Create summary report transform
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_report:
                tmp_report.write("\n".join(report_lines))
                tmp_report.flush()
                report_object_id = self.storage.upload_file(tmp_report.name)

                transforms.append(
                    Transform(
                        type="finding_summary",
                        object_id=f"{report_object_id}",
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
                    writer.writerow([row[0], row[1], row[2], convert_chromium_timestamp(row[3], True)])
                tmp_urls.flush()
                urls_object_id = self.storage.upload_file(tmp_urls.name)

                transforms.append(
                    Transform(
                        type="chromium_urls",
                        object_id=f"{urls_object_id}",
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
                    writer.writerow([row[0], row[1], convert_chromium_timestamp(row[2], True), row[3], row[4]])
                tmp_downloads.flush()
                downloads_object_id = self.storage.upload_file(tmp_downloads.name)

                transforms.append(
                    Transform(
                        type="chromium_downloads",
                        object_id=f"{downloads_object_id}",
                        metadata={
                            "file_name": f"{file_enriched.file_name}_chromium_downloads.csv",
                            "offer_as_download": True,
                        },
                    )
                )

            conn.close()
            enrichment_result.transforms = transforms
            return enrichment_result

        except Exception:
            logger.exception(message="Error processing Chrome History database")


def create_enrichment_module() -> EnrichmentModule:
    return ChromeHistoryParser()

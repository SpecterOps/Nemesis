# enrichment_modules/chromium_history/analyzer.py
import csv
import sqlite3
import tempfile
from uuid import UUID

import yara_x
from chromium import convert_chromium_timestamp, process_chromium_history
from common.logger import get_logger
from common.models import EnrichmentResult, Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from common.untrusted_sqlite import read_untrusted_sqlite_async, require_tables
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)


def _read_report_data(conn: sqlite3.Connection) -> dict:
    conn.text_factory = lambda x: x.decode("utf-8", errors="replace")
    require_tables(conn, "urls", "downloads")
    return {
        "url_count": conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0],
        "top_urls": conn.execute("""
            SELECT url, visit_count
            FROM urls
            ORDER BY visit_count DESC
            LIMIT 10
        """).fetchall(),
        "download_count": conn.execute("SELECT COUNT(*) FROM downloads").fetchone()[0],
        "recent_downloads": conn.execute("""
            SELECT target_path, tab_url, end_time
            FROM downloads
            ORDER BY end_time DESC
            LIMIT 10
        """).fetchall(),
        "urls": conn.execute("SELECT url, title, visit_count, last_visit_time FROM urls").fetchall(),
        "downloads": conn.execute(
            "SELECT target_path, total_bytes, end_time, tab_url, mime_type FROM downloads"
        ).fetchall(),
    }


class ChromeHistoryParser(EnrichmentModule):
    name: str = "chrome_history_parser"
    dependencies: list[str] = []

    def __init__(self):
        self.storage = StorageMinio()
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

    async def should_process(self, object_id: UUID, file_path: str | None = None) -> bool:
        """Determine if this module should run.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file
        """

        file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

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

    async def process(self, object_id: UUID, file_path: str | None = None) -> EnrichmentResult | None:
        """Process Chrome History database.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file
        """
        try:
            file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)
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

            # The collected database is untrusted: read it read-only, time-limited and off the event loop
            if file_path:
                data = await read_untrusted_sqlite_async(
                    file_path, _read_report_data, detect_types=sqlite3.PARSE_DECLTYPES
                )
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    data = await read_untrusted_sqlite_async(
                        temp_file.name, _read_report_data, detect_types=sqlite3.PARSE_DECLTYPES
                    )

            # Generate summary report
            report_lines = []

            # URLs summary
            report_lines.append("# Chrome History Summary")
            report_lines.append(f"\nTotal URLs visited: {data['url_count']}")

            # Top 10 visited URLs
            report_lines.append("\n## Top 10 Most Visited URLs")
            report_lines.append("\n| URL | Visit Count |")
            report_lines.append("| --- | ----------- |")
            for url, count in data["top_urls"]:
                report_lines.append(f"| {url} | {count} |")

            # Downloads summary
            report_lines.append(f"\nTotal Downloads: {data['download_count']}")

            # Recent downloads
            report_lines.append("\n## Most Recent Downloads")
            report_lines.append("\n| Time | Path | Source URL |")
            report_lines.append("| ---- | ---- | ---------- |")
            for path, url, end_time in data["recent_downloads"]:
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
                        object_id=report_object_id,
                        metadata={
                            "file_name": f"{file_enriched.file_name}.md",
                            "display_type_in_dashboard": "markdown",
                            "default_display": True,
                        },
                    )
                )

            # Export URLs table
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="") as tmp_urls:
                writer = csv.writer(tmp_urls)
                writer.writerow(["url", "title", "visit_count", "last_visit_time"])
                for row in data["urls"]:
                    writer.writerow([row[0], row[1], row[2], convert_chromium_timestamp(row[3], True)])
                tmp_urls.flush()
                urls_object_id = self.storage.upload_file(tmp_urls.name)

                transforms.append(
                    Transform(
                        type="chromium_urls",
                        object_id=urls_object_id,
                        metadata={
                            "file_name": f"{file_enriched.file_name}_chromium_urls.csv",
                            "offer_as_download": True,
                        },
                    )
                )

            # Export downloads table
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="") as tmp_downloads:
                writer = csv.writer(tmp_downloads)
                writer.writerow(["target_path", "total_bytes", "end_time", "tab_url", "mime_type"])
                for row in data["downloads"]:
                    writer.writerow([row[0], row[1], convert_chromium_timestamp(row[2], True), row[3], row[4]])
                tmp_downloads.flush()
                downloads_object_id = self.storage.upload_file(tmp_downloads.name)

                transforms.append(
                    Transform(
                        type="chromium_downloads",
                        object_id=downloads_object_id,
                        metadata={
                            "file_name": f"{file_enriched.file_name}_chromium_downloads.csv",
                            "offer_as_download": True,
                        },
                    )
                )

            enrichment_result.transforms = transforms
            return enrichment_result

        except Exception:
            logger.exception(message="Error processing Chrome History database")


def create_enrichment_module() -> EnrichmentModule:
    return ChromeHistoryParser()

# enrichment_modules/chromium_cookies/analyzer.py
import csv
import sqlite3
import tempfile
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import yara_x
from chromium import convert_chromium_timestamp, process_chromium_cookies
from common.logger import get_logger
from common.models import EnrichmentResult, Transform
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule

if TYPE_CHECKING:
    from nemesis_dpapi import DpapiManager

logger = get_logger(__name__)


class ChromeCookiesParser(EnrichmentModule):
    def __init__(self):
        super().__init__("chrome_cookies_parser")
        self.storage = StorageMinio()

        # the workflows this module should automatically run in
        self.workflows = ["default"]

        self.dpapi_manager: DpapiManager

        # Yara rule to check for Chrome Cookies tables
        self.yara_rule = yara_x.compile("""
rule Chrome_Cookies_Tables
{
    meta:
        description = "Detects Chrome/Chromium cookies database tables"

    strings:
        $cookies_table = "CREATE TABLE cookies"
        $cookies_index = "CREATE UNIQUE INDEX cookies_unique_index"

    condition:
        all of them
}
        """)

    def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file
        """

        file_enriched = get_file_enriched(object_id)

        # Check if filename is exactly "Cookies" and SQLite magic type
        if not (file_enriched.file_name == "Cookies" and "sqlite 3.x database" in file_enriched.magic_type.lower()):
            return False

        if file_path:
            # Use provided file path
            with open(file_path, "rb") as f:
                file_bytes = f.read()
        else:
            # Fallback to downloading the file itself
            file_bytes = self.storage.download_bytes(file_enriched.object_id)

        # Verify Chrome cookies tables using Yara
        should_run = len(self.yara_rule.scan(file_bytes).matching_rules) > 0

        return should_run

    def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process Chrome Cookies database.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file
        """
        try:
            file_enriched = get_file_enriched(object_id)
            enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)
            transforms = []

            # Use the chromium library to process and insert into database
            process_chromium_cookies(object_id, file_path)

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

            # Cookies summary
            cursor.execute("SELECT COUNT(*) FROM cookies")
            cookie_count = cursor.fetchone()[0]
            report_lines.append("# Chrome Cookies Summary")
            report_lines.append(f"\nTotal cookies: {cookie_count}")

            # Count of non-expired cookies at time of processing
            cursor.execute(
                """
                SELECT COUNT(*) FROM cookies
                WHERE expires_utc IS NULL OR expires_utc > ?
            """,
                (int((datetime.now(UTC).timestamp() - 11644473600) * 1000000),),
            )
            non_expired_count = cursor.fetchone()[0]
            report_lines.append(f"Non-expired cookies (at time of processing): {non_expired_count}")

            # Most recently accessed cookies
            cursor.execute("""
                SELECT host_key, name, last_access_utc
                FROM cookies
                ORDER BY last_access_utc DESC
                LIMIT 10
            """)
            report_lines.append("\n## Most Recently Accessed Cookies")
            report_lines.append("\n| Last Access Time | Host | Cookie Name |")
            report_lines.append("| ---------------- | ---- | ----------- |")
            for host_key, name, last_access_utc in cursor.fetchall():
                last_access_iso = convert_chromium_timestamp(last_access_utc, True)
                # Escape pipe characters to prevent table formatting issues
                safe_host = host_key.replace("|", "\\|") if host_key else ""
                safe_name = name.replace("|", "\\|") if name else ""
                report_lines.append(f"| {last_access_iso} | {safe_host} | {safe_name} |")

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

            # Export cookies table
            cursor.execute("""
                SELECT creation_utc, host_key, source_port, path, name, expires_utc,
                       last_access_utc, last_update_utc, is_secure, is_httponly,
                       is_persistent, samesite
                FROM cookies
            """)
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="") as tmp_cookies:
                writer = csv.writer(tmp_cookies)
                writer.writerow(
                    [
                        "creation_utc",
                        "host_key",
                        "source_port",
                        "path",
                        "name",
                        "expires_utc",
                        "last_access_utc",
                        "last_update_utc",
                        "is_secure",
                        "is_httponly",
                        "is_persistent",
                        "samesite",
                    ]
                )
                for row in cursor:
                    # Convert Chromium timestamps to ISO format
                    creation_utc = convert_chromium_timestamp(row[0], True) if row[0] else None
                    expires_utc = convert_chromium_timestamp(row[5], True) if row[5] else None
                    last_access_utc = convert_chromium_timestamp(row[6], True) if row[6] else None
                    last_update_utc = convert_chromium_timestamp(row[7], True) if row[7] else None

                    writer.writerow(
                        [
                            creation_utc,
                            row[1],
                            row[2],
                            row[3],
                            row[4],
                            expires_utc,
                            last_access_utc,
                            last_update_utc,
                            row[8],
                            row[9],
                            row[10],
                            row[11],
                        ]
                    )
                tmp_cookies.flush()
                cookies_object_id = self.storage.upload_file(tmp_cookies.name)

                transforms.append(
                    Transform(
                        type="chromium_cookies",
                        object_id=f"{cookies_object_id}",
                        metadata={
                            "file_name": f"{file_enriched.file_name}_chromium_cookies.csv",
                            "offer_as_download": True,
                        },
                    )
                )

            conn.close()
            enrichment_result.transforms = transforms
            return enrichment_result

        except Exception as e:
            logger.exception(e, message="Error processing Chrome Cookies database")


def create_enrichment_module() -> EnrichmentModule:
    return ChromeCookiesParser()

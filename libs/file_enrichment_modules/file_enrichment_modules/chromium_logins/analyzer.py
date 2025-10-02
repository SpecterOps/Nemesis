# enrichment_modules/chromium_logins/analyzer.py
import csv
import sqlite3
import tempfile
from typing import TYPE_CHECKING

import yara_x
from chromium import convert_chromium_timestamp, process_chromium_logins
from common.logger import get_logger
from common.models import EnrichmentResult, Transform
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule

if TYPE_CHECKING:
    from nemesis_dpapi import DpapiManager

logger = get_logger(__name__)


class ChromeLoginsParser(EnrichmentModule):
    def __init__(self):
        super().__init__("chrome_logins_parser")
        self.storage = StorageMinio()

        # the workflows this module should automatically run in
        self.workflows = ["default"]

        self.dpapi_manager: DpapiManager

        # Yara rule to check for Chrome Login Data tables
        self.yara_rule = yara_x.compile("""
rule Chrome_Logins_Tables
{
    meta:
        description = "Detects Chrome/Chromium logins database tables"

    strings:
        $logins_table = "CREATE TABLE logins "
        $logins_table2 = "CREATE TABLE insecure_credentials"

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

        if not "sqlite 3.x database" in file_enriched.magic_type.lower():
            return False

        if file_path:
            # Use provided file path
            with open(file_path, "rb") as f:
                file_bytes = f.read()
        else:
            # Fallback to downloading the file itself
            file_bytes = self.storage.download_bytes(file_enriched.object_id)

        # Verify Chrome Login Data tables using Yara
        should_run = len(self.yara_rule.scan(file_bytes).matching_rules) > 0

        return should_run

    def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process Chrome Login Data database.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file
        """
        try:
            file_enriched = get_file_enriched(object_id)
            enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)
            transforms = []

            # Use the chromium library to process and insert into database
            process_chromium_logins(object_id, file_path)

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

            # Logins summary
            cursor.execute("SELECT COUNT(*) FROM logins")
            login_count = cursor.fetchone()[0]
            report_lines.append("# Chrome Logins Summary")
            report_lines.append(f"\nTotal logins: {login_count}")

            # Count of logins with non-empty password_value
            cursor.execute("SELECT COUNT(*) FROM logins WHERE password_value IS NOT NULL")
            password_count = cursor.fetchone()[0]
            report_lines.append(f"\nLogins with saved passwords: {password_count}")

            # Most recently used logins
            cursor.execute("""
                SELECT origin_url, username_value, date_last_used
                FROM logins
                ORDER BY date_last_used DESC
                LIMIT 10
            """)
            report_lines.append("\n## Most Recently Used Logins")
            report_lines.append("\n| Last Used Time | Origin URL | Username |")
            report_lines.append("| -------------- | ---------- | -------- |")
            for origin_url, username_value, date_last_used in cursor.fetchall():
                last_used_iso = convert_chromium_timestamp(date_last_used, True)
                # Escape pipe characters to prevent table formatting issues
                safe_origin = origin_url.replace("|", "\\|") if origin_url else ""
                safe_username = username_value.replace("|", "\\|") if username_value else ""
                report_lines.append(f"| {last_used_iso} | {safe_origin} | {safe_username} |")

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

            # Export logins table
            cursor.execute("""
                SELECT origin_url, username_value, signon_realm, date_created,
                       date_last_used, date_password_modified, times_used
                FROM logins
            """)
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="") as tmp_logins:
                writer = csv.writer(tmp_logins)
                writer.writerow(
                    [
                        "origin_url",
                        "username_value",
                        "signon_realm",
                        "date_created",
                        "date_last_used",
                        "date_password_modified",
                        "times_used",
                    ]
                )
                for row in cursor:
                    # Convert Chromium timestamps to ISO format
                    date_created = convert_chromium_timestamp(row[3], True) if row[3] else None
                    date_last_used = convert_chromium_timestamp(row[4], True) if row[4] else None
                    date_password_modified = convert_chromium_timestamp(row[5], True) if row[5] else None

                    writer.writerow(
                        [row[0], row[1], row[2], date_created, date_last_used, date_password_modified, row[6]]
                    )
                tmp_logins.flush()
                logins_object_id = self.storage.upload_file(tmp_logins.name)

                transforms.append(
                    Transform(
                        type="chromium_logins",
                        object_id=f"{logins_object_id}",
                        metadata={
                            "file_name": f"{file_enriched.file_name}_chromium_logins.csv",
                            "offer_as_download": True,
                        },
                    )
                )

            conn.close()
            enrichment_result.transforms = transforms
            return enrichment_result

        except Exception as e:
            logger.exception(e, message="Error processing Chrome Login Data database")


def create_enrichment_module() -> EnrichmentModule:
    return ChromeLoginsParser()

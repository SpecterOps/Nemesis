# enrichment_modules/shadow/analyzer.py
import tempfile
import textwrap
from pathlib import Path

import yara_x
from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)


class ShadowParser(EnrichmentModule):
    name: str = "shadow_parser"
    dependencies: list[str] = []

    def __init__(self):
        self.storage = StorageMinio()

        self.asyncpg_pool = None  # type: ignore
        # the workflows this module should automatically run in
        self.workflows = ["default"]

        # Yara rule to detect shadow files
        self.yara_rule = yara_x.compile("""
rule shadow_file
{
    meta:
        description = "Detects Linux/Unix shadow password files"
        author = "SpecterOps"
        severity = "Medium"

    strings:
        // Always look for root user entry (required)
        $root = /root:[^:]*:[0-9]+:[0-9]+:[0-9]+:[0-9]+:::/

        // Common system users that appear in shadow files
        $daemon = "daemon:*:"
        $bin = "bin:*:"
        $sys = "sys:*:"

        // Shadow file field separators (colon-delimited format)
        // Looking for lines with the shadow file structure
        $shadow_format = /[a-zA-Z0-9_-]+:[^:]*:[0-9]+:[0-9]+:[0-9]+:[0-9]+:::/

    condition:
        $root and 2 of ($daemon, $bin, $sys) and #shadow_format >= 5
}
        """)

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run based on file type."""

        file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

        if not file_enriched.is_plaintext:
            return False

        if file_path:
            # Use provided file path
            with open(file_path, "rb") as f:
                file_bytes = f.read()
        else:
            # Fallback to downloading the file itself
            file_bytes = self.storage.download_bytes(file_enriched.object_id)

        # Verify shadow file format using YARA
        should_run = len(self.yara_rule.scan(file_bytes).matching_rules) > 0

        return should_run

    def _parse_shadow_file(self, content: str) -> list[dict]:
        """Parse shadow file and extract entries with non-null password hashes.

        Shadow file format: username:password:lastchanged:min:max:warn:inactive:expire:reserved
        Password field values:
        - * or ! = locked/disabled account
        - empty = no password required
        - hash string = actual password hash
        """
        credentials = []

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            fields = line.split(":")
            if len(fields) < 2:
                continue

            username = fields[0]
            password_hash = fields[1]

            # Skip entries with null/disabled passwords (*, !, !*, or empty)
            if not password_hash or password_hash in ["*", "!", "!*"]:
                continue

            # Extract additional fields if available
            credential = {
                "username": username,
                "password_hash": password_hash,
                "last_changed": fields[2] if len(fields) > 2 else "",
                "min_days": fields[3] if len(fields) > 3 else "",
                "max_days": fields[4] if len(fields) > 4 else "",
                "warn_days": fields[5] if len(fields) > 5 else "",
                "inactive_days": fields[6] if len(fields) > 6 else "",
                "expire_date": fields[7] if len(fields) > 7 else "",
            }
            credentials.append(credential)

        return credentials

    def _create_finding_summary(self, credentials: list[dict]) -> str:
        """Creates a markdown summary for the shadow file finding."""
        summary = "# Shadow File Credentials Detected\n\n"
        summary += f"Found {len(credentials)} user(s) with password hashes\n\n"

        for i, cred in enumerate(credentials, 1):
            summary += f"## User {i}\n"
            summary += f"* **Username**: `{cred['username']}`\n"
            summary += f"* **Password Hash**: `{cred['password_hash']}`\n"

            if cred.get("last_changed"):
                summary += f"* **Last Changed**: {cred['last_changed']} days since epoch\n"
            if cred.get("max_days"):
                summary += f"* **Max Password Age**: {cred['max_days']} days\n"

            summary += "\n"

        return summary

    def _analyze_shadow(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze shadow file and generate enrichment result.

        Args:
            file_path: Path to the shadow file to analyze
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

        try:
            content = Path(file_path).read_text(encoding="utf-8")

            # Parse the shadow file
            credentials = self._parse_shadow_file(content)

            if credentials:
                # Create finding summary
                summary_markdown = self._create_finding_summary(credentials)

                # Create display data
                display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

                # Create finding
                finding = Finding(
                    category=FindingCategory.CREDENTIAL,
                    finding_name="shadow_file_credentials_detected",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=file_enriched.object_id,
                    severity=5,
                    raw_data={"credentials": credentials},
                    data=[display_data],
                )

                # Add finding to enrichment result
                enrichment_result.findings = [finding]
                enrichment_result.results = {"credentials": credentials}

                # Create a displayable version of the results
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_display_file:
                    yaml_output = []
                    yaml_output.append("Shadow File Analysis")
                    yaml_output.append("====================\n")

                    for i, cred in enumerate(credentials, 1):
                        yaml_output.append(f"User {i}:")
                        yaml_output.append(f"   username: {cred['username']}")
                        yaml_output.append(f"   password_hash: {cred['password_hash']}")

                        if cred.get("last_changed"):
                            yaml_output.append(f"   last_changed: {cred['last_changed']} days since epoch")
                        if cred.get("min_days"):
                            yaml_output.append(f"   min_days: {cred['min_days']}")
                        if cred.get("max_days"):
                            yaml_output.append(f"   max_days: {cred['max_days']}")
                        if cred.get("warn_days"):
                            yaml_output.append(f"   warn_days: {cred['warn_days']}")

                        yaml_output.append("")  # Add empty line between users

                    display = textwrap.indent("\n".join(yaml_output), "   ")
                    tmp_display_file.write(display)
                    tmp_display_file.flush()

                    object_id = self.storage.upload_file(tmp_display_file.name)

                    displayable_parsed = Transform(
                        type="displayable_parsed",
                        object_id=f"{object_id}",
                        metadata={
                            "file_name": f"{file_enriched.file_name}_analysis.txt",
                            "display_type_in_dashboard": "monaco",
                            "default_display": True,
                        },
                    )
                    enrichment_result.transforms = [displayable_parsed]

            return enrichment_result

        except Exception:
            logger.exception(message=f"Error analyzing shadow file for {file_enriched.file_name}")
            return None

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process shadow file and extract credentials.

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
                return self._analyze_shadow(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_shadow(temp_file.name, file_enriched)

        except Exception:
            logger.exception(message="Error processing shadow file")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return ShadowParser()

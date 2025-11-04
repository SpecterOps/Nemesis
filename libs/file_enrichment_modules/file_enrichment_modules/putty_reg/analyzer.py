# enrichment_modules/putty_reg/analyzer.py
import re
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

# Port of https://github.com/NetSPI/PowerHuntShares/blob/46238ba37dc85f65f2c1d7960f551ea3d80c236a/Scripts/ConfigParsers/parser-putty.reg.ps1
#   Original Author: Scott Sutherland, NetSPI (@_nullbind / nullbind)
#   License: BSD 3-clause


class PuttyParser(EnrichmentModule):
    name: str = "putty_parser"
    dependencies: list[str] = []

    def __init__(self):
        self.storage = StorageMinio()

        self.asyncpg_pool = None  # type: ignore
        # the workflows this module should automatically run in
        self.workflows = ["default"]

        self.size_limit = 50_000_000  # 50MB size limit

        # Yara rule to check for Putty registry content
        self.yara_rule = yara_x.compile("""
rule has_putty_reg
{
    strings:
        $putty_header = "HKEY_CURRENT_USER\\\\Software\\\\SimonTatham\\\\PuTTY" nocase
    condition:
        $putty_header
}
        """)

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run based on file type."""
        file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

        # First check if it's a plaintext .reg file
        if not (file_enriched.is_plaintext and file_enriched.file_name.lower().endswith(".reg")):
            return False

        if file_path:
            # Use provided file path - read only the needed bytes
            with open(file_path, "rb") as f:
                num_bytes = min(file_enriched.size, self.size_limit)
                file_bytes = f.read(num_bytes)
        else:
            # Fallback to downloading the file itself
            num_bytes = file_enriched.size if file_enriched.size < self.size_limit else self.size_limit
            file_bytes = self.storage.download_bytes(file_enriched.object_id, length=num_bytes)

        should_run = len(self.yara_rule.scan(file_bytes).matching_rules) > 0
        return should_run

    def _parse_putty_reg(self, content: str) -> list[dict]:
        """Parse the Putty registry file content."""
        sessions = []
        current_session = None
        current_data = {}

        for line in content.splitlines():
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith(";"):
                continue

            # Check for session headers
            if line.startswith("["):
                # Save previous session if exists
                if current_session and current_data:
                    sessions.append({"session_name": current_session, **current_data})

                # Start new session
                match = re.search(r"Sessions\\(.+?)\]", line)
                if match:
                    current_session = match.group(1)
                    current_data = {}
                continue

            # Parse key-value pairs
            if "=" in line:
                key, value = line.split("=", 1)
                key = key.strip('"')

                # Handle different value types
                if value.startswith("dword:"):
                    value = int(value[7:], 16)
                else:
                    value = value.strip('"')

                current_data[key] = value

        # Add final session
        if current_session and current_data:
            sessions.append({"session_name": current_session, **current_data})

        return sessions

    def _create_finding_summary(self, sessions: list[dict]) -> str:
        """Creates a markdown summary for the Putty sessions."""
        summary = "# Putty Sessions Found\n\n"

        for session in sessions:
            if "HostName" not in session:
                continue

            summary += f"## Session: {session['session_name']}\n"
            summary += f"* **Hostname**: {session.get('HostName', 'N/A')}\n"
            summary += f"* **Port**: {session.get('PortNumber', 22)}\n"
            summary += f"* **Username**: {session.get('UserName', 'N/A')}\n"
            if "PublicKeyFile" in session:
                summary += f"* **Key File**: {session['PublicKeyFile']}\n"
            summary += "\n"

        return summary

    def _analyze_putty_registry(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze Putty registry file and generate enrichment result.

        Args:
            file_path: Path to the Putty registry file to analyze
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

        try:
            content = Path(file_path).read_text(encoding="utf-8")

            # Parse the registry content
            sessions = self._parse_putty_reg(content)

            if sessions:
                # Create finding summary
                summary_markdown = self._create_finding_summary(sessions)

                # Create display data
                display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

                # Create finding
                finding = Finding(
                    category=FindingCategory.CREDENTIAL,
                    finding_name="putty_sessions_detected",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=file_enriched.object_id,
                    severity=3,
                    raw_data={"sessions": sessions},
                    data=[display_data],
                )

                # Add finding to enrichment result
                enrichment_result.findings = [finding]
                enrichment_result.results = {"sessions": sessions}

                # Create a displayable version of the results
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_display_file:
                    yaml_output = []
                    yaml_output.append("Putty Registry Analysis")
                    yaml_output.append("=====================\n")

                    for session in sessions:
                        yaml_output.append(f"Session: {session['session_name']}")
                        for key, value in session.items():
                            if key != "session_name":
                                yaml_output.append(f"   {key}: {value}")
                        yaml_output.append("")

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
            logger.exception(message=f"Error analyzing Putty registry for {file_enriched.file_name}")
            return None

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process Putty registry file.

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
                return self._analyze_putty_registry(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_putty_registry(temp_file.name, file_enriched)

        except Exception:
            logger.exception(message="Error processing Putty registry file")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return PuttyParser()

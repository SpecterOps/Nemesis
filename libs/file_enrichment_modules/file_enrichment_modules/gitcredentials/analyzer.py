# enrichment_modules/gitcredentials/analyzer.py
import re
import tempfile
import textwrap
from pathlib import Path

from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)

# Port of https://github.com/NetSPI/PowerHuntShares/blob/46238ba37dc85f65f2c1d7960f551ea3d80c236a/Scripts/ConfigParsers/parser-gitcredentials.ps1
#   Original Author: Scott Sutherland, NetSPI (@_nullbind / nullbind)
#   License: BSD 3-clause


class GitCredentialsParser(EnrichmentModule):
    name: str = "git_credentials_parser"
    dependencies: list[str] = []

    def __init__(self):
        self.storage = StorageMinio()

        self.asyncpg_pool = None  # type: ignore
        # the workflows this module should automatically run in
        self.workflows = ["default"]

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run based on file type."""

        file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

        # Check if file is a Git credentials file
        should_run = file_enriched.is_plaintext and (
            file_enriched.file_name.lower() in [".git-credentials", ".gitcredentials"]
        )

        return should_run

    def _parse_credentials(self, content: str) -> list[dict]:
        """Parse Git credentials from file content."""
        credentials = []
        pattern = re.compile(r"https://([^:]+):([^@]+)@(.*)")

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            match = pattern.match(line)
            if match:
                username, token, target_url = match.groups()
                target_server = target_url.split("/")[0]

                credential = {
                    "username": username,
                    "token": token,
                    "target_url": target_url,
                    "target_server": target_server,
                }
                credentials.append(credential)

        return credentials

    def _create_finding_summary(self, credentials: list[dict]) -> str:
        """Creates a markdown summary for the Git credentials finding."""
        summary = "# Git Credentials Detected\n\n"

        for i, cred in enumerate(credentials, 1):
            summary += f"## Credential Set {i}\n"
            summary += f"* **Username**: `{cred['username']}`\n"
            summary += f"* **Token**: `{cred['token']}`\n"
            summary += f"* **Target URL**: {cred['target_url']}\n"
            summary += f"* **Target Server**: {cred['target_server']}\n\n"

        return summary

    def _analyze_gitcredentials(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze Git credentials file and generate enrichment result.

        Args:
            file_path: Path to the Git credentials file to analyze
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

        try:
            content = Path(file_path).read_text(encoding="utf-8")

            # Parse the credentials
            credentials = self._parse_credentials(content)

            if credentials:
                # Create finding summary
                summary_markdown = self._create_finding_summary(credentials)

                # Create display data
                display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

                # Create finding
                finding = Finding(
                    category=FindingCategory.CREDENTIAL,
                    finding_name="git_credentials_detected",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=file_enriched.object_id,
                    severity=7,
                    raw_data={"credentials": credentials},
                    data=[display_data],
                )

                # Add finding to enrichment result
                enrichment_result.findings = [finding]
                enrichment_result.results = {"credentials": credentials}

                # Create a displayable version of the results
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_display_file:
                    yaml_output = []
                    yaml_output.append("Git Credentials Analysis")
                    yaml_output.append("========================\n")

                    for i, cred in enumerate(credentials, 1):
                        yaml_output.append(f"Credential Set {i}:")
                        for key, value in cred.items():
                            yaml_output.append(f"   {key}: {value}")
                        yaml_output.append("")  # Add empty line between sets

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
            logger.exception(message=f"Error analyzing Git credentials for {file_enriched.file_name}")
            return None

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process Git credentials file and extract credentials.

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
                return self._analyze_gitcredentials(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_gitcredentials(temp_file.name, file_enriched)

        except Exception:
            logger.exception(message="Error processing Git credentials file")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return GitCredentialsParser()

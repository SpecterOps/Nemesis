from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin
from common.state_helpers import get_file_enriched_async
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)


class FilenameScanner(EnrichmentModule):
    name: str = "filename_scanner"
    dependencies: list[str] = []

    def __init__(self):
        self.workflows = ["default"]

        # List of sensitive terms to check for in filenames
        self.sensitive_terms = [
            # Credentials & Authentication
            "password",
            "passwd",
            "secret",
            "credentials",
            "apikey",
            "api_key",
            "token",
            "oauth",
            "bearer",
            # Authentication info
            "login",
            "logon",
            "signin",
            "signon",
            "credential",
            "keytab",
            # Personal or confidential
            "confidential",
            "proprietary",
            "classified",
            "restricted",
            "sensitive",
            "internal",
            "private",
            # Web related
            "htaccess",
            "htpasswd",
            "wp-config",
            "phpinfo",
        ]

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Always returns True as filename scanning should run on all files.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file (not used by filename scanner)
        """
        return True

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process file by checking its filename for sensitive terms.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file (not used by filename scanner)
        """
        try:
            # Get the current file_enriched from the database backend
            file_enriched = await get_file_enriched_async(object_id)

            matches = []
            filename_lower = file_enriched.file_name.lower()

            # Check each sensitive term against the filename
            for term in self.sensitive_terms:
                if term in filename_lower:
                    matches.append(term)

            # If we found sensitive terms in the filename
            if matches:
                enrichment_result = EnrichmentResult(module_name=self.name)

                # Create a display summary for the finding
                summary_markdown = self._create_summary_markdown(file_enriched.file_name, matches)
                display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

                # Create the finding
                finding = Finding(
                    category=FindingCategory.MISC,
                    finding_name="sensitive_filename",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=file_enriched.object_id,
                    severity=4,
                    raw_data={"filename": file_enriched.file_name, "matches": matches},
                    data=[display_data],
                )

                enrichment_result.findings = [finding]
                enrichment_result.results = {"sensitive_terms": matches}

                return enrichment_result

            return None

        except Exception:
            logger.exception(message="Error in process()")
            return None

    def _create_summary_markdown(self, filename, matches):
        """Create a markdown summary of the finding."""
        markdown = [
            "# Sensitive Filename Detection",
            f"\nThe filename **{filename}** contains potentially sensitive terms:\n",
            "### Matches",
        ]

        for match in matches:
            markdown.append(f"- `{match}`")

        return "\n".join(markdown)


def create_enrichment_module() -> EnrichmentModule:
    return FilenameScanner()

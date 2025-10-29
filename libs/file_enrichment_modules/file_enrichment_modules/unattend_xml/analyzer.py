# enrichment_modules/unattend_xml/analyzer.py
import base64
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

import yara_x
from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)

# Port of https://github.com/NetSPI/PowerHuntShares/blob/46238ba37dc85f65f2c1d7960f551ea3d80c236a/Scripts/ConfigParsers/parser-unattend.xml.ps1
#   Original Author: Scott Sutherland, NetSPI (@_nullbind / nullbind)
#   License: BSD 3-clause


class UnattendParser(EnrichmentModule):
    name: str = "unattend_parser"
    dependencies: list[str] = []

    def __init__(self):
        self.storage = StorageMinio()

        # the workflows this module should automatically run in
        self.workflows = ["default"]

        self.size_limit = 5_000_000  # 5MB size limit

        # Yara rule to detect unattend.xml files
        self.yara_rule = yara_x.compile("""
rule Detect_Windows_Unattend_XML {
    meta:
        description = "Detects Windows unattend.xml files that may contain sensitive data"
        author = "Claude"
        severity = "High"

    strings:
        // Basic structure identifiers
        $xml_header = "<?xml" nocase
        $unattend_ns = "schemas-microsoft-com:unattend" nocase

        // Common sections
        $settings = "<settings" nocase
        $component = "<component" nocase
        $shell_setup = "Windows-Shell-Setup" nocase

        // Sensitive content indicators
        $autologon = "AutoLogon" nocase
        $password = "<Password>" nocase
        $value_tag = "<Value>" nocase
        $user_accounts = "UserAccounts" nocase

        // OOBE indicators
        $oobe = "OOBE" nocase
        $hide = "Hide" nocase

    condition:
        $xml_header and $unattend_ns and
        all of ($settings, $component, $shell_setup) and
        2 of ($autologon, $password, $value_tag, $user_accounts) and
        1 of ($oobe, $hide)
}
        """)

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run based on file type."""
        file_enriched = await get_file_enriched_async(object_id)

        # Initial checks for file type and name
        if not (file_enriched.is_plaintext and file_enriched.file_name.lower() == "unattend.xml"):
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

    def _decode_password(self, password_value: str, is_plaintext: bool) -> str | None:
        """Decode base64 password if needed."""
        if not is_plaintext:
            try:
                return base64.b64decode(password_value).decode("utf-8")
            except Exception as e:
                logger.error(f"Error decoding password: {str(e)}")
                return None
        return password_value

    def _parse_unattend_xml(self, xml_content: str) -> list[dict]:
        """Parse the unattend.xml content and extract credentials."""
        credentials = []
        try:
            root = ET.fromstring(xml_content)
            ns = {
                "unattend": "urn:schemas-microsoft-com:unattend",
                "wcm": "http://schemas.microsoft.com/WMIConfig/2002/State",
            }

            # Parse AutoLogon credentials
            for autologon in root.findall(".//unattend:AutoLogon", ns):
                username = autologon.findtext("unattend:Username", "", ns)
                password_elem = autologon.find(".//unattend:Password", ns)
                if password_elem is not None:
                    password_value = password_elem.findtext("unattend:Value", "", ns)
                    is_plaintext = password_elem.findtext("unattend:PlainText", "true", ns).lower() == "true"
                    password = self._decode_password(password_value, is_plaintext)

                    if password and username and password != "***":
                        credentials.append({"username": username, "password": password, "source": "AutoLogon"})

            # Parse LocalAccounts credentials
            for account in root.findall(".//unattend:LocalAccounts/unattend:LocalAccount", ns):
                username = account.findtext("unattend:Name", "", ns)
                password_elem = account.find(".//unattend:Password", ns)
                if password_elem is not None:
                    password_value = password_elem.findtext("unattend:Value", "", ns)
                    is_plaintext = password_elem.findtext("unattend:PlainText", "true", ns).lower() == "true"
                    password = self._decode_password(password_value, is_plaintext)

                    if password and username and password != "***":
                        credentials.append({"username": username, "password": password, "source": "LocalAccount"})

            return credentials

        except Exception as e:
            logger.error(f"Error parsing unattend.xml: {str(e)}")
            return []

    def _create_finding_summary(self, credentials: list[dict]) -> str:
        """Creates a markdown summary for the credentials finding."""
        summary = "# Windows Unattend.xml Credentials Detected\n\n"

        for cred in credentials:
            summary += f"## {cred['source']}\n"
            summary += f"* **Username**: `{cred['username']}`\n"
            summary += f"* **Password**: `{cred['password']}`\n\n"

        return summary

    def _analyze_unattend_xml(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze unattend.xml file and generate enrichment result.

        Args:
            file_path: Path to the unattend.xml file to analyze
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

        try:
            content = Path(file_path).read_text(encoding="utf-8")

            # Parse the XML and extract credentials
            credentials = self._parse_unattend_xml(content)

            if credentials:
                # Create finding summary
                summary_markdown = self._create_finding_summary(credentials)

                # Create display data
                display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

                # Create finding
                finding = Finding(
                    category=FindingCategory.CREDENTIAL,
                    finding_name="unattend_credentials_detected",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=file_enriched.object_id,
                    severity=8,
                    raw_data={"credentials": credentials},
                    data=[display_data],
                )

                enrichment_result.findings = [finding]
                enrichment_result.results = {"credentials": credentials}

                # Create a displayable version of the results
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_display_file:
                    display = "Windows Unattend.xml Analysis\n"
                    display += "==========================\n\n"

                    for cred in credentials:
                        display += f"Source: {cred['source']}\n"
                        display += f"Username: {cred['username']}\n"
                        display += f"Password: {cred['password']}\n"
                        display += "-" * 40 + "\n"

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

                # Create finding summary
                summary_markdown = self._create_finding_summary(credentials)

                # Create display data
                display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

                # Create finding
                finding = Finding(
                    category=FindingCategory.CREDENTIAL,
                    finding_name="unattend_credentials_detected",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=file_enriched.object_id,
                    severity=8,
                    raw_data={"credentials": credentials},
                    data=[display_data],
                )

                enrichment_result.findings = [finding]
                enrichment_result.results = {"credentials": credentials}

                # Create a displayable version of the results
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_display_file:
                    display = "Windows Unattend.xml Analysis\n"
                    display += "==========================\n\n"

                    for cred in credentials:
                        display += f"Source: {cred['source']}\n"
                        display += f"Username: {cred['username']}\n"
                        display += f"Password: {cred['password']}\n"
                        display += "-" * 40 + "\n"

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
            logger.exception(message=f"Error analyzing unattend.xml for {file_enriched.file_name}")
            return None

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process unattend.xml file and extract credentials.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file

        Returns:
            EnrichmentResult or None if processing fails
        """
        try:
            file_enriched = await get_file_enriched_async(object_id)

            # Use provided file_path if available, otherwise download
            if file_path:
                return self._analyze_unattend_xml(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_unattend_xml(temp_file.name, file_enriched)

        except Exception:
            logger.exception(message="Error processing unattend.xml file")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return UnattendParser()

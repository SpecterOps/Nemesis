# enrichment_modules/group_policy_preferences/analyzer.py
import base64
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable, Tuple

import yara_x
from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)


class GroupPolicyPreferencesParser(EnrichmentModule):
    name: str = "group_policy_preferences_parser"
    dependencies: list[str] = []

    def __init__(self):
        self.storage = StorageMinio()

        self.asyncpg_pool = None  # type: ignore

        # the workflows this module should automatically run in
        self.workflows = ["default"]

        self.size_limit = 1_000_000  # 1MB size limit

        # Yara rule to detect Group Policy Preferences XML files with cpassword
        self.yara_rule = yara_x.compile("""
rule Detect_GPP_CPassword_XML {
    meta:
        description = "Detects Group Policy Preferences XML files containing encrypted cpassword credentials"
        author = "Nemesis"

    strings:
        // Basic structure identifiers
        $xml_header = "<?xml" nocase

        // The critical cpassword field
        $cpassword = "cpassword=" nocase

        // Common GPP file structures
        $properties = "<Properties" nocase
        $user = "<User" nocase
        $groups = "<Groups" nocase

        // Common attributes that appear with cpassword
        $username = "userName=" nocase

    condition:
        $xml_header and
        $cpassword and
        $properties and
        ($user or $groups or $username)
}
        """)

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run based on file type."""
        file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

        # ensure we only look at plaintext XMLs
        if (not file_enriched.is_plaintext) or "text/xml" not in file_enriched.mime_type.lower():
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

    def _decrypt_cpassword(self, cpassword: str) -> str | None:
        """
        Decrypts a single Group Policy Preferences cpassword.

        Adapted from https://github.com/ShutdownRepo/Get-GPPPassword/blob/main/Get-GPPPassword.py
        License: GPLv3
        """
        try:
            if not cpassword or len(cpassword) == 0:
                return ""

            # MS published AES key from MS-GPPREF documentation
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be
            key = b"\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"

            # Fixed IV of all zeros
            iv = b"\x00" * 16

            # Fix padding for base64
            pad = len(cpassword) % 4
            if pad == 1:
                cpassword = cpassword[:-1]
            elif pad == 2 or pad == 3:
                cpassword += "=" * (4 - pad)

            # Decrypt
            pw_enc = base64.b64decode(cpassword)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pw_dec = unpad(cipher.decrypt(pw_enc), cipher.block_size)

            password = pw_dec.decode("utf-16-le")
            return password if password else "<empty>"

        except Exception as e:
            logger.error(f"Error decrypting cpassword: {str(e)}")
            return None

    def _parse_gpp_xml(self, xml_content: str) -> list[dict]:
        """Parse the Group Policy Preferences XML content and extract credentials."""
        credentials = []
        try:
            root = ET.fromstring(xml_content)

            # Look for Properties elements that contain cpassword
            for properties in root.iter("Properties"):
                try:
                    cpassword = properties.get("cpassword", "")

                    if cpassword:
                        entry = {
                            "username": properties.get("userName", ""),
                            "cpassword": cpassword,
                            "password": "",
                            "action": properties.get("action", ""),
                            "description": properties.get("description", ""),
                            "full_name": properties.get("fullName", ""),
                            "new_name": properties.get("newName", ""),
                            "disabled": False,
                            "never_expires": False,
                            "change_logon": False,
                            "no_change": False,
                            "changed": "",
                        }

                        # Decrypt the password
                        decrypted = self._decrypt_cpassword(cpassword)
                        if decrypted:
                            entry["password"] = decrypted

                        # Parse boolean fields
                        if properties.get("acctDisabled"):
                            entry["disabled"] = bool(int(properties.get("acctDisabled", "0")))
                        if properties.get("neverExpires"):
                            entry["never_expires"] = bool(int(properties.get("neverExpires", "0")))
                        if properties.get("changeLogon"):
                            entry["change_logon"] = bool(int(properties.get("changeLogon", "0")))
                        if properties.get("noChange"):
                            entry["no_change"] = bool(int(properties.get("noChange", "0")))

                        # Get changed timestamp from parent node if available
                        parent = None
                        for elem in root.iter():
                            if properties in elem:
                                parent = elem
                                break

                        if parent is not None and parent.get("changed"):
                            entry["changed"] = parent.get("changed", "")

                        # Only add entries with valid passwords and active accounts
                        if entry["password"] and entry["password"] not in ["", "<empty>"] and not entry["disabled"]:
                            credentials.append(entry)

                except Exception as e:
                    logger.error(f"Error parsing GPP entry: {str(e)}")
                    continue

            return credentials

        except Exception as e:
            logger.error(f"Error parsing Group Policy Preferences XML: {str(e)}")
            return []

    def _create_finding_summary(self, credentials: list[dict], file_name: str) -> str:
        """Creates a markdown summary for the credentials finding."""
        summary = "# Group Policy Preferences Credentials Detected\n\n"
        summary += f"**File**: `{file_name}`\n\n"
        summary += "---\n\n"

        for cred in credentials:
            summary += f"## Credential Entry\n"
            summary += f"* **Username**: `{cred['username']}`\n"
            summary += f"* **Password**: `{cred['password']}`\n"

            if cred['action']:
                summary += f"* **Action**: `{cred['action']}`\n"
            if cred['description']:
                summary += f"* **Description**: `{cred['description']}`\n"
            if cred['full_name']:
                summary += f"* **Full Name**: `{cred['full_name']}`\n"
            if cred['changed']:
                summary += f"* **Changed**: `{cred['changed']}`\n"

            summary += f"* **Never Expires**: `{cred['never_expires']}`\n"
            summary += f"* **Disabled**: `{cred['disabled']}`\n\n"

        return summary

    def _analyze_gpp_xml(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze Group Policy Preferences XML file and generate enrichment result.

        Args:
            file_path: Path to the GPP XML file to analyze
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

        try:
            content = Path(file_path).read_text(encoding="utf-8")

            # Parse the XML and extract credentials
            credentials = self._parse_gpp_xml(content)

            if credentials:
                # Create finding summary
                summary_markdown = self._create_finding_summary(credentials, file_enriched.file_name)

                # Create display data
                display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

                # Create finding
                finding = Finding(
                    category=FindingCategory.CREDENTIAL,
                    finding_name="cpassword_decrypted",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=file_enriched.object_id,
                    severity=9,
                    raw_data={"credentials": credentials},
                    data=[display_data],
                )

                enrichment_result.findings = [finding]
                enrichment_result.results = {"credentials": credentials}

                # Create a displayable version of the results
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_display_file:
                    display = "Group Policy Preferences Analysis\n"
                    display += "=================================\n\n"

                    for cred in credentials:
                        display += f"Username: {cred['username']}\n"
                        display += f"Password: {cred['password']}\n"

                        if cred['action']:
                            display += f"Action: {cred['action']}\n"
                        if cred['description']:
                            display += f"Description: {cred['description']}\n"
                        if cred['full_name']:
                            display += f"Full Name: {cred['full_name']}\n"
                        if cred['changed']:
                            display += f"Changed: {cred['changed']}\n"

                        display += f"Never Expires: {cred['never_expires']}\n"
                        display += f"Disabled: {cred['disabled']}\n"
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
            logger.exception(message=f"Error analyzing Group Policy Preferences XML for {file_enriched.file_name}")
            return None

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process Group Policy Preferences XML file and extract credentials.

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
                return self._analyze_gpp_xml(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_gpp_xml(temp_file.name, file_enriched)

        except Exception:
            logger.exception(message="Error processing Group Policy Preferences XML file")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return GroupPolicyPreferencesParser()

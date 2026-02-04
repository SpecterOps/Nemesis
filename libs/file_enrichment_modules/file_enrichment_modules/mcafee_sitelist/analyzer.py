# enrichment_modules/mcafee_sitelist/analyzer.py
import base64
import codecs
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

import yara_x
from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from Cryptodome.Cipher import DES3
from Cryptodome.Hash import SHA
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)

# Adapted from https://github.com/funoverip/mcafee-sitelist-pwd-decryption/blob/master/mcafee_sitelist_pwd_decrypt.py
# Credit to funoverip
# No license


class McAfeeSiteListParser(EnrichmentModule):
    name: str = "mcafee_sitelist_parser"
    dependencies: list[str] = []

    def __init__(self):
        self.storage = StorageMinio()

        self.asyncpg_pool = None  # type: ignore

        # the workflows this module should automatically run in
        self.workflows = ["default"]

        self.size_limit = 1_000_000  # 1MB size limit

        # Yara rule to detect McAfee SiteList.xml files
        self.yara_rule = yara_x.compile("""
rule Detect_McAfee_SiteList_XML {
    meta:
        description = "Detects McAfee SiteList.xml files that may contain encrypted credentials"
        author = "Nemesis"

    strings:
        // Basic structure identifiers
        $xml_header = "<?xml" nocase
        $sitelist_single = "<SiteList" nocase
        $sitelist_plural = "<SiteLists" nocase
        $namespace = "naSiteList" nocase

        // Key elements that indicate credential storage
        $password = "<Password" nocase
        $encrypted = "Encrypted" nocase
        $username = "<UserName>" nocase

        // McAfee-specific site types and elements
        $unc_site = "<UNCSite" nocase
        $http_site = "<HttpSite" nocase
        $share_name = "<ShareName>" nocase
        $domain_name = "<DomainName>" nocase
        $relative_path = "<RelativePath>" nocase
        $use_auth = "<UseAuth>" nocase

    condition:
        $xml_header and
        ($sitelist_single or $sitelist_plural or $namespace) and
        $password and
        2 of ($username, $encrypted, $unc_site, $http_site, $share_name, $domain_name, $relative_path, $use_auth)
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

    def _sitelist_xor(self, xs: bytes) -> bytes:
        """
        Decryption helper for XOR operation.

        Adapted from https://github.com/funoverip/mcafee-sitelist-pwd-decryption/blob/master/mcafee_sitelist_pwd_decrypt.py
        Credit to funoverip
        """
        decode_hex: Callable[[bytes], tuple[bytes, int]] = codecs.getdecoder("hex_codec")  # type: ignore

        # hardcoded XOR key
        KEY: bytes = decode_hex(b"12150F10111C1A060A1F1B1817160519")[0]

        return bytes([c ^ KEY[i % 16] for i, c in enumerate(xs)])

    def _decrypt_sitelist_password(self, b64data: str) -> str | None:
        """
        Decrypts a single base64 encrypted sitelist password.

        Adapted from https://github.com/funoverip/mcafee-sitelist-pwd-decryption/blob/master/mcafee_sitelist_pwd_decrypt.py
        Credit to funoverip
        """
        try:
            data = self._sitelist_xor(base64.b64decode(b64data))
            decode_hex = codecs.getdecoder("hex_codec")

            # hardcoded 3DES key
            key = SHA.new(b"<!@#$%^>").digest() + decode_hex(b"00000000")[0]  # type: ignore

            try:
                des3 = DES3.new(key, DES3.MODE_ECB, None)
            except (TypeError, ValueError):
                des3 = DES3.new(key, DES3.MODE_ECB)

            decrypted = des3.decrypt(bytes(data))

            # quick hack to ignore padding
            password = decrypted[0 : decrypted.find(b"\x00")].decode("utf-8")
            return password if password else "<empty>"

        except Exception as e:
            logger.error(f"Error decrypting password: {str(e)}")
            return None

    def _parse_sitelist_xml(self, xml_content: str) -> list[dict]:
        """Parse the SiteList.xml content and extract credentials."""
        credentials = []
        try:
            root = ET.fromstring(xml_content)

            for sitelist in root:
                nodes = list(sitelist)

                for node in nodes:
                    try:
                        entry = {
                            "type": node.get("Type", ""),
                            "name": node.get("Name", ""),
                            "server": node.get("Server", ""),
                            "enabled": bool(int(node.get("Enabled", "0"))),
                            "local": bool(int(node.get("Local", "0"))),
                            "username": "",
                            "password": "",
                            "password_encrypted": "",
                            "domain_name": "",
                            "share_name": "",
                            "relative_path": "",
                            "use_auth": False,
                            "use_loggedon_user_account": False,
                        }

                        for element in list(node):
                            name = element.tag
                            data = element.text

                            if data:
                                if name.lower() == "password":
                                    if element.get("Encrypted") == "1":
                                        entry["password_encrypted"] = data
                                        dec_pass = self._decrypt_sitelist_password(data)
                                        if dec_pass:
                                            entry["password"] = dec_pass
                                    else:
                                        entry["password"] = data
                                elif name.lower() == "username":
                                    entry["username"] = data
                                elif name.lower() == "domainname":
                                    entry["domain_name"] = data
                                elif name.lower() == "sharename":
                                    entry["share_name"] = data
                                elif name.lower() == "relativepath":
                                    entry["relative_path"] = data
                                elif name.lower() == "useauth":
                                    entry["use_auth"] = bool(int(data))
                                elif name.lower() == "useloggedonuseraccount":
                                    entry["use_loggedon_user_account"] = bool(int(data))

                        # Only add entries with valid credentials
                        if entry["password"] and entry["password"] not in ["", "<empty>"]:
                            credentials.append(entry)

                    except Exception as e:
                        logger.error(f"Error parsing sitelist entry: {str(e)}")
                        continue

            return credentials

        except Exception as e:
            logger.error(f"Error parsing SiteList.xml: {str(e)}")
            return []

    def _create_finding_summary(self, credentials: list[dict]) -> str:
        """Creates a markdown summary for the credentials finding."""
        summary = "# McAfee SiteList.xml Credentials Detected\n\n"

        for cred in credentials:
            summary += f"## {cred['type']} - {cred['name']}\n"
            summary += f"* **Server**: `{cred['server']}`\n"
            summary += f"* **Username**: `{cred['username']}`\n"
            if cred["domain_name"]:
                summary += f"* **Domain**: `{cred['domain_name']}`\n"
            summary += f"* **Password**: `{cred['password']}`\n"
            if cred["share_name"]:
                summary += f"* **Share**: `{cred['share_name']}`\n"
            if cred["relative_path"]:
                summary += f"* **Path**: `{cred['relative_path']}`\n"
            summary += f"* **Enabled**: `{cred['enabled']}`\n\n"

        return summary

    def _analyze_sitelist_xml(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze SiteList.xml file and generate enrichment result.

        Args:
            file_path: Path to the SiteList.xml file to analyze
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

        try:
            content = Path(file_path).read_text(encoding="utf-8")

            # Parse the XML and extract credentials
            credentials = self._parse_sitelist_xml(content)

            if credentials:
                # Create finding summary
                summary_markdown = self._create_finding_summary(credentials)

                # Create display data
                display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

                # Create finding
                finding = Finding(
                    category=FindingCategory.CREDENTIAL,
                    finding_name="mcafee_sitelist_credentials_detected",
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
                    display = "McAfee SiteList.xml Analysis\n"
                    display += "============================\n\n"

                    for cred in credentials:
                        display += f"Type: {cred['type']}\n"
                        display += f"Name: {cred['name']}\n"
                        display += f"Server: {cred['server']}\n"
                        display += f"Username: {cred['username']}\n"
                        if cred["domain_name"]:
                            display += f"Domain: {cred['domain_name']}\n"
                        display += f"Password: {cred['password']}\n"
                        if cred["share_name"]:
                            display += f"Share: {cred['share_name']}\n"
                        if cred["relative_path"]:
                            display += f"Path: {cred['relative_path']}\n"
                        display += f"Enabled: {cred['enabled']}\n"
                        display += f"Local: {cred['local']}\n"
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
            logger.exception(message=f"Error analyzing SiteList.xml for {file_enriched.file_name}")
            return None

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process SiteList.xml file and extract credentials.

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
                return self._analyze_sitelist_xml(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_sitelist_xml(temp_file.name, file_enriched)

        except Exception:
            logger.exception(message="Error processing SiteList.xml file")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return McAfeeSiteListParser()

# enrichment_modules/filezilla/analyzer.py
import base64
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

import yara_x
from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)


class FileZillaParser(EnrichmentModule):
    name: str = "filezilla_parser"
    dependencies: list[str] = []
    def __init__(self):
        self.storage = StorageMinio()
        # the workflows this module should automatically run in
        self.workflows = ["default"]

        self.size_limit = 50000000  # only check the first 50 megs, for efficiency

        # Yara rule to detect FileZilla configuration files
        self.yara_rule = yara_x.compile("""
rule Detect_FileZilla_Config {
    meta:
        description = "Detects FileZilla configuration files that may contain sensitive data"
        author = "Claude"
        severity = "Medium"

    strings:
        // XML header
        $xml_header = "<?xml" nocase

        // FileZilla specific identifiers
        $filezilla = "FileZilla3" nocase
        $servers = "<Servers>" nocase
        $recentservers = "<RecentServers>" nocase
        $server = "<Server>" nocase

        // Connection details
        $host = "<Host>" nocase
        $port = "<Port>" nocase
        $user = "<User>" nocase
        $pass = "<Pass" nocase

        // Protocol indicators
        $protocol = "<Protocol>" nocase

    condition:
        $xml_header and $filezilla and
        ($servers or $recentservers) and $server and
        all of ($host, $port, $user) and
        ($pass or $protocol)
}
        """)

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run based on file type."""
        file_enriched = get_file_enriched(object_id)

        # Initial checks for file type and name
        if not file_enriched.is_plaintext:
            return False

        # Check if filename suggests FileZilla config
        filename_lower = file_enriched.file_name.lower()
        if not (
            filename_lower in ["sitemanager.xml", "recentservers.xml", "filezilla.xml"] or "filezilla" in filename_lower
        ):
            return False

        # Check using Yara rule as a fallback
        if file_path:
            # Use provided file path
            with open(file_path, "rb") as f:
                num_bytes = min(file_enriched.size, self.size_limit)
                file_bytes = f.read(num_bytes)
        else:
            # Fallback to downloading the file itself
            num_bytes = file_enriched.size if file_enriched.size < self.size_limit else self.size_limit
            file_bytes = self.storage.download_bytes(file_enriched.object_id, length=num_bytes)

        should_run = len(self.yara_rule.scan(file_bytes).matching_rules) > 0

        return should_run

    def _decode_password(self, password_elem) -> str:
        """Decode password based on encoding attribute."""
        if password_elem is None:
            return "<NO PASSWORD>"

        password_text = password_elem.text or ""

        # Check for encoding attribute
        encoding = password_elem.get("encoding", "").lower()

        if encoding == "base64":
            try:
                decoded = base64.b64decode(password_text).decode("utf-8")
                return decoded
            except Exception as e:
                logger.error(f"Error decoding base64 password: {str(e)}")
                return f"<BASE64 DECODE ERROR: {password_text}>"
        elif encoding == "crypt":
            return "<PROTECTED BY MASTER PASSWORD>"
        elif encoding == "" and password_text:
            # No encoding means plaintext (if there's actual text)
            return password_text
        elif encoding == "" and not password_text:
            return "<EMPTY PASSWORD>"
        else:
            return f"<UNKNOWN ENCODING '{encoding}': {password_text}>"

    def _get_protocol_name(self, protocol_code: str) -> str:
        """Convert protocol code to human readable name."""
        protocol_map = {"0": "FTP", "1": "SFTP", "3": "FTPS (Explicit)", "4": "FTPS (Implicit)", "6": "FTPES"}
        return protocol_map.get(protocol_code, f"Unknown ({protocol_code})")

    def _parse_filezilla_xml(self, xml_content: str) -> list[dict]:
        """Parse the FileZilla XML content and extract server configurations."""
        servers = []
        try:
            root = ET.fromstring(xml_content)

            # Find all Server elements
            server_elements = root.findall(".//Server")

            for server in server_elements:
                server_config = {}

                # Extract basic connection info
                server_config["host"] = server.findtext("Host", "<UNKNOWN>")
                server_config["port"] = server.findtext("Port", "21")
                server_config["username"] = server.findtext("User", "<NO USERNAME>")
                server_config["name"] = server.findtext("Name", "<UNNAMED>")

                # Extract and decode password
                password_elem = server.find("Pass")
                server_config["password"] = self._decode_password(password_elem)

                # Extract protocol info
                protocol_code = server.findtext("Protocol", "0")
                server_config["protocol"] = self._get_protocol_name(protocol_code)
                server_config["protocol_code"] = protocol_code

                # Extract logon type
                logontype = server.findtext("Logontype", "0")
                logontype_map = {
                    "0": "Anonymous",
                    "1": "Normal",
                    "2": "Ask for password",
                    "3": "Key file",
                    "4": "Interactive",
                }
                server_config["logon_type"] = logontype_map.get(logontype, f"Unknown ({logontype})")

                # Additional settings
                server_config["account"] = server.findtext("Account", "")
                server_config["bypass_proxy"] = server.findtext("BypassProxy", "0") == "1"
                server_config["pasv_mode"] = server.findtext("PasvMode", "MODE_DEFAULT")
                server_config["encoding"] = server.findtext("EncodingType", "Auto")
                server_config["timezone_offset"] = server.findtext("TimezoneOffset", "0")
                server_config["max_connections"] = server.findtext("MaximumMultipleConnections", "0")
                server_config["comments"] = server.findtext("Comments", "")
                server_config["local_dir"] = server.findtext("LocalDir", "")
                server_config["remote_dir"] = server.findtext("RemoteDir", "")
                server_config["sync_browsing"] = server.findtext("SyncBrowsing", "0") == "1"

                servers.append(server_config)

        except Exception as e:
            logger.error(f"Error parsing FileZilla XML: {str(e)}")

        return servers

    def _create_finding_summary(self, servers: list[dict], file_name: str) -> str:
        """Creates a markdown summary for the FileZilla configurations finding."""
        summary = f"# FileZilla Configuration Analysis - {file_name}\n\n"
        summary += f"Found **{len(servers)}** server configuration(s)\n\n"

        for i, server in enumerate(servers, 1):
            summary += f"## Server {i}: {server['name']}\n"
            summary += f"* **Host**: `{server['host']}:{server['port']}`\n"
            summary += f"* **Protocol**: {server['protocol']}\n"
            summary += f"* **Username**: `{server['username']}`\n"
            summary += f"* **Password**: `{server['password']}`\n"
            summary += f"* **Logon Type**: {server['logon_type']}\n"

            # Add account if present
            if server.get("account"):
                summary += f"* **Account**: `{server['account']}`\n"

            # Add additional details if present
            if server["bypass_proxy"]:
                summary += "* **Proxy**: Bypassed\n"
            if server["pasv_mode"] != "MODE_DEFAULT":
                summary += f"* **PASV Mode**: {server['pasv_mode']}\n"
            if server["encoding"] != "Auto":
                summary += f"* **Encoding**: {server['encoding']}\n"
            if server.get("comments"):
                summary += f"* **Comments**: {server['comments']}\n"
            if server.get("local_dir"):
                summary += f"* **Local Dir**: {server['local_dir']}\n"
            if server.get("remote_dir"):
                summary += f"* **Remote Dir**: {server['remote_dir']}\n"
            if server.get("sync_browsing"):
                summary += "* **Sync Browsing**: Enabled\n"

            summary += "\n"

        return summary

    def _has_credentials(self, servers: list[dict]) -> bool:
        """Check if any server has extractable credentials."""
        for server in servers:
            password = server.get("password", "")
            username = server.get("username", "")

            # Consider it a credential finding if we have a username and a password that's not empty/protected
            if (
                username
                and username != "<NO USERNAME>"
                and password
                and password not in ["<NO PASSWORD>", "<EMPTY PASSWORD>", "<PROTECTED BY MASTER PASSWORD>"]
            ):
                return True
        return False

    def _analyze_filezilla(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze FileZilla configuration file and generate enrichment result.

        Args:
            file_path: Path to the FileZilla config file to analyze
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

        try:
            content = Path(file_path).read_text(encoding="utf-8")

            # Parse the XML and extract server configurations
            servers = self._parse_filezilla_xml(content)

            if servers:
                # Create finding summary
                summary_markdown = self._create_finding_summary(servers, file_enriched.file_name)

                # Create display data
                display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

                # Determine if this should be a credential finding or just informational
                has_creds = self._has_credentials(servers)

                # Create finding
                finding = Finding(
                    category=FindingCategory.CREDENTIAL if has_creds else FindingCategory.MISC,
                    finding_name="filezilla_config_detected" if not has_creds else "filezilla_credentials_detected",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=file_enriched.object_id,
                    severity=7 if has_creds else 4,
                    raw_data={"servers": servers, "file_type": file_enriched.file_name},
                    data=[display_data],
                )

                enrichment_result.findings = [finding]
                enrichment_result.results = {"servers": servers, "server_count": len(servers)}

                # Create a displayable version of the results
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_display_file:
                    display = f"FileZilla Configuration Analysis - {file_enriched.file_name}\n"
                    display += "=" * (35 + len(file_enriched.file_name)) + "\n\n"
                    display += f"Total Servers: {len(servers)}\n\n"

                    for i, server in enumerate(servers, 1):
                        display += f"Server {i}: {server['name']}\n"
                        display += f"  Host:        {server['host']}:{server['port']}\n"
                        display += f"  Protocol:    {server['protocol']}\n"
                        display += f"  Username:    {server['username']}\n"
                        display += f"  Password:    {server['password']}\n"
                        display += f"  Logon Type:  {server['logon_type']}\n"

                        # Add account if present
                        if server.get("account"):
                            display += f"  Account:     {server['account']}\n"

                        # Add additional details if present
                        if server["bypass_proxy"]:
                            display += "  Proxy:       Bypassed\n"
                        if server["pasv_mode"] != "MODE_DEFAULT":
                            display += f"  PASV Mode:   {server['pasv_mode']}\n"
                        if server["encoding"] != "Auto":
                            display += f"  Encoding:    {server['encoding']}\n"
                        if server.get("timezone_offset", "0") != "0":
                            display += f"  Timezone:    {server['timezone_offset']}\n"
                        if server.get("max_connections", "0") != "0":
                            display += f"  Max Conns:   {server['max_connections']}\n"
                        if server.get("comments"):
                            display += f"  Comments:    {server['comments']}\n"
                        if server.get("local_dir"):
                            display += f"  Local Dir:   {server['local_dir']}\n"
                        if server.get("remote_dir"):
                            display += f"  Remote Dir:  {server['remote_dir']}\n"
                        if server.get("sync_browsing"):
                            display += "  Sync Browse: Enabled\n"

                        display += "\n" + "-" * 50 + "\n\n"

                    tmp_display_file.write(display)
                    tmp_display_file.flush()

                    display_object_id = self.storage.upload_file(tmp_display_file.name)

                    displayable_parsed = Transform(
                        type="displayable_parsed",
                        object_id=f"{display_object_id}",
                        metadata={
                            "file_name": f"{file_enriched.file_name}_analysis.txt",
                            "display_type_in_dashboard": "monaco",
                            "default_display": True,
                        },
                    )
                    enrichment_result.transforms = [displayable_parsed]

            return enrichment_result
        except Exception as e:
            logger.exception(e, message=f"Error analyzing FileZilla config for {file_enriched.file_name}")
            return None

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process FileZilla configuration file and extract server details.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file

        Returns:
            EnrichmentResult or None if processing fails
        """
        try:
            file_enriched = get_file_enriched(object_id)

            # Use provided file_path if available, otherwise download
            if file_path:
                return self._analyze_filezilla(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_filezilla(temp_file.name, file_enriched)

        except Exception as e:
            logger.exception(e, message="Error processing FileZilla configuration file")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return FileZillaParser()

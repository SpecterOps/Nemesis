# enrichment_modules/vnc_ini/analyzer.py
import tempfile
import textwrap
from pathlib import Path

from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from Crypto.Cipher import DES
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)

# VNC obfuscates stored passwords with DES under the fixed key 17 52 6B 06 23 4E 58 07, applied with each key byte's
# bits reversed (the d3des convention). For a standard DES implementation the key is therefore e8 4a d6 60 c4 72 1a e0.
VNC_DES_KEY = bytes.fromhex("e84ad660c4721ae0")

# (section, key) pairs holding obfuscated passwords, matched case-insensitively.
#   RealVNC/TightVNC-style ini: [Server] Password
#   UltraVNC ultravnc.ini: [ultravnc] passwd (full access) and passwd2 (view-only); 18 hex digits = 9 bytes, of which
#   only the first 8 are the DES block.
PASSWORD_FIELDS = (("server", "password"), ("ultravnc", "passwd"), ("ultravnc", "passwd2"))

# Port of https://github.com/NetSPI/PowerHuntShares/blob/46238ba37dc85f65f2c1d7960f551ea3d80c236a/Scripts/ConfigParsers/parser-vnc.ini.ps1
#   Original Author: Scott Sutherland, NetSPI (@_nullbind / nullbind)
#   License: BSD 3-clause


class VncParser(EnrichmentModule):
    name: str = "vnc_parser"
    dependencies: list[str] = []

    def __init__(self):
        self.storage = StorageMinio()

        self.asyncpg_pool = None  # type: ignore

        self.des_key = VNC_DES_KEY

        # the workflows this module should automatically run in
        self.workflows = ["default"]

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run based on file type."""
        file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)
        should_run = (
            file_enriched.file_name.lower().endswith(".ini")
            and "vnc" in file_enriched.file_name.lower()
            and "text" in file_enriched.magic_type.lower()
        )
        return should_run

    def _decrypt_password(self, encrypted_hex: str) -> str | None:
        """Decrypt the VNC password using the fixed DES key."""
        try:
            encrypted_bytes = bytes.fromhex(encrypted_hex.strip())
        except ValueError as e:
            logger.warning(f"VNC password is not valid hex: {e}")
            return None
        if len(encrypted_bytes) < 8:
            logger.warning(f"VNC password is too short to decrypt ({len(encrypted_bytes)} bytes)")
            return None

        # VNC passwords are at most 8 characters: one DES block. UltraVNC appends a ninth byte, which is ignored.
        cipher = DES.new(self.des_key, DES.MODE_ECB)
        decrypted_bytes = cipher.decrypt(encrypted_bytes[:8]).rstrip(b"\0")
        if not decrypted_bytes:
            return None
        # Non-ASCII bytes (e.g. a corrupted value) are kept visible rather than dropping the finding.
        return decrypted_bytes.decode("latin-1")

    def _create_finding_summary(self, config: dict, decrypted_password: str) -> str:
        """Creates a markdown summary for the VNC password finding."""
        summary = "# VNC Password Detected\n\n"
        summary += "### Configuration Details\n"

        for section, values in config.items():
            summary += f"\n## {section}\n"
            for key, value in values.items():
                if (section.lower(), key.lower()) in PASSWORD_FIELDS:
                    summary += f"* **Encrypted {key}**: `{value}`\n"
                elif key.startswith("Decrypted"):
                    summary += f"* **{key}**: `{value}`\n"
                else:
                    summary += f"* **{key}**: {value}\n"

        return summary

    def _parse_vnc_config(self, config_content: str) -> dict:
        """Parse the VNC configuration file content."""
        config = {}
        current_section = None

        for line in config_content.splitlines():
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith(("#", ";")):
                continue

            # Check for section headers
            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1]
                config[current_section] = {}
                continue

            # Parse key-value pairs
            if "=" in line and current_section:
                key, value = line.split("=", 1)
                config[current_section][key.strip()] = value.strip()

        return config

    def _decrypt_config_passwords(self, config: dict) -> list[str]:
        """Decrypt each known password field in place, adding a ``Decrypted<Key>`` entry next to it."""
        decrypted = []
        for section, values in config.items():
            for key in list(values):
                if (section.lower(), key.lower()) not in PASSWORD_FIELDS:
                    continue
                password = self._decrypt_password(values[key])
                if password:
                    values[f"Decrypted{key[:1].upper()}{key[1:]}"] = password
                    decrypted.append(password)
        return decrypted

    def _analyze_vnc_config(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze VNC config file and generate enrichment result.

        Args:
            file_path: Path to the VNC config file to analyze
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")

            # Parse the configuration
            config = self._parse_vnc_config(content)

            # Extract and decrypt every stored password
            decrypted_passwords = self._decrypt_config_passwords(config)
            if decrypted_passwords:
                # Create finding summary
                summary_markdown = self._create_finding_summary(config, decrypted_passwords[0])

                # Create display data
                display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

                # Create finding
                finding = Finding(
                    category=FindingCategory.CREDENTIAL,
                    finding_name="vnc_password_detected",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=file_enriched.object_id,
                    severity=7,
                    raw_data={"config": config},
                    data=[display_data],
                )

                # Add finding to enrichment result
                if not enrichment_result.findings:
                    enrichment_result.findings = []
                enrichment_result.findings.append(finding)

            enrichment_result.results = config

            # Create a displayable version of the results
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_display_file:
                # Convert config to YAML with custom formatting
                yaml_output = []
                yaml_output.append("VNC Configuration Analysis")
                yaml_output.append("========================\n")

                for section, values in config.items():
                    yaml_output.append(f"{section}:")
                    for key, value in values.items():
                        # Highlight the decrypted password if present
                        if key.startswith("Decrypted"):
                            yaml_output.append(f"   {key}: !!! {value} !!!")
                        else:
                            yaml_output.append(f"   {key}: {value}")
                    yaml_output.append("")  # Add empty line between sections

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
            logger.exception(message=f"Error analyzing VNC config for {file_enriched.file_name}")
            return None

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process VNC config file and decrypt password if present.

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
                return self._analyze_vnc_config(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_vnc_config(temp_file.name, file_enriched)

        except Exception:
            logger.exception(message="Error processing VNC config file")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return VncParser()

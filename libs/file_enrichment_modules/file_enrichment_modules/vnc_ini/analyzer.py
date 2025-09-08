# enrichment_modules/vnc_ini/analyzer.py
import tempfile
import textwrap
from pathlib import Path

import structlog
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from Crypto.Cipher import DES
from file_enrichment_modules.module_loader import EnrichmentModule

logger = structlog.get_logger(module=__name__)

# Port of https://github.com/NetSPI/PowerHuntShares/blob/46238ba37dc85f65f2c1d7960f551ea3d80c236a/Scripts/ConfigParsers/parser-vnc.ini.ps1
#   Original Author: Scott Sutherland, NetSPI (@_nullbind / nullbind)
#   License: BSD 3-clause


class VncParser(EnrichmentModule):
    def __init__(self):
        super().__init__("vnc_parser")
        self.storage = StorageMinio()

        # Define the fixed DES key used by VNC
        self.des_key = bytes([0x23, 0x52, 0x6A, 0x3B, 0x58, 0x92, 0x67, 0x34])

        # the workflows this module should automatically run in
        self.workflows = ["default"]

    def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run based on file type."""
        file_enriched = get_file_enriched(object_id)
        should_run = (
            file_enriched.file_name.lower().endswith(".ini")
            and "vnc" in file_enriched.file_name.lower()
            and "text" in file_enriched.magic_type.lower()
        )
        return should_run

    def _decrypt_password(self, encrypted_hex: str) -> str | None:
        """Decrypt the VNC password using the fixed DES key."""
        try:
            # Convert hex string to bytes
            encrypted_bytes = bytes.fromhex(encrypted_hex.strip())

            # Create DES cipher in ECB mode with no padding
            cipher = DES.new(self.des_key, DES.MODE_ECB)

            # Decrypt the password
            decrypted_bytes = cipher.decrypt(encrypted_bytes)

            # Convert to string and remove null padding
            decrypted_password = decrypted_bytes.decode("ascii").rstrip("\0")

            return decrypted_password
        except Exception as e:
            logger.error(f"Error decrypting password: {str(e)}")
            return None

    def _create_finding_summary(self, config: dict, decrypted_password: str) -> str:
        """Creates a markdown summary for the VNC password finding."""
        summary = "# VNC Password Detected\n\n"
        summary += "### Configuration Details\n"

        for section, values in config.items():
            summary += f"\n## {section}\n"
            for key, value in values.items():
                if key == "Password":
                    summary += f"* **Encrypted Password**: `{value}`\n"
                elif key == "DecryptedPassword":
                    summary += f"* **Decrypted Password**: `{value}`\n"
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
            if not line or line.startswith("#"):
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
            content = Path(file_path).read_text(encoding="utf-8")

            # Parse the configuration
            config = self._parse_vnc_config(content)

            # Extract and decrypt password if present
            server_config = config.get("Server", {})
            if "Password" in server_config:
                decrypted_password = self._decrypt_password(server_config["Password"])
                if decrypted_password:
                    server_config["DecryptedPassword"] = decrypted_password

                    # Create finding summary
                    summary_markdown = self._create_finding_summary(config, decrypted_password)

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
                        if key == "DecryptedPassword":
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

        except Exception as e:
            logger.exception(e, message=f"Error analyzing VNC config for {file_enriched.file_name}")
            return None

    def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process VNC config file and decrypt password if present.

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
                return self._analyze_vnc_config(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_vnc_config(temp_file.name, file_enriched)

        except Exception as e:
            logger.exception(e, message="Error processing VNC config file")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return VncParser()

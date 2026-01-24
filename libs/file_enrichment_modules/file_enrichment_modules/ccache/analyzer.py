# enrichment_modules/ccache/analyzer.py
import tempfile
from datetime import UTC, datetime

import yara_x
from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule
from impacket.krb5.ccache import CCache

logger = get_logger(__name__)


class CcacheAnalyzer(EnrichmentModule):
    """Analyzer for Kerberos Credential Cache (ccache) files.

    Ccache files store Kerberos tickets (TGTs and service tickets) that can be
    used for pass-the-ticket attacks and lateral movement.
    """

    name: str = "ccache_analyzer"
    dependencies: list[str] = []

    # Encryption types mapping for readable output
    ENCRYPTION_TYPES = {
        1: "DES-CBC-CRC",
        2: "DES-CBC-MD4",
        3: "DES-CBC-MD5",
        5: "DES3-CBC-SHA1",
        16: "DES3-CBC-SHA1-KD",
        17: "AES-128-CTS-HMAC-SHA1-96",
        18: "AES-256-CTS-HMAC-SHA1-96",
        23: "RC4-HMAC",
        24: "RC4-HMAC-EXP",
    }

    # Ticket flags
    TICKET_FLAGS = {
        0x40000000: "forwardable",
        0x20000000: "forwarded",
        0x10000000: "proxiable",
        0x08000000: "proxy",
        0x04000000: "may-postdate",
        0x02000000: "postdated",
        0x01000000: "invalid",
        0x00800000: "renewable",
        0x00400000: "initial",
        0x00200000: "pre-authent",
        0x00100000: "hw-authent",
        0x00080000: "transited-policy-checked",
        0x00040000: "ok-as-delegate",
    }

    def __init__(self):
        self.storage = StorageMinio()
        self.workflows = ["default"]
        self.size_limit = 50_000_000  # 50 MB limit for YARA scanning
        self.asyncpg_pool = None

        # YARA rule to detect ccache files by magic bytes
        self.yara_rule = yara_x.compile("""
rule CCache_File {
    meta:
        description = "Detects Kerberos credential cache files"

    strings:
        $ccache_v4 = { 05 04 }
        $ccache_v3 = { 05 03 }

    condition:
        ($ccache_v4 at 0) or ($ccache_v3 at 0)
}
        """)

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should process the file."""
        file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

        # Fast path: check file extension
        if file_enriched.file_name.lower().endswith(".ccache"):
            return True

        # Also check for krb5cc_ prefix (Linux default naming)
        if file_enriched.file_name.lower().startswith("krb5cc_"):
            return True

        # Slow path: YARA check for magic bytes
        if file_path:
            with open(file_path, "rb") as f:
                num_bytes = min(file_enriched.size, self.size_limit)
                file_bytes = f.read(num_bytes)
        else:
            num_bytes = min(file_enriched.size, self.size_limit)
            file_bytes = self.storage.download_bytes(file_enriched.object_id, length=num_bytes)

        return len(self.yara_rule.scan(file_bytes).matching_rules) > 0

    def _format_timestamp(self, timestamp: int) -> str:
        """Format Unix timestamp to ISO format, handling edge cases."""
        if timestamp == 0:
            return "N/A"
        try:
            return datetime.fromtimestamp(timestamp, tz=UTC).isoformat()
        except (OSError, ValueError):
            return f"Invalid ({timestamp})"

    def _decode_flags(self, flags: int) -> list[str]:
        """Decode ticket flags into human-readable list."""
        decoded = []
        for flag_value, flag_name in self.TICKET_FLAGS.items():
            if flags & flag_value:
                decoded.append(flag_name)
        return decoded

    def _get_encryption_name(self, etype: int) -> str:
        """Get human-readable encryption type name."""
        return self.ENCRYPTION_TYPES.get(etype, f"Unknown ({etype})")

    def _is_ticket_expired(self, endtime: int) -> bool:
        """Check if a ticket has expired."""
        if endtime == 0:
            return False
        try:
            return datetime.fromtimestamp(endtime, tz=UTC) < datetime.now(tz=UTC)
        except (OSError, ValueError):
            return True

    def _analyze_ccache_file(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze ccache file and extract credential information."""
        result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)
        transforms = []
        findings = []

        try:
            # Load ccache using impacket
            ccache = CCache.loadFile(file_path)

            # Extract principal
            principal = ccache.principal.prettyPrint().decode("utf-8") if ccache.principal else "Unknown"

            # Parse all credentials
            credentials = []
            unexpired_credentials = []

            for cred in ccache.credentials:
                # Extract credential details
                client = cred["client"].prettyPrint().decode("utf-8") if cred["client"] else "Unknown"
                server = cred["server"].prettyPrint().decode("utf-8") if cred["server"] else "Unknown"

                # Get encryption info
                key_data = cred["key"]
                etype = key_data["keytype"]
                etype_name = self._get_encryption_name(etype)

                # Get timestamps
                times = cred["time"]
                authtime = times["authtime"]
                starttime = times["starttime"]
                endtime = times["endtime"]
                renew_till = times["renew_till"]

                # Get flags
                flags = cred["tktflags"]
                flag_names = self._decode_flags(flags)

                # Check expiration
                is_expired = self._is_ticket_expired(endtime)

                cred_info = {
                    "client": client,
                    "server": server,
                    "encryption_type": etype,
                    "encryption_type_name": etype_name,
                    "authtime": self._format_timestamp(authtime),
                    "starttime": self._format_timestamp(starttime),
                    "endtime": self._format_timestamp(endtime),
                    "renew_till": self._format_timestamp(renew_till),
                    "flags": flag_names,
                    "is_expired": is_expired,
                    "is_tgt": "krbtgt" in server.lower(),
                }

                credentials.append(cred_info)

                if not is_expired:
                    unexpired_credentials.append(cred_info)

            # Generate markdown summary report
            report_lines = [
                "# Kerberos Credential Cache Analysis",
                f"\n**File:** {file_enriched.file_name}",
                f"\n**Primary Principal:** `{principal}`",
                f"\n**Total Credentials:** {len(credentials)}",
                f"\n**Unexpired Credentials:** {len(unexpired_credentials)}",
            ]

            for i, cred in enumerate(credentials, 1):
                status = "EXPIRED" if cred["is_expired"] else "VALID"
                ticket_type = "TGT" if cred["is_tgt"] else "Service Ticket"

                report_lines.append(f"\n## Credential {i} ({ticket_type}) - {status}")
                report_lines.append(f"\n**Client:** `{cred['client']}`")
                report_lines.append(f"\n**Server:** `{cred['server']}`")
                report_lines.append(f"\n**Encryption:** {cred['encryption_type_name']}")
                report_lines.append(f"\n**Auth Time:** {cred['authtime']}")
                report_lines.append(f"\n**Start Time:** {cred['starttime']}")
                report_lines.append(f"\n**End Time:** {cred['endtime']}")
                report_lines.append(f"\n**Renew Till:** {cred['renew_till']}")

                if cred["flags"]:
                    report_lines.append(f"\n**Flags:** {', '.join(cred['flags'])}")

            # Create summary report transform
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as tmp_report:
                tmp_report.write("\n".join(report_lines))
                tmp_report.flush()
                report_id = self.storage.upload_file(tmp_report.name)

                transforms.append(
                    Transform(
                        type="finding_summary",
                        object_id=str(report_id),
                        metadata={
                            "file_name": f"{file_enriched.file_name}_analysis.md",
                            "display_type_in_dashboard": "markdown",
                            "default_display": True,
                        },
                    )
                )

            # Hybrid Mode: Only create findings for unexpired credentials
            if unexpired_credentials:
                # Determine severity based on ticket types
                has_tgt = any(c["is_tgt"] for c in unexpired_credentials)
                severity = 8 if has_tgt else 6  # TGTs are more valuable

                finding_summary = "## Active Kerberos Tickets Detected\n\n"
                finding_summary += "The following **unexpired** Kerberos tickets were found:\n\n"

                for cred in unexpired_credentials:
                    ticket_type = "TGT" if cred["is_tgt"] else "Service Ticket"
                    finding_summary += f"**{ticket_type}**\n"
                    finding_summary += f"- **Client:** `{cred['client']}`\n"
                    finding_summary += f"- **Server:** `{cred['server']}`\n"
                    finding_summary += f"- **Encryption:** {cred['encryption_type_name']}\n"
                    finding_summary += f"- **Expires:** {cred['endtime']}\n\n"

                finding_summary += "\n### Security Impact\n\n"
                if has_tgt:
                    finding_summary += (
                        "- **TGT found:** Can be used to request service tickets for any service\n"
                    )
                    finding_summary += "- **Pass-the-ticket:** Export `KRB5CCNAME` and use with impacket tools\n"
                else:
                    finding_summary += "- **Service tickets:** Can be used to access specific services\n"

                display_data = FileObject(type="finding_summary", metadata={"summary": finding_summary})

                finding = Finding(
                    category=FindingCategory.CREDENTIAL,
                    finding_name="kerberos_ccache_active_tickets",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=file_enriched.object_id,
                    severity=severity,
                    raw_data={
                        "principal": principal,
                        "credentials": unexpired_credentials,
                        "total_credentials": len(credentials),
                        "unexpired_count": len(unexpired_credentials),
                    },
                    data=[display_data],
                )

                findings.append(finding)

            result.transforms = transforms
            result.findings = findings
            result.results = {
                "principal": principal,
                "credentials": credentials,
                "total_credentials": len(credentials),
                "unexpired_count": len(unexpired_credentials),
            }

            return result

        except Exception:
            logger.exception(message=f"Error analyzing ccache file: {file_enriched.file_name}")

            # Create error report
            error_report = [
                "# Ccache Analysis Error",
                f"\nFailed to analyze {file_enriched.file_name}",
                "\n## Possible Causes",
                "\n- The file may not be a valid Kerberos ccache file",
                "- The file format may be corrupted",
                "- Unsupported ccache format version",
                "\n## Troubleshooting",
                "\n- Verify with: `klist -c <file>`",
                "- Check format version (v3 or v4 supported)",
            ]

            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as tmp_error:
                tmp_error.write("\n".join(error_report))
                tmp_error.flush()
                error_id = self.storage.upload_file(tmp_error.name)

                transforms.append(
                    Transform(
                        type="finding_summary",
                        object_id=str(error_id),
                        metadata={
                            "file_name": f"{file_enriched.file_name}_analysis_error.md",
                            "display_type_in_dashboard": "markdown",
                            "default_display": True,
                        },
                    )
                )

            result.transforms = transforms
            return result

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process ccache file."""
        try:
            file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

            if file_path:
                return self._analyze_ccache_file(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_ccache_file(temp_file.name, file_enriched)

        except Exception:
            logger.exception(message="Error in ccache analyzer")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return CcacheAnalyzer()

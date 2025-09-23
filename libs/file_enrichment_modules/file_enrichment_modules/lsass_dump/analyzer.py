# enrichment_modules/lsass_dump/analyzer.py
import asyncio
import tempfile
import textwrap
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

import structlog
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule
from nemesis_dpapi.core import MasterKey
from pypykatz.pypykatz import pypykatz

if TYPE_CHECKING:
    from nemesis_dpapi import DpapiManager

logger = structlog.get_logger(module=__name__)


class Credential:
    """Simple credential class to match the original structure"""

    def __init__(
        self,
        hostname=None,
        ssp=None,
        domain=None,
        username=None,
        password=None,
        lmhash=None,
        nthash=None,
        sha1=None,
        masterkey=None,
        ticket=None,
    ):
        self.hostname = hostname
        self.ssp = ssp
        self.domain = domain
        self.username = username
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash
        self.sha1 = sha1
        self.masterkey = masterkey
        self.ticket = ticket


# adapted from/inspired by https://github.com/login-securite/lsassy/blob/9682127364f6f64ce190e8b7f03cdfa1dd457066/lsassy/parser.py (MIT License)
class LsassDumpParser(EnrichmentModule):
    def __init__(self):
        super().__init__("lsass_dump")
        self.storage = StorageMinio()
        # the workflows this module should automatically run in
        self.workflows = ["default"]
        self.dpapi_manager: DpapiManager

    def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run based on file type."""
        file_enriched = get_file_enriched(object_id)
        return "mini dump crash report" in file_enriched.magic_type.lower()

    def _convert_bytes_to_string(self, value):
        """Convert bytes objects and datetime objects to strings for JSON serialization"""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        elif isinstance(value, datetime):
            return str(value)
        elif hasattr(value, "strftime"):  # Handle other datetime-like objects
            return str(value)
        elif isinstance(value, dict):
            return {k: self._convert_bytes_to_string(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._convert_bytes_to_string(item) for item in value]
        else:
            return value

    def _parse_lsass_dump(self, dump_file_path: str, target_hostname: str = "unknown") -> tuple[list, list, list, list]:
        """
        Parse LSASS dump file using pypykatz
        :param dump_file_path: Path to the dump file
        :param target_hostname: Target hostname for credential tracking
        :return: Tuple of (logon_sessions, credentials, tickets, masterkeys)
        """
        logon_sessions = []
        credentials = []
        tickets = []
        masterkeys = []

        try:
            pypy_parse = pypykatz.parse_minidump_file(dump_file_path)
        except Exception as e:
            logger.error(f"An error occurred while parsing lsass dump: {e}", exc_info=True)
            return [], [], [], []

        ssps = [
            "msv_creds",
            "wdigest_creds",
            "ssp_creds",
            "livessp_creds",
            "kerberos_creds",
            "credman_creds",
            "tspkg_creds",
            "dpapi_creds",
        ]

        for luid in pypy_parse.logon_sessions:
            session = pypy_parse.logon_sessions[luid]

            # Extract session metadata
            session_data = {
                "authentication_id": getattr(session, "authentication_id", luid),
                "session_id": getattr(session, "session_id", None),
                "username": getattr(session, "username", None),
                "domainname": getattr(session, "domainname", None),
                "logon_server": getattr(session, "logon_server", None),
                "logon_time": getattr(session, "logon_time", None),
                "sid": getattr(session, "sid", None),
                "luid": luid,
                "credentials_by_ssp": {},
            }

            # Convert logon_time to string if it exists
            if session_data["logon_time"]:
                session_data["logon_time"] = str(session_data["logon_time"])
            if session_data["sid"]:
                session_data["sid"] = str(session_data["sid"])

            # Process each SSP type for session data AND create original credentials
            for ssp in ssps:
                ssp_creds = []
                creds = getattr(session, ssp, [])

                for cred in creds:
                    cred_data = {}

                    # Common fields
                    if hasattr(cred, "username"):
                        cred_data["username"] = cred.username
                    if hasattr(cred, "domainname"):
                        cred_data["domainname"] = cred.domainname
                    if hasattr(cred, "password"):
                        cred_data["password"] = cred.password
                    if hasattr(cred, "credtype"):
                        cred_data["credtype"] = cred.credtype
                    if hasattr(cred, "luid"):
                        cred_data["luid"] = cred.luid

                    # Extract credential info for original credential objects (for ALL SSP types)
                    domain = getattr(cred, "domainname", None)
                    username = getattr(cred, "username", None)
                    password = getattr(cred, "password", None)
                    LMHash = getattr(cred, "LMHash", None)
                    NThash = getattr(cred, "NThash", None)
                    SHA1 = getattr(cred, "SHAHash", None)

                    if LMHash is not None:
                        LMHash = LMHash.hex() if hasattr(LMHash, "hex") else str(LMHash)
                    if NThash is not None:
                        NThash = NThash.hex() if hasattr(NThash, "hex") else str(NThash)
                    if SHA1 is not None:
                        SHA1 = SHA1.hex() if hasattr(SHA1, "hex") else str(SHA1)

                    # Create credential object for all SSP types that have valid credentials
                    if username and (
                        password
                        or (NThash and NThash != "00000000000000000000000000000000")
                        or (LMHash and LMHash != "00000000000000000000000000000000")
                    ):
                        credentials.append(
                            Credential(
                                hostname=target_hostname,
                                ssp=ssp,
                                domain=domain,
                                username=username,
                                password=password,
                                lmhash=LMHash,
                                nthash=NThash,
                                sha1=SHA1,
                            )
                        )

                    # MSV specific fields for session data
                    if ssp == "msv_creds":
                        if hasattr(cred, "LMHash") and cred.LMHash:
                            cred_data["LMHash"] = cred.LMHash.hex() if hasattr(cred.LMHash, "hex") else str(cred.LMHash)
                        if hasattr(cred, "NThash") and cred.NThash:
                            cred_data["NThash"] = cred.NThash.hex() if hasattr(cred.NThash, "hex") else str(cred.NThash)
                        if hasattr(cred, "SHAHash") and cred.SHAHash:
                            cred_data["SHAHash"] = (
                                cred.SHAHash.hex() if hasattr(cred.SHAHash, "hex") else str(cred.SHAHash)
                            )
                        if hasattr(cred, "DPAPI") and cred.DPAPI:
                            cred_data["DPAPI"] = cred.DPAPI.hex() if hasattr(cred.DPAPI, "hex") else str(cred.DPAPI)

                    # Kerberos specific fields
                    elif ssp == "kerberos_creds":
                        ticket_list = []
                        if hasattr(cred, "tickets"):
                            for ticket in cred.tickets:
                                tickets.append(ticket)
                                # Add ticket info to the session data
                                ticket_info = {
                                    "service_name": getattr(ticket, "ServiceName", [None])[0]
                                    if hasattr(ticket, "ServiceName") and ticket.ServiceName
                                    else None,
                                    "client_name": getattr(ticket, "EClientName", [None])[0]
                                    if hasattr(ticket, "EClientName") and ticket.EClientName
                                    else None,
                                    "domain_name": getattr(ticket, "DomainName", None),
                                    "end_time": str(getattr(ticket, "EndTime", None))
                                    if hasattr(ticket, "EndTime")
                                    else None,
                                }
                                ticket_list.append(ticket_info)
                            cred_data["tickets"] = ticket_list
                        else:
                            cred_data["tickets"] = []
                        if hasattr(cred, "aes128") and cred.aes128:
                            cred_data["aes128"] = cred.aes128.hex() if hasattr(cred.aes128, "hex") else str(cred.aes128)
                        if hasattr(cred, "aes256") and cred.aes256:
                            cred_data["aes256"] = cred.aes256.hex() if hasattr(cred.aes256, "hex") else str(cred.aes256)

                    # DPAPI specific fields
                    elif ssp == "dpapi_creds":
                        if hasattr(cred, "key_guid"):
                            cred_data["key_guid"] = str(cred.key_guid)
                            masterkey_bytes = None
                            sha1_masterkey_bytes = None
                            if hasattr(cred, "masterkey") and cred.masterkey:
                                masterkey_bytes = bytes.fromhex(cred.masterkey)
                            if hasattr(cred, "sha1_masterkey") and cred.sha1_masterkey:
                                sha1_masterkey_bytes = bytes.fromhex(cred.sha1_masterkey)

                            mk = MasterKey(
                                guid=UUID(str(cred.key_guid)),
                                plaintext_key=masterkey_bytes,
                                plaintext_key_sha1=sha1_masterkey_bytes,
                            )
                            # add this masterkey to the DPAPI cache
                            asyncio.run(self.dpapi_manager.upsert_masterkey(mk))

                        if hasattr(cred, "masterkey") and cred.masterkey:
                            cred_data["masterkey"] = (
                                cred.masterkey.hex() if hasattr(cred.masterkey, "hex") else str(cred.masterkey)
                            )
                        if hasattr(cred, "sha1_masterkey") and cred.sha1_masterkey:
                            sha1_hex = (
                                cred.sha1_masterkey.hex()
                                if hasattr(cred.sha1_masterkey, "hex")
                                else str(cred.sha1_masterkey)
                            )
                            cred_data["sha1_masterkey"] = sha1_hex

                            # Add to masterkeys list
                            m = f"{{{cred.key_guid}}}:{sha1_hex}"
                            if m not in masterkeys:
                                masterkeys.append(m)
                                credentials.append(
                                    Credential(
                                        hostname=target_hostname,
                                        ssp="dpapi",
                                        domain="",
                                        username="",
                                        masterkey=m,
                                    )
                                )

                    # WDIGEST specific fields
                    elif ssp == "wdigest_creds":
                        if hasattr(cred, "password_raw"):
                            # Convert bytes to string for JSON serialization
                            if isinstance(cred.password_raw, bytes):
                                cred_data["password_raw"] = cred.password_raw.decode("utf-8", errors="replace")
                            else:
                                cred_data["password_raw"] = (
                                    str(cred.password_raw) if cred.password_raw is not None else ""
                                )

                    if cred_data:  # Only add if we have some data
                        # Convert any bytes objects to strings for JSON serialization
                        cred_data = self._convert_bytes_to_string(cred_data)
                        ssp_creds.append(cred_data)

                if ssp_creds:  # Only add SSP if it has credentials
                    session_data["credentials_by_ssp"][ssp] = ssp_creds

            # Clean session data of any remaining bytes objects
            session_data = self._convert_bytes_to_string(session_data)
            logon_sessions.append(session_data)

        # Process orphaned credentials
        for cred in pypy_parse.orphaned_creds:
            if cred.credtype == "kerberos":
                for ticket in cred.tickets:
                    tickets.append(ticket)

        # Process tickets for TGT detection
        for ticket in tickets:
            if ticket.ServiceName is not None and ticket.ServiceName[0] == "krbtgt":
                if ticket.EClientName is not None and ticket.DomainName is not None:
                    if ticket.TargetDomainName is not None and ticket.TargetDomainName != ticket.DomainName:
                        target_domain = ticket.TargetDomainName
                    else:
                        target_domain = ticket.DomainName
                    # Keep only valid tickets
                    if ticket.EndTime > datetime.now(ticket.EndTime.tzinfo):
                        credentials.append(
                            Credential(
                                hostname=target_hostname,
                                ssp="kerberos",
                                domain=ticket.DomainName,
                                username=ticket.EClientName[0],
                                ticket={
                                    "file": list(ticket.kirbi_data)[0].split(".kirbi")[0]
                                    + "_"
                                    + ticket.EndTime.strftime("%Y%m%d%H%M%S")
                                    + ".kirbi",
                                    "domain": target_domain,
                                    "endtime": str(ticket.EndTime),  # Convert datetime to string
                                },
                            )
                        )

        return logon_sessions, credentials, tickets, masterkeys

    def _create_finding_summary(self, logon_sessions: list, credentials: list, tickets: list, masterkeys: list) -> str:
        """Creates a markdown summary for the LSASS dump findings."""
        summary = "# LSASS Dump Analysis Results\n\n"

        # Summary statistics
        summary += f"**Total Logon Sessions**: {len(logon_sessions)}\n\n"
        summary += f"**Total Credentials Found**: {len(credentials)}\n\n"
        summary += f"**Total Tickets Found**: {len(tickets)}\n\n"
        summary += f"**Total DPAPI Masterkeys**: {len(masterkeys)}\n\n\n"

        # Process each logon session
        for i, session in enumerate(logon_sessions, 1):
            summary += f"## Logon Session {i}\n\n"

            # Session metadata
            summary += f"* **Authentication ID**: `{session.get('authentication_id', 'N/A')}`\n"
            summary += f"* **Session ID**: `{session.get('session_id', 'N/A')}`\n"
            summary += f"* **Username**: `{session.get('username', 'N/A')}`\n"
            summary += f"* **Domain**: `{session.get('domainname', 'N/A')}`\n"
            summary += f"* **Logon Server**: `{session.get('logon_server', 'N/A')}`\n"
            summary += f"* **Logon Time**: `{session.get('logon_time', 'N/A')}`\n"
            summary += f"* **SID**: `{session.get('sid', 'N/A')}`\n"
            summary += f"* **LUID**: `{session.get('luid', 'N/A')}`\n\n"

            # Credentials by SSP
            creds_by_ssp = session.get("credentials_by_ssp", {})
            if creds_by_ssp:
                for ssp, creds in creds_by_ssp.items():
                    if creds:
                        summary += f"### {ssp.upper().replace('_', ' ')}\n\n"

                        for j, cred in enumerate(creds, 1):
                            summary += f"**Credential {j}:**\n"

                            for key, value in cred.items():
                                if value is not None and value != "":
                                    if key in [
                                        "NThash",
                                        "LMHash",
                                        "SHAHash",
                                        "DPAPI",
                                        "aes128",
                                        "aes256",
                                        "masterkey",
                                        "sha1_masterkey",
                                    ]:
                                        summary += f"* **{key}**: `{value}`\n"
                                    elif key == "tickets" and isinstance(value, list) and value:
                                        summary += f"* **Tickets**: {len(value)} found\n"
                                        for i, ticket in enumerate(value, 1):
                                            summary += f"  * **Ticket {i}**: Service=`{ticket.get('service_name', 'N/A')}`, Client=`{ticket.get('client_name', 'N/A')}`, Domain=`{ticket.get('domain_name', 'N/A')}`, EndTime=`{ticket.get('end_time', 'N/A')}`\n"
                                    else:
                                        summary += f"* **{key.title()}**: `{value}`\n"
                            summary += "\n"
            else:
                summary += "*No credentials found for this session.*\n\n"

            summary += "---\n\n"

        return summary

    def _analyze_lsass_dump_file(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze LSASS dump file and generate enrichment result.

        Args:
            file_path: Path to the LSASS dump file to analyze
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

        # Parse the LSASS dump
        logon_sessions, credentials, tickets, masterkeys = self._parse_lsass_dump(file_path, file_enriched.file_name)

        if not len(logon_sessions):
            logger.error("Failed to parse LSASS dump file")
            return None

        if logon_sessions or credentials or tickets or masterkeys:
            # Create finding summary
            summary_markdown = self._create_finding_summary(logon_sessions, credentials, tickets, masterkeys)

            # Prepare credentials data for serialization (convert objects to dicts)
            credentials_data = []
            for cred in credentials:
                cred_dict = {
                    "hostname": cred.hostname,
                    "ssp": cred.ssp,
                    "domain": cred.domain,
                    "username": cred.username,
                    "password": cred.password,
                    "lmhash": cred.lmhash,
                    "nthash": cred.nthash,
                    "sha1": cred.sha1,
                    "masterkey": cred.masterkey,
                    "ticket": cred.ticket,
                }
                credentials_data.append(cred_dict)

            # Create display data
            display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

            # Create finding
            finding = Finding(
                category=FindingCategory.CREDENTIAL,
                finding_name="lsass_credentials_detected",
                origin_type=FindingOrigin.ENRICHMENT_MODULE,
                origin_name=self.name,
                object_id=file_enriched.object_id,
                severity=9,  # High severity for credential extraction
                raw_data={
                    "logon_sessions": logon_sessions,
                    "credentials": credentials_data,
                    "ticket_count": len(tickets),
                    "masterkey_count": len(masterkeys),
                },
                data=[display_data],
            )

            # Add finding to enrichment result
            enrichment_result.findings = [finding]
            enrichment_result.results = {
                "logon_sessions": logon_sessions,
                "credentials": credentials_data,
                "ticket_count": len(tickets),
                "masterkey_count": len(masterkeys),
            }

            # Create a displayable version of the results
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_display_file:
                yaml_output = []
                yaml_output.append("LSASS Dump Analysis Results")
                yaml_output.append("===========================\n")

                yaml_output.append(f"Total Logon Sessions: {len(logon_sessions)}")
                yaml_output.append(f"Total Credentials: {len(credentials)}")
                yaml_output.append(f"Total Tickets: {len(tickets)}")
                yaml_output.append(f"Total Masterkeys: {len(masterkeys)}\n")

                for i, session in enumerate(logon_sessions, 1):
                    yaml_output.append(f"Logon Session {i}:")
                    yaml_output.append(f"   Authentication ID: {session.get('authentication_id', 'N/A')}")
                    yaml_output.append(f"   Username: {session.get('username', 'N/A')}")
                    yaml_output.append(f"   Domain: {session.get('domainname', 'N/A')}")
                    yaml_output.append(f"   Logon Server: {session.get('logon_server', 'N/A')}")
                    yaml_output.append(f"   Logon Time: {session.get('logon_time', 'N/A')}")
                    yaml_output.append(f"   SID: {session.get('sid', 'N/A')}")
                    yaml_output.append(f"   LUID: {session.get('luid', 'N/A')}")

                    creds_by_ssp = session.get("credentials_by_ssp", {})
                    if creds_by_ssp:
                        for ssp, creds in creds_by_ssp.items():
                            yaml_output.append(f"   {ssp.upper()}:")
                            for j, cred in enumerate(creds, 1):
                                yaml_output.append(f"      Credential {j}:")
                                for key, value in cred.items():
                                    if value is not None and value != "":
                                        if key == "tickets" and isinstance(value, list) and value:
                                            yaml_output.append(f"         {key}: {len(value)} tickets found")
                                            for k, ticket in enumerate(value, 1):
                                                yaml_output.append(
                                                    f"            Ticket {k}: Service={ticket.get('service_name', 'N/A')}, Client={ticket.get('client_name', 'N/A')}, Domain={ticket.get('domain_name', 'N/A')}, EndTime={ticket.get('end_time', 'N/A')}"
                                                )
                                        else:
                                            yaml_output.append(f"         {key}: {value}")
                    yaml_output.append("")  # Add empty line between sessions

                display = textwrap.indent("\n".join(yaml_output), "   ")
                tmp_display_file.write(display)
                tmp_display_file.flush()

                object_id = self.storage.upload_file(tmp_display_file.name)

                displayable_parsed = Transform(
                    type="displayable_parsed",
                    object_id=f"{object_id}",
                    metadata={
                        "file_name": f"{file_enriched.file_name}_lsass_analysis.txt",
                        "display_type_in_dashboard": "monaco",
                        "default_display": True,
                    },
                )
                enrichment_result.transforms = [displayable_parsed]

        return enrichment_result

    def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process LSASS dump file and extract credentials.

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
                return self._analyze_lsass_dump_file(file_path, file_enriched)
            else:
                # Download the file to a temporary location
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_lsass_dump_file(temp_file.name, file_enriched)

        except Exception as e:
            logger.exception(e, message="Error processing LSASS dump file")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return LsassDumpParser()

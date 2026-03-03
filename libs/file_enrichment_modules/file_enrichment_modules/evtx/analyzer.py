"""Windows Event Log (.evtx) enrichment module.

Parses EVTX files and extracts:
- Statistical summary (event counts, timeline, unique accounts/IPs/computers)
- Discrete findings for high-signal security events (new services, admin changes, scheduled tasks, etc.)
- CSV transform for scheduled task changes (downloadable)
- Child files: PowerShell 4104 script blocks resubmitted into the pipeline for further enrichment
"""

import csv
import hashlib
import json
import os
import re
import tempfile
from collections import defaultdict
from datetime import datetime, timedelta

import evtx as evtx_lib
from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)

# High-value event IDs to collect, organized by source log
SECURITY_EVENT_IDS = {
    "4624",  # Successful logon
    "4625",  # Failed logon
    "4648",  # Explicit credential logon (runas/pass-the-hash)
    "4672",  # Special privileges assigned at logon
    "4688",  # Process creation
    "4698",  # Scheduled task created
    "4699",  # Scheduled task deleted
    "4702",  # Scheduled task updated
    "4720",  # User account created
    "4722",  # User account enabled
    "4724",  # Password reset attempt
    "4726",  # User account deleted
    "4728",  # Member added to global security group
    "4729",  # Member removed from global security group
    "4732",  # Member added to local security group
    "4733",  # Member removed from local security group
    "4768",  # Kerberos TGT request
    "4769",  # Kerberos service ticket request
    "4776",  # NTLM credential validation
    "1102",  # Audit log cleared
}

SYSTEM_EVENT_IDS = {
    "7045",  # New service installed
    "7040",  # Service start type changed
    "7036",  # Service state changed
    "12",  # Kernel boot (Microsoft-Windows-Kernel-General)
    "13",  # Kernel shutdown
    "1",  # Awake from sleep (Microsoft-Windows-Power-Troubleshooter)
    "42",  # Sleep
    "6008",  # Unexpected/unclean shutdown
}

POWERSHELL_EVENT_IDS = {
    "4103",  # Module logging
    "4104",  # Script block logging (gold — captures deobfuscated PS)
}

TASKSCHEDULER_EVENT_IDS = {
    "106",  # Task registered/created
    "141",  # Task deleted
    "140",  # Task updated
}

# Logon types that indicate interactive/network/remote access
INTERESTING_LOGON_TYPES = {
    2,
    3,
    10,
    4,
    8,
    9,
}  # Interactive, Network, RemoteInteractive, Batch, NetworkCleartext, NewCredentials

# Local admin / privileged group SIDs
ADMIN_GROUP_SIDS = {
    "S-1-5-32-544",  # BUILTIN\Administrators
    "S-1-5-32-551",  # Backup Operators
    "S-1-5-32-548",  # Account Operators
}

# Max script blocks to emit as child files (avoid runaway on huge PS logs)
MAX_SCRIPT_BLOCK_FILES = 100
# Min size of a script block to bother extracting (skip tiny one-liners from system PS)
MIN_SCRIPT_BLOCK_SIZE = 100
# Cap on events stored per event ID in the summary (avoids huge result JSON)
MAX_EVENTS_PER_ID = 50
# Number of days back from the most recent event to include in the power timeline
POWER_TIMELINE_DAYS = 15

# Noise user/SID filter for scheduled task user contexts and service accounts
_NOISE_USER_CONTEXT_RE = re.compile(
    r"^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|UMFD-\d+|DWM-\d+|ANONYMOUS LOGON)$",
    re.IGNORECASE,
)
_NOISE_SIDS = {"S-1-5-18"}  # SYSTEM
_NOISE_USER_STRINGS = {"NT AUTHORITY\\SYSTEM", "NT AUTHORITY/SYSTEM"}

# Power event ID → human-readable label
POWER_EVENT_LABELS = {
    "12": "Startup",
    "13": "Shutdown",
    "1": "Awake",
    "42": "Sleep",
    "6008": "Unclean Shutdown",
}


def _normalize_event_id(eid_raw) -> str:
    """EventID is sometimes a plain int/str, sometimes {'#text': N, '#attributes': {...}}."""
    if isinstance(eid_raw, dict):
        return str(eid_raw.get("#text", ""))
    return str(eid_raw)


def _get_system_time(sys_block: dict) -> str | None:
    """Extract SystemTime from TimeCreated block."""
    tc = sys_block.get("TimeCreated", {})
    if isinstance(tc, dict):
        return tc.get("#attributes", {}).get("SystemTime")
    return None


def _safe_str(val) -> str:
    if val is None:
        return ""
    return str(val).strip()


def _is_noise_user(user: str, sid: str = "") -> bool:
    """Return True if the user/SID should be filtered out as noise (system accounts)."""
    if sid and sid in _NOISE_SIDS:
        return True
    if not user:
        return True
    if user in _NOISE_USER_STRINGS:
        return True
    # Strip domain prefix for regex match (e.g. "NT AUTHORITY\SYSTEM" → already handled above)
    bare = user.split("\\")[-1].split("/")[-1]
    return bool(_NOISE_USER_CONTEXT_RE.match(bare))


class EVTXAnalyzer(EnrichmentModule):
    name: str = "evtx_analyzer"
    dependencies: list[str] = []

    def __init__(self):
        self.storage = StorageMinio()
        self.asyncpg_pool = None
        self.workflows = ["default"]

        # EVTX magic bytes: "ElfFile\x00"
        self._magic = b"ElfFile\x00"

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

        # Extension check (fast path)
        if file_enriched.extension and file_enriched.extension.lower() == ".evtx":
            return True

        # Magic check (handles renamed files)
        if "MS Windows Vista Event Log" in (file_enriched.magic_type or ""):
            return True

        # Read header bytes for magic confirmation
        try:
            if file_path:
                with open(file_path, "rb") as f:
                    header = f.read(8)
            else:
                header = self.storage.download_bytes(object_id, length=8)
            return header[:8] == self._magic
        except Exception:
            return False

    def _parse_evtx(self, file_path: str) -> dict:
        """Stream-parse the EVTX file and collect high-value events."""
        parser = evtx_lib.PyEvtxParser(file_path)

        # Structures we'll build up
        event_counts: dict[str, int] = defaultdict(int)
        timestamps: list[str] = []
        unique_accounts: set[str] = set()
        unique_computers: set[str] = set()
        unique_ips: set[str] = set()

        # Per-category collected events
        logon_events: list[dict] = []
        explicit_logon_events: list[dict] = []
        process_creation_events: list[dict] = []
        account_change_events: list[dict] = []
        group_change_events: list[dict] = []
        service_install_events: list[dict] = []
        task_events: list[dict] = []
        log_cleared_events: list[dict] = []
        ntlm_events: list[dict] = []
        kerberos_tgt_events: list[dict] = []
        kerberos_st_events: list[dict] = []
        power_events: list[dict] = []

        # Script block reassembly: script_block_id -> list of (msg_num, text)
        script_blocks: dict[str, dict] = {}  # id -> {total, chunks: {num: text}, path: str, time: str}

        for record in parser.records_json():
            try:
                data = json.loads(record["data"])
                event = data.get("Event", {})
                sys = event.get("System", {})
                edata = event.get("EventData", {}) or {}

                eid = _normalize_event_id(sys.get("EventID", ""))
                timestamp = _get_system_time(sys)
                computer = _safe_str(sys.get("Computer", ""))

                event_counts[eid] += 1
                if timestamp:
                    timestamps.append(timestamp)
                if computer:
                    unique_computers.add(computer)

                # Collect subject/target usernames and IPs where present
                for field in ("SubjectUserName", "TargetUserName"):
                    val = _safe_str(edata.get(field, ""))
                    if val and val not in ("-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
                        if not val.endswith("$"):  # Skip machine accounts
                            unique_accounts.add(val)

                for field in ("IpAddress", "Workstation", "WorkstationName"):
                    val = _safe_str(edata.get(field, ""))
                    if val and val not in ("-", "::1", "127.0.0.1"):
                        unique_ips.add(val)

                # --- Per-event-ID processing ---

                if eid == "4624":  # Successful logon
                    logon_type = edata.get("LogonType")
                    try:
                        lt = int(logon_type) if logon_type is not None else 0
                    except (ValueError, TypeError):
                        lt = 0
                    if lt in INTERESTING_LOGON_TYPES and len(logon_events) < MAX_EVENTS_PER_ID:
                        logon_events.append(
                            {
                                "time": timestamp,
                                "target_user": _safe_str(edata.get("TargetUserName")),
                                "target_domain": _safe_str(edata.get("TargetDomainName")),
                                "logon_type": lt,
                                "auth_package": _safe_str(edata.get("AuthenticationPackageName")),
                                "ip_address": _safe_str(edata.get("IpAddress")),
                                "workstation": _safe_str(edata.get("WorkstationName")),
                                "process": _safe_str(edata.get("ProcessName")),
                            }
                        )

                elif eid == "4625":  # Failed logon
                    if len(logon_events) < MAX_EVENTS_PER_ID:
                        logon_events.append(
                            {
                                "time": timestamp,
                                "type": "FAILED",
                                "target_user": _safe_str(edata.get("TargetUserName")),
                                "target_domain": _safe_str(edata.get("TargetDomainName")),
                                "logon_type": edata.get("LogonType"),
                                "failure_reason": _safe_str(edata.get("FailureReason")),
                                "ip_address": _safe_str(edata.get("IpAddress")),
                                "workstation": _safe_str(edata.get("WorkstationName")),
                            }
                        )

                elif eid == "4648":  # Explicit credential use
                    if len(explicit_logon_events) < MAX_EVENTS_PER_ID:
                        explicit_logon_events.append(
                            {
                                "time": timestamp,
                                "subject_user": _safe_str(edata.get("SubjectUserName")),
                                "subject_domain": _safe_str(edata.get("SubjectDomainName")),
                                "target_user": _safe_str(edata.get("TargetUserName")),
                                "target_domain": _safe_str(edata.get("TargetDomainName")),
                                "target_server": _safe_str(edata.get("TargetServerName")),
                                "process": _safe_str(edata.get("ProcessName")),
                                "ip_address": _safe_str(edata.get("IpAddress")),
                            }
                        )

                elif eid == "4688":  # Process creation — no cap, full dataset goes to CSV
                    cmdline = _safe_str(edata.get("CommandLine", ""))
                    proc = _safe_str(edata.get("NewProcessName", ""))
                    if cmdline or proc:
                        process_creation_events.append(
                            {
                                "time": timestamp,
                                "process": proc,
                                "command_line": cmdline,
                                "parent_process": _safe_str(edata.get("ParentProcessName")),
                                "user": _safe_str(edata.get("SubjectUserName")),
                                "domain": _safe_str(edata.get("SubjectDomainName")),
                            }
                        )

                elif eid in ("4720", "4722", "4726", "4738", "4724"):  # Account changes
                    account_change_events.append(
                        {
                            "time": timestamp,
                            "event_id": eid,
                            "target_user": _safe_str(edata.get("TargetUserName")),
                            "target_domain": _safe_str(edata.get("TargetDomainName")),
                            "subject_user": _safe_str(edata.get("SubjectUserName")),
                            "subject_domain": _safe_str(edata.get("SubjectDomainName")),
                        }
                    )

                elif eid in ("4728", "4729", "4732", "4733"):  # Group membership changes
                    target_sid = _safe_str(edata.get("TargetSid", ""))
                    group_change_events.append(
                        {
                            "time": timestamp,
                            "event_id": eid,
                            "member_sid": _safe_str(edata.get("MemberSid")),
                            "group_name": _safe_str(edata.get("TargetUserName")),
                            "group_domain": _safe_str(edata.get("TargetDomainName")),
                            "group_sid": target_sid,
                            "subject_user": _safe_str(edata.get("SubjectUserName")),
                            "is_admin_group": target_sid in ADMIN_GROUP_SIDS,
                        }
                    )

                elif eid == "4776":  # NTLM credential validation
                    if len(ntlm_events) < MAX_EVENTS_PER_ID:
                        ntlm_events.append(
                            {
                                "time": timestamp,
                                "target_user": _safe_str(edata.get("TargetUserName")),
                                "workstation": _safe_str(edata.get("Workstation")),
                                "error_code": _safe_str(edata.get("Status")),
                            }
                        )

                elif eid == "4768":  # Kerberos TGT request
                    if len(kerberos_tgt_events) < MAX_EVENTS_PER_ID:
                        kerberos_tgt_events.append(
                            {
                                "time": timestamp,
                                "client_name": _safe_str(edata.get("TargetUserName")),
                                "client_domain": _safe_str(edata.get("TargetDomainName")),
                                "service_name": _safe_str(edata.get("ServiceName")),
                                "ip_address": _safe_str(edata.get("IpAddress")),
                                "ticket_options": _safe_str(edata.get("TicketOptions")),
                                "result_code": _safe_str(edata.get("Status")),
                            }
                        )

                elif eid == "4769":  # Kerberos service ticket request
                    if len(kerberos_st_events) < MAX_EVENTS_PER_ID:
                        kerberos_st_events.append(
                            {
                                "time": timestamp,
                                "client_name": _safe_str(edata.get("TargetUserName")),
                                "client_domain": _safe_str(edata.get("TargetDomainName")),
                                "service_name": _safe_str(edata.get("ServiceName")),
                                "ip_address": _safe_str(edata.get("IpAddress")),
                                "ticket_options": _safe_str(edata.get("TicketOptions")),
                                "result_code": _safe_str(edata.get("FailureCode")),
                            }
                        )

                elif eid == "1102":  # Audit log cleared
                    log_cleared_events.append(
                        {
                            "time": timestamp,
                            "subject_user": _safe_str(edata.get("SubjectUserName")),
                            "subject_domain": _safe_str(edata.get("SubjectDomainName")),
                        }
                    )

                elif eid in ("1", "12", "13", "42", "6008"):  # Power/boot/shutdown events
                    power_events.append(
                        {
                            "time": timestamp,
                            "event_id": eid,
                            "description": POWER_EVENT_LABELS.get(eid, eid),
                        }
                    )

                elif eid == "7045":  # New service installed
                    service_install_events.append(
                        {
                            "time": timestamp,
                            "service_name": _safe_str(edata.get("ServiceName")),
                            "image_path": _safe_str(edata.get("ImagePath")),
                            "service_type": _safe_str(edata.get("ServiceType")),
                            "start_type": _safe_str(edata.get("StartType")),
                            "account": _safe_str(edata.get("AccountName")),
                        }
                    )

                elif eid in ("106", "141", "140"):  # Task registered/deleted/updated
                    # edata may be nested under #attributes
                    task_name = _safe_str(edata.get("TaskName", ""))
                    user_ctx = _safe_str(edata.get("UserContext", ""))
                    task_events.append(
                        {
                            "time": timestamp,
                            "event_id": eid,
                            "task_name": task_name,
                            "user_context": user_ctx,
                        }
                    )

                elif eid == "4104":  # PowerShell script block
                    script_id = _safe_str(edata.get("ScriptBlockId", ""))
                    msg_num = edata.get("MessageNumber", 1)
                    msg_total = edata.get("MessageTotal", 1)
                    text = edata.get("ScriptBlockText", "")
                    ps_path = _safe_str(edata.get("Path", ""))

                    if script_id and text:
                        if script_id not in script_blocks:
                            script_blocks[script_id] = {
                                "total": msg_total,
                                "path": ps_path,
                                "time": timestamp,
                                "chunks": {},
                            }
                        script_blocks[script_id]["chunks"][msg_num] = text
                        # Update path if we get a non-empty one
                        if ps_path and not script_blocks[script_id]["path"]:
                            script_blocks[script_id]["path"] = ps_path

            except Exception:
                logger.exception(message="Error parsing EVTX record")
                continue

        return {
            "event_counts": dict(event_counts),
            "timestamps": sorted(timestamps),
            "unique_accounts": list(unique_accounts),
            "unique_computers": list(unique_computers),
            "unique_ips": list(unique_ips),
            "logon_events": logon_events,
            "explicit_logon_events": explicit_logon_events,
            "process_creation_events": process_creation_events,
            "account_change_events": account_change_events,
            "group_change_events": group_change_events,
            "service_install_events": service_install_events,
            "task_events": task_events,
            "log_cleared_events": log_cleared_events,
            "ntlm_events": ntlm_events,
            "kerberos_tgt_events": kerberos_tgt_events,
            "kerberos_st_events": kerberos_st_events,
            "power_events": power_events,
            "script_blocks": script_blocks,
        }

    def _reassemble_script_blocks(self, script_blocks: dict) -> list[dict]:
        """Reassemble multi-chunk 4104 script blocks into complete scripts, deduped by content hash."""
        complete = []
        seen_hashes: set[str] = set()
        for script_id, info in script_blocks.items():
            chunks = info["chunks"]
            total = info["total"]
            # Only emit blocks that have all chunks present
            if len(chunks) < total:
                continue
            full_text = "".join(chunks[i] for i in sorted(chunks.keys()))
            if len(full_text) < MIN_SCRIPT_BLOCK_SIZE:
                continue
            text_hash = hashlib.sha256(full_text.encode()).hexdigest()
            if text_hash in seen_hashes:
                continue
            seen_hashes.add(text_hash)
            complete.append(
                {
                    "id": script_id,
                    "path": info["path"],
                    "time": info["time"],
                    "text": full_text,
                }
            )
        return complete

    def _build_summary_markdown(self, file_name: str, parsed: dict, script_blocks_extracted: int = 0) -> str:
        """Build a human-readable markdown summary of the EVTX analysis."""
        timestamps = parsed["timestamps"]
        first_ts = timestamps[0] if timestamps else "unknown"
        last_ts = timestamps[-1] if timestamps else "unknown"

        event_counts = parsed["event_counts"]
        total_events = sum(event_counts.values())

        lines = [
            f"# EVTX Analysis: {file_name}",
            "",
            "## Summary",
            f"- **Total events:** {total_events:,}",
            f"- **Time range:** {first_ts} → {last_ts}",
            f"- **Unique computers:** {', '.join(sorted(parsed['unique_computers'])) or 'none'}",
            f"- **Unique accounts:** {', '.join(sorted(parsed['unique_accounts'])[:20]) or 'none'}",
            f"- **Unique IPs/workstations:** {', '.join(sorted(parsed['unique_ips'])[:20]) or 'none'}",
        ]
        if script_blocks_extracted:
            lines.append(f"- **Unique PowerShell scripts carved:** {script_blocks_extracted}")

        def fmt_time(ts):
            if not ts:
                return ""
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S UTC")
            except Exception:
                return ts

        if parsed["service_install_events"]:
            lines += [
                "",
                "## New Services Installed (7045)",
                "| Time | Name | Image Path | Account |",
                "|------|------|------------|---------|",
            ]
            for e in parsed["service_install_events"]:
                account = e["account"]
                display_account = "" if _is_noise_user(account) else account
                lines.append(f"| {fmt_time(e['time'])} | {e['service_name']} | {e['image_path']} | {display_account} |")

        if parsed["account_change_events"]:
            lines += [
                "",
                "## Account Changes",
                f"- {len(parsed['account_change_events'])} account change event(s) detected",
                "- Full details available as downloadable CSV transform",
            ]

        if parsed["group_change_events"]:
            admin_count = sum(1 for e in parsed["group_change_events"] if e["is_admin_group"])
            lines += [
                "",
                "## Group Membership Changes",
                f"- {len(parsed['group_change_events'])} group membership change(s) detected ({admin_count} to privileged groups)",
                "- Full details available as downloadable CSV transform",
            ]

        if parsed["task_events"]:
            task_registered = sum(1 for e in parsed["task_events"] if e["event_id"] == "106")
            task_deleted = sum(1 for e in parsed["task_events"] if e["event_id"] == "141")
            task_updated = sum(1 for e in parsed["task_events"] if e["event_id"] == "140")
            # Collect filtered unique user contexts
            seen_users: set[str] = set()
            for e in parsed["task_events"]:
                uc = e.get("user_context", "")
                if uc and not _is_noise_user(uc):
                    seen_users.add(uc)
            user_list = ", ".join(sorted(seen_users)) if seen_users else "none"
            lines += [
                "",
                "## Scheduled Task Changes",
                f"- {task_registered} registered, {task_deleted} deleted, {task_updated} updated",
                f"- Unique user contexts (filtered): {user_list}",
                "- Full task list available as downloadable CSV transform",
            ]

        if parsed["explicit_logon_events"]:
            lines += [
                "",
                "## Explicit Credential Use (4648)",
                f"- {len(parsed['explicit_logon_events'])} explicit credential use event(s) detected",
                "- Full details available as downloadable CSV transform",
            ]

        if parsed["ntlm_events"]:
            lines += [
                "",
                "## NTLM Authentications (4776)",
                "| Time | User | Workstation | Error |",
                "|------|------|-------------|-------|",
            ]
            for e in parsed["ntlm_events"][:30]:
                lines.append(f"| {fmt_time(e['time'])} | {e['target_user']} | {e['workstation']} | {e['error_code']} |")

        if parsed["process_creation_events"]:
            lines += [
                "",
                "## Process Creation (4688)",
                f"- {len(parsed['process_creation_events'])} process creation event(s) recorded",
                "- Full details available as downloadable CSV transform",
            ]

        # --- System: Power/Boot/Shutdown Timeline ---
        if parsed.get("power_events"):
            # Only show events within the last POWER_TIMELINE_DAYS days of the log
            ref_ts = timestamps[-1] if timestamps else None
            if ref_ts:
                try:
                    ref_dt = datetime.fromisoformat(ref_ts.replace("Z", "+00:00"))
                    cutoff_dt = ref_dt - timedelta(days=POWER_TIMELINE_DAYS)
                    recent_power = []
                    for e in parsed["power_events"]:
                        try:
                            e_dt = datetime.fromisoformat(e["time"].replace("Z", "+00:00"))
                            if e_dt >= cutoff_dt:
                                recent_power.append(e)
                        except Exception:
                            pass
                except Exception:
                    recent_power = parsed["power_events"]
            else:
                recent_power = parsed["power_events"]

            if recent_power:
                lines += [
                    "",
                    "## System Power Timeline",
                    "| Time | Event |",
                    "|------|-------|",
                ]
                for e in sorted(recent_power, key=lambda x: x["time"] or ""):
                    lines.append(f"| {fmt_time(e['time'])} | {e['description']} ({e['event_id']}) |")

        # --- Security: Authentication Summary ---
        inbound_logons = [
            e
            for e in parsed.get("logon_events", [])
            if e.get("ip_address") and e["ip_address"] not in ("-", "::1", "127.0.0.1", "")
        ]
        outbound_4648 = parsed.get("explicit_logon_events", [])
        outbound_ntlm = [e for e in parsed.get("ntlm_events", []) if e.get("workstation")]
        outbound_tgt = parsed.get("kerberos_tgt_events", [])
        outbound_st = parsed.get("kerberos_st_events", [])

        has_auth_data = inbound_logons or outbound_4648 or outbound_ntlm or outbound_tgt or outbound_st
        if has_auth_data:
            lines += ["", "## Authentication Summary"]

            if inbound_logons:
                # Group by (user, domain, ip, auth_package)
                inbound_counts: dict[tuple, int] = defaultdict(int)
                for e in inbound_logons:
                    key = (
                        e.get("target_user", ""),
                        e.get("target_domain", ""),
                        e.get("ip_address") or e.get("workstation", ""),
                        e.get("auth_package", ""),
                    )
                    inbound_counts[key] += 1

                lines += [
                    "",
                    "### Inbound Authentication",
                    "| User | Domain | Source IP/Host | Auth Package | Count |",
                    "|------|--------|----------------|--------------|-------|",
                ]
                for (user, domain, src, pkg), cnt in sorted(inbound_counts.items(), key=lambda x: -x[1])[:20]:
                    lines.append(f"| {user} | {domain} | {src} | {pkg} | {cnt} |")

            _local_targets = {"localhost", "127.0.0.1", "::1", "-", ""}

            def _is_local_target(target: str) -> bool:
                return target.lower() in _local_targets

            outbound_rows: list[tuple[str, str, str, str]] = []
            for e in outbound_tgt[:20]:
                target = e.get("service_name", "")
                if _is_local_target(target):
                    continue
                outbound_rows.append(
                    (
                        "Kerberos TGT",
                        e.get("client_name", ""),
                        target,
                        f"domain={e.get('client_domain', '')} ip={e.get('ip_address', '')} code={e.get('result_code', '')}",
                    )
                )
            for e in outbound_st[:20]:
                target = e.get("service_name", "")
                if _is_local_target(target):
                    continue
                outbound_rows.append(
                    (
                        "Kerberos ST",
                        e.get("client_name", ""),
                        target,
                        f"domain={e.get('client_domain', '')} ip={e.get('ip_address', '')} code={e.get('result_code', '')}",
                    )
                )
            for e in outbound_ntlm[:20]:
                target = e.get("workstation", "")
                if _is_local_target(target):
                    continue
                status = e.get("error_code", "")
                result_label = "success" if status in ("0x0", "", "0") else f"failed ({status})"
                outbound_rows.append(("NTLM", e.get("target_user", ""), target, result_label))
            for e in outbound_4648[:20]:
                target = e.get("target_server", "") or e.get("ip_address", "")
                if _is_local_target(target):
                    continue
                outbound_rows.append(
                    (
                        "Explicit Creds",
                        e.get("subject_user", ""),
                        target,
                        f"via {e.get('process', '')}",
                    )
                )

            if outbound_rows:
                lines += [
                    "",
                    "### Outbound Authentication",
                    "| Type | User | Target | Details |",
                    "|------|------|--------|---------|",
                ]
                for row in outbound_rows[:20]:
                    lines.append(f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} |")

        return "\n".join(lines)

    async def _analyze_file(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

        try:
            parsed = self._parse_evtx(file_path)
        except Exception:
            logger.exception(message="Failed to parse EVTX file", file_name=file_enriched.file_name)
            return None

        # --- Build results summary (stored in DB) ---
        script_block_data = self._reassemble_script_blocks(parsed["script_blocks"])

        result.results = {
            "file_name": file_enriched.file_name,
            "total_events": sum(parsed["event_counts"].values()),
            "event_counts": parsed["event_counts"],
            "time_range": {
                "first": parsed["timestamps"][0] if parsed["timestamps"] else None,
                "last": parsed["timestamps"][-1] if parsed["timestamps"] else None,
            },
            "unique_accounts": parsed["unique_accounts"],
            "unique_computers": parsed["unique_computers"],
            "unique_ips": list(parsed["unique_ips"]),
            "service_installs_count": len(parsed["service_install_events"]),
            "account_changes_count": len(parsed["account_change_events"]),
            "group_changes_count": len(parsed["group_change_events"]),
            "explicit_logons_count": len(parsed["explicit_logon_events"]),
            "log_cleared": len(parsed["log_cleared_events"]) > 0,
            "script_blocks_extracted": len(script_block_data),
        }

        # --- Markdown summary transform ---
        md = self._build_summary_markdown(file_enriched.file_name, parsed, len(script_block_data))
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".md", delete=False) as tmp:
            tmp.write(md)
            tmp.flush()
            summary_id = self.storage.upload_file(tmp.name)

        result.transforms.append(
            Transform(
                type="evtx_analysis",
                object_id=str(summary_id),
                metadata={
                    "file_name": f"{file_enriched.file_name}_analysis.md",
                    "display_type_in_dashboard": "markdown",
                    "default_display": True,
                    "offer_as_download": False,
                },
            )
        )

        # --- Findings ---

        # Audit log cleared — always high severity
        if parsed["log_cleared_events"]:
            e = parsed["log_cleared_events"][0]
            summary = f"Security audit log was cleared by {e['subject_user']}@{e['subject_domain']} at {e['time']}"
            result.findings.append(
                Finding(
                    category=FindingCategory.EXTRACTED_DATA,
                    finding_name="evtx_audit_log_cleared",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=file_enriched.object_id,
                    severity=8,
                    raw_data={"events": parsed["log_cleared_events"]},
                    data=[FileObject(type="finding_summary", metadata={"summary": summary})],
                )
            )

        # New service installed
        if parsed["service_install_events"]:
            summary_lines = ["**New services installed (Event 7045):**\n"]
            for e in parsed["service_install_events"]:
                summary_lines.append(f"- `{e['service_name']}` — `{e['image_path']}` (account: {e['account']})")
            result.findings.append(
                Finding(
                    category=FindingCategory.EXTRACTED_DATA,
                    finding_name="evtx_new_service_installed",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=file_enriched.object_id,
                    severity=5,
                    raw_data={"events": parsed["service_install_events"]},
                    data=[FileObject(type="finding_summary", metadata={"summary": "\n".join(summary_lines)})],
                )
            )

        # Group membership changes — CSV transform + findings split by admin/non-admin
        if parsed["group_change_events"]:
            eid_desc = {
                "4728": "Added to Global Group",
                "4729": "Removed from Global Group",
                "4732": "Added to Local Group",
                "4733": "Removed from Local Group",
            }
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", newline="", suffix=".csv", delete=False
            ) as tmp_csv:
                writer = csv.writer(tmp_csv)
                writer.writerow(
                    [
                        "time",
                        "action",
                        "group_name",
                        "group_domain",
                        "group_sid",
                        "member_sid",
                        "subject_user",
                        "is_admin_group",
                    ]
                )
                for e in parsed["group_change_events"]:
                    writer.writerow(
                        [
                            e["time"],
                            eid_desc.get(e["event_id"], e["event_id"]),
                            e["group_name"],
                            e["group_domain"],
                            e["group_sid"],
                            e["member_sid"],
                            e["subject_user"],
                            e["is_admin_group"],
                        ]
                    )
                tmp_csv.flush()
                group_csv_id = self.storage.upload_file(tmp_csv.name)

            result.transforms.append(
                Transform(
                    type="evtx_group_changes",
                    object_id=str(group_csv_id),
                    metadata={
                        "file_name": f"{file_enriched.file_name}_group_changes.csv",
                        "display_type_in_dashboard": "csv",
                        "display_title": "Group Changes",
                    },
                )
            )

            admin_changes = [e for e in parsed["group_change_events"] if e["is_admin_group"]]
            if admin_changes:
                summary_lines = ["**Admin group membership changes:**\n"]
                for e in admin_changes:
                    action = eid_desc.get(e["event_id"], e["event_id"])
                    summary_lines.append(
                        f"- {action}: SID `{e['member_sid']}` in `{e['group_name']}` by {e['subject_user']}"
                    )
                result.findings.append(
                    Finding(
                        category=FindingCategory.EXTRACTED_DATA,
                        finding_name="evtx_admin_group_change",
                        origin_type=FindingOrigin.ENRICHMENT_MODULE,
                        origin_name=self.name,
                        object_id=file_enriched.object_id,
                        severity=7,
                        raw_data={"count": len(admin_changes)},
                        data=[FileObject(type="finding_summary", metadata={"summary": "\n".join(summary_lines)})],
                    )
                )

            non_admin_changes = [e for e in parsed["group_change_events"] if not e["is_admin_group"]]
            if non_admin_changes:
                result.findings.append(
                    Finding(
                        category=FindingCategory.EXTRACTED_DATA,
                        finding_name="evtx_group_membership_change",
                        origin_type=FindingOrigin.ENRICHMENT_MODULE,
                        origin_name=self.name,
                        object_id=file_enriched.object_id,
                        severity=3,
                        raw_data={"count": len(non_admin_changes)},
                        data=[
                            FileObject(
                                type="finding_summary",
                                metadata={
                                    "summary": f"{len(non_admin_changes)} non-admin group membership change(s) detected"
                                },
                            )
                        ],
                    )
                )

        # Account changes — CSV transform + finding
        if parsed["account_change_events"]:
            eid_desc = {
                "4720": "Created",
                "4722": "Enabled",
                "4726": "Deleted",
                "4738": "Modified",
                "4724": "Password Reset",
            }
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", newline="", suffix=".csv", delete=False
            ) as tmp_csv:
                writer = csv.writer(tmp_csv)
                writer.writerow(["time", "action", "target_user", "target_domain", "subject_user", "subject_domain"])
                for e in parsed["account_change_events"]:
                    writer.writerow(
                        [
                            e["time"],
                            eid_desc.get(e["event_id"], e["event_id"]),
                            e["target_user"],
                            e["target_domain"],
                            e["subject_user"],
                            e["subject_domain"],
                        ]
                    )
                tmp_csv.flush()
                acct_csv_id = self.storage.upload_file(tmp_csv.name)

            result.transforms.append(
                Transform(
                    type="evtx_account_changes",
                    object_id=str(acct_csv_id),
                    metadata={
                        "file_name": f"{file_enriched.file_name}_account_changes.csv",
                        "display_type_in_dashboard": "csv",
                        "display_title": "Account Changes",
                    },
                )
            )
            result.findings.append(
                Finding(
                    category=FindingCategory.EXTRACTED_DATA,
                    finding_name="evtx_account_change",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=file_enriched.object_id,
                    severity=5,
                    raw_data={"count": len(parsed["account_change_events"])},
                    data=[
                        FileObject(
                            type="finding_summary",
                            metadata={
                                "summary": f"{len(parsed['account_change_events'])} account change event(s) detected"
                            },
                        )
                    ],
                )
            )

        # Scheduled task changes — finding + downloadable CSV (not inline markdown)
        if parsed["task_events"]:
            task_registered = [e for e in parsed["task_events"] if e["event_id"] == "106"]
            task_deleted = [e for e in parsed["task_events"] if e["event_id"] == "141"]
            task_updated = [e for e in parsed["task_events"] if e["event_id"] == "140"]
            summary = (
                f"{len(task_registered)} task(s) registered, {len(task_deleted)} deleted, {len(task_updated)} updated"
            )

            eid_desc = {"106": "Registered", "141": "Deleted", "140": "Updated"}
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", newline="", suffix=".csv", delete=False
            ) as tmp_csv:
                writer = csv.writer(tmp_csv)
                writer.writerow(["time", "action", "task_name", "user_context"])
                for e in parsed["task_events"]:
                    writer.writerow(
                        [e["time"], eid_desc.get(e["event_id"], e["event_id"]), e["task_name"], e["user_context"]]
                    )
                tmp_csv.flush()
                task_csv_id = self.storage.upload_file(tmp_csv.name)

            result.transforms.append(
                Transform(
                    type="evtx_task_changes",
                    object_id=str(task_csv_id),
                    metadata={
                        "file_name": f"{file_enriched.file_name}_task_changes.csv",
                        "display_type_in_dashboard": "csv",
                        "display_title": "Task Changes",
                    },
                )
            )
            result.findings.append(
                Finding(
                    category=FindingCategory.EXTRACTED_DATA,
                    finding_name="evtx_scheduled_task_change",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=file_enriched.object_id,
                    severity=4,
                    raw_data={
                        "total": len(parsed["task_events"]),
                        "registered": len(task_registered),
                        "deleted": len(task_deleted),
                        "updated": len(task_updated),
                    },
                    data=[FileObject(type="finding_summary", metadata={"summary": summary})],
                )
            )

        # Explicit credential use (4648) — CSV transform + finding
        if parsed["explicit_logon_events"]:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", newline="", suffix=".csv", delete=False
            ) as tmp_csv:
                writer = csv.writer(tmp_csv)
                writer.writerow(
                    [
                        "time",
                        "subject_user",
                        "subject_domain",
                        "target_user",
                        "target_domain",
                        "target_server",
                        "process",
                        "ip_address",
                    ]
                )
                for e in parsed["explicit_logon_events"]:
                    writer.writerow(
                        [
                            e["time"],
                            e["subject_user"],
                            e["subject_domain"],
                            e["target_user"],
                            e["target_domain"],
                            e["target_server"],
                            e["process"],
                            e["ip_address"],
                        ]
                    )
                tmp_csv.flush()
                explicit_csv_id = self.storage.upload_file(tmp_csv.name)

            result.transforms.append(
                Transform(
                    type="evtx_explicit_credential_use",
                    object_id=str(explicit_csv_id),
                    metadata={
                        "file_name": f"{file_enriched.file_name}_explicit_credential_use.csv",
                        "display_type_in_dashboard": "csv",
                        "display_title": "Explicit Credential Use",
                    },
                )
            )
            result.findings.append(
                Finding(
                    category=FindingCategory.EXTRACTED_DATA,
                    finding_name="evtx_explicit_credential_use",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=file_enriched.object_id,
                    severity=4,
                    raw_data={"count": len(parsed["explicit_logon_events"])},
                    data=[
                        FileObject(
                            type="finding_summary",
                            metadata={
                                "summary": f"{len(parsed['explicit_logon_events'])} explicit credential use event(s) (4648)"
                            },
                        )
                    ],
                )
            )

        # Process creation (4688) — CSV transform (no finding, just the data)
        if parsed["process_creation_events"]:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", newline="", suffix=".csv", delete=False
            ) as tmp_csv:
                writer = csv.writer(tmp_csv)
                writer.writerow(["time", "process", "command_line", "parent_process", "user", "domain"])
                for e in parsed["process_creation_events"]:
                    writer.writerow(
                        [
                            e["time"],
                            e["process"],
                            e["command_line"],
                            e["parent_process"],
                            e["user"],
                            e["domain"],
                        ]
                    )
                tmp_csv.flush()
                proc_csv_id = self.storage.upload_file(tmp_csv.name)

            result.transforms.append(
                Transform(
                    type="evtx_process_creation",
                    object_id=str(proc_csv_id),
                    metadata={
                        "file_name": f"{file_enriched.file_name}_process_creation.csv",
                        "display_type_in_dashboard": "csv",
                        "display_title": "Process Creation",
                    },
                )
            )

        # --- Child file resubmission: PowerShell script blocks ---
        # Each reassembled script block is uploaded and published as a new file
        # so the full enrichment pipeline (Titus, YARA, etc.) runs on it.
        resubmitted_count = 0
        if script_block_data:
            from common.models import File
            from common.queues import FILES_NEW_FILE_TOPIC, FILES_PUBSUB
            from dapr.aio.clients import DaprClient

            async with DaprClient() as dapr_client:
                for sb in script_block_data[:MAX_SCRIPT_BLOCK_FILES]:
                    text = sb["text"]
                    ps_path = sb["path"]
                    script_id = sb["id"]

                    # Derive child filename from the original script path if available
                    if ps_path:
                        base = os.path.basename(ps_path)
                        child_name = base if base.endswith(".ps1") else f"{base}.ps1"
                    else:
                        child_name = f"script_block_{script_id[:8]}.ps1"

                    try:
                        with tempfile.NamedTemporaryFile(
                            mode="w", encoding="utf-8", suffix=".ps1", delete=False
                        ) as tmp:
                            tmp.write(text)
                            tmp.flush()
                            child_id = self.storage.upload_file(tmp.name)

                        file_message = File(
                            object_id=str(child_id),
                            agent_id=file_enriched.agent_id,
                            project=file_enriched.project,
                            timestamp=file_enriched.timestamp,
                            expiration=file_enriched.expiration,
                            path=f"{file_enriched.path}/{child_name}",
                            originating_object_id=file_enriched.object_id,
                            nesting_level=(file_enriched.nesting_level or 0) + 1,
                        )

                        data = json.dumps(file_message.model_dump(exclude_unset=True, mode="json"))
                        await dapr_client.publish_event(
                            pubsub_name=FILES_PUBSUB,
                            topic_name=FILES_NEW_FILE_TOPIC,
                            data=data,
                            data_content_type="application/json",
                        )

                        resubmitted_count += 1
                    except Exception:
                        logger.exception(message="Failed to resubmit script block", script_id=script_id)

        if resubmitted_count > 0:
            result.findings.append(
                Finding(
                    category=FindingCategory.EXTRACTED_DATA,
                    finding_name="evtx_powershell_script_blocks",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=file_enriched.object_id,
                    severity=1,
                    raw_data={"script_block_count": resubmitted_count},
                    data=[
                        FileObject(
                            type="finding_summary",
                            metadata={
                                "summary": f"{resubmitted_count} PowerShell script block(s) extracted from Event 4104 and resubmitted for enrichment"
                            },
                        )
                    ],
                )
            )

        return result

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        try:
            file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

            if file_path:
                return await self._analyze_file(file_path, file_enriched)
            else:
                with self.storage.download(object_id) as temp_file:
                    return await self._analyze_file(temp_file.name, file_enriched)

        except Exception:
            logger.exception(message="Error in process()", object_id=object_id)
            return None


def create_enrichment_module() -> EnrichmentModule:
    return EVTXAnalyzer()

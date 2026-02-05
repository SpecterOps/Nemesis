# enrichment_modules/registry_hive/analyzer.py
import os
import posixpath
import shutil
import struct
import tempfile
import textwrap
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from common.helpers import get_drive_from_path
from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule
from file_linking.helpers import add_file_linking
from nemesis_dpapi import DpapiSystemCredential
from pypykatz.registry.offline_parser import OffineRegistry as OfflineRegistry
from pypykatz.registry.sam.structures import USER_ACCOUNT_V
from regipy.registry import RegistryHive

if TYPE_CHECKING:
    import asyncpg
    from nemesis_dpapi import DpapiManager


logger = get_logger(__name__)

# Well-known hash values for empty/blank passwords
EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"
EMPTY_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"

# SAM per-user F value Account Control Bits (ACB flags)
# Reference: ReactOS SAM_USER_FIXED_DATA structure
ACB_DISABLED = 0x0001
ACB_PWNOEXP = 0x0200

# Maximum number of characters to display before truncating LSA secret values
HEX_BLOB_TRUNCATE_CHARS = 200
GENERIC_SECRET_TRUNCATE_CHARS = 200


def _regipy_value_to_bytes(value: object) -> bytes | None:
    """Convert a regipy registry value to raw bytes.

    regipy returns REG_BINARY values as hex strings rather than raw bytes.
    This helper normalizes the value to bytes for struct parsing.
    """
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError:
            return None
    return None


def _filetime_to_str(filetime: int) -> str | None:
    """Convert a Windows FILETIME value (unsigned 64-bit) to a readable UTC string.

    Returns None for values representing 'never' or 'not set'.
    """
    if filetime == 0 or filetime >= 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        # FILETIME: 100-nanosecond intervals since 1601-01-01
        EPOCH_DIFF = 116444736000000000  # 100ns intervals between 1601-01-01 and 1970-01-01
        if filetime <= EPOCH_DIFF:
            return None
        timestamp = (filetime - EPOCH_DIFF) / 10_000_000
        dt = datetime.fromtimestamp(timestamp, tz=UTC)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, ValueError, OverflowError):
        return None


class RegistryHiveAnalyzer(EnrichmentModule):
    name: str = "registry_hive"
    dependencies: list[str] = []

    def __init__(self):
        self.storage = StorageMinio()

        self.asyncpg_pool = None  # type: ignore
        self.workflows = ["default"]
        self.dpapi_manager: DpapiManager = None  # type: ignore
        self.asyncpg_pool: asyncpg.Pool | None = None  # type: ignore

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run based on file type."""
        file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)
        magic_type = file_enriched.magic_type.lower()
        mime_type = file_enriched.mime_type.lower()

        # This is because the "strings.txt" of a registry hive
        #   has a matching magic type of the registry hive itself
        if mime_type != "application/octet-stream":
            return False

        if file_enriched.is_plaintext:
            return False

        # Check if it's a Windows registry hive
        return any(
            hive_type in magic_type
            for hive_type in [
                "ms windows registry file",
                "windows registry file",
                "registry hive",
                "windows nt registry hive",
            ]
        )

    def _identify_hive_type(self, file_path: str) -> str | None:
        """Identify the type of registry hive based regipy"""

        try:
            hive_type = RegistryHive(file_path).hive_type
            return hive_type.upper() if hive_type else None
        except Exception:
            logger.exception("Error parsing using regipy")

        return None

    def _extract_bootkey(self, registry: OfflineRegistry) -> str | None:
        """Extract bootkey from SYSTEM hive using pypykatz."""
        try:
            # pypykatz OfflineRegistry already extracts the bootkey when parsing SYSTEM
            if hasattr(registry, "system") and registry.system:
                # The bootkey is available in the system object
                if hasattr(registry.system, "bootkey"):
                    return (
                        registry.system.bootkey.hex()  # pyright: ignore[reportOptionalMemberAccess]
                        if hasattr(registry.system.bootkey, "hex")
                        else str(registry.system.bootkey)
                    )
            return None
        except Exception as e:
            logger.error(f"Failed to extract bootkey: {e}")
            return None

    async def _find_existing_hive(self, file_enriched, target_hive_path: str) -> str | None:
        """Find an existing hive by path."""
        if not self.asyncpg_pool:
            logger.warning("No connection pool available, cannot find existing hive")
            return None

        try:
            async with self.asyncpg_pool.acquire() as conn:
                # Look for existing hive by path
                result = await conn.fetchrow(
                    """
                    SELECT object_id
                    FROM files_enriched
                    WHERE source = $1
                    AND LOWER(path) = LOWER($2)
                    ORDER BY timestamp DESC
                    LIMIT 1
                """,
                    file_enriched.source,
                    target_hive_path,
                )

                if result:
                    return str(result["object_id"])  # Convert UUID to string

                # Fallback query: look for registry files by magic_type and enrichment results
                # Extract the hive type from the target path (e.g., SECURITY from .../Windows/System32/Config/SECURITY)
                target_hive_type = posixpath.basename(target_hive_path).upper()

                result = await conn.fetchrow(
                    """
                    SELECT fe.object_id
                    FROM files_enriched fe
                    JOIN enrichments e ON fe.object_id = e.object_id
                    WHERE fe.source = $1
                    AND fe.magic_type = 'MS Windows registry file, NT/2000 or above'
                    AND e.module_name = 'registry_hive'
                    AND e.result_data->'results'->'hive_type' = $2
                    ORDER BY fe.timestamp DESC
                    LIMIT 1
                """,
                    file_enriched.source,
                    f'"{target_hive_type}"',
                )

                if result:
                    return str(result["object_id"])  # Convert UUID to string

        except Exception as e:
            logger.error(f"Failed to find existing hive {target_hive_path}: {e}")

        return None

    async def _get_existing_hive_path(self, file_enriched, standard_path: str) -> str:
        """Get the actual path of an existing hive, or return the standard path if not found."""
        # First try to find an existing hive
        object_id = await self._find_existing_hive(file_enriched, standard_path)

        if object_id and self.asyncpg_pool:
            # Found an existing hive, get its actual path from the database
            try:
                async with self.asyncpg_pool.acquire() as conn:
                    result = await conn.fetchrow(
                        """
                        SELECT path
                        FROM files_enriched
                        WHERE object_id = $1
                        LIMIT 1
                    """,
                        object_id,
                    )

                    if result and result["path"]:
                        logger.debug(f"Found existing hive at {result['path']} instead of {standard_path}")
                        return result["path"]
            except Exception as e:
                logger.error(f"Failed to get path for existing hive {object_id}: {e}")

        # Fall back to standard path if not found or on error
        return standard_path

    async def _create_proactive_file_linkings(self, file_enriched, hive_type: str):
        """Create proactive file linkings based on hive type."""
        if not file_enriched.source or not file_enriched.path:
            return

        drive = get_drive_from_path(file_enriched.path) or ""
        # if not drive:
        #     logger.warning(f"Could not extract drive from path: {file_enriched.path}")
        #     return

        try:
            if hive_type == "SYSTEM":
                # Link to SAM and SECURITY hives
                # First check if they exist at non-standard locations
                sam_standard_path = f"{drive}/Windows/System32/Config/SAM"
                security_standard_path = f"{drive}/Windows/System32/Config/SECURITY"

                sam_path = await self._get_existing_hive_path(file_enriched, sam_standard_path)
                security_path = await self._get_existing_hive_path(file_enriched, security_standard_path)

                await add_file_linking(
                    source=file_enriched.source,
                    source_file_path=file_enriched.path,
                    linked_file_path=sam_path,
                    link_type="registry_system",
                    collection_reason="SYSTEM hive can decrypt SAM accounts",
                    connection_pool=self.asyncpg_pool,
                )

                await add_file_linking(
                    source=file_enriched.source,
                    source_file_path=file_enriched.path,
                    linked_file_path=security_path,
                    link_type="registry_system",
                    collection_reason="SYSTEM hive required to decrypt SECURITY data",
                    connection_pool=self.asyncpg_pool,
                )

            elif hive_type in ["SAM", "SECURITY"]:
                # Link to SYSTEM hive
                # First check if it exists at a non-standard location
                system_standard_path = f"{drive}/Windows/System32/Config/SYSTEM"
                system_path = await self._get_existing_hive_path(file_enriched, system_standard_path)

                await add_file_linking(
                    source=file_enriched.source,
                    source_file_path=file_enriched.path,
                    linked_file_path=system_path,
                    link_type="registry_system",
                    collection_reason=f"SYSTEM hive required to decrypt {hive_type} data",
                    connection_pool=self.asyncpg_pool,
                )

        except Exception as e:
            logger.error(f"Failed to create proactive file linkings: {e}")

    def _extract_machine_sid(self, sam_file: str) -> str | None:
        """Extract the machine SID from the SAM hive's domain V value.

        SAM\\Domains\\Account\\V contains an array of SAMP_VARIABLE_LENGTH_ATTRIBUTE
        descriptors (12 bytes each: {LONG Offset, ULONG Length, ULONG Qualifier})
        followed by a variable-length data region. Domain objects have 4 entries
        (SAMP_DOMAIN_VARIABLE_ATTRIBUTES = 4):

            Index 0: SAMP_DOMAIN_SECURITY_DESCRIPTOR
            Index 1: SAMP_DOMAIN_SID
            Index 2: SAMP_DOMAIN_OEM_INFORMATION
            Index 3: SAMP_DOMAIN_REPLICA

        Offsets are relative to the start of the data region, which begins
        immediately after the descriptor array (data_base = num_entries * 12).

        Returns a string like 'S-1-5-21-1234567890-1234567890-1234567890' or None.
        """
        try:
            hive = RegistryHive(sam_file)
            account_key = hive.get_key("\\SAM\\Domains\\Account")
            v_raw = account_key.get_value("V")

            if not isinstance(v_raw, bytes):
                return None

            # Domain V values have exactly SAMP_DOMAIN_VARIABLE_ATTRIBUTES (4)
            # descriptor entries, each 12 bytes (SAMP_VARIABLE_LENGTH_ATTRIBUTE).
            # The data region starts immediately after: data_base = 4 * 12 = 48.
            num_entries = 4
            data_base = num_entries * 12  # 48

            if len(v_raw) < data_base:
                return None

            # SAMP_DOMAIN_SID is at index 1.  Offset is LONG (signed),
            # Length and Qualifier are ULONG (unsigned).
            sid_data_offset, sid_length, _ = struct.unpack_from("<iII", v_raw, 1 * 12)

            if sid_data_offset < 0 or sid_length < 12:
                return None

            sid_abs = data_base + sid_data_offset
            if sid_abs + sid_length > len(v_raw):
                return None

            sid_bytes = v_raw[sid_abs : sid_abs + sid_length]

            # Decode standard binary SID:
            #   BYTE  Revision
            #   BYTE  SubAuthorityCount
            #   BYTE[6] IdentifierAuthority (big-endian)
            #   DWORD[n] SubAuthorities (little-endian)
            revision = sid_bytes[0]
            sub_auth_count = sid_bytes[1]
            if sub_auth_count == 0 or 8 + sub_auth_count * 4 > len(sid_bytes):
                return None

            authority = int.from_bytes(sid_bytes[2:8], "big")
            sub_auths = []
            for i in range(sub_auth_count):
                sa = struct.unpack_from("<I", sid_bytes, 8 + i * 4)[0]
                sub_auths.append(sa)
            return f"S-{revision}-{authority}-" + "-".join(str(sa) for sa in sub_auths)
        except Exception as e:
            logger.debug(f"Could not extract machine SID: {e}")
        return None

    def _get_sam_user_metadata(self, sam_file: str) -> dict[int, dict]:
        """Read additional per-user metadata from a SAM hive using regipy.

        Reads the per-user F value (SAM_USER_FIXED_DATA) for account flags and timestamps,
        and the V value (USER_ACCOUNT_V) for full name and comment. These fields are not
        exposed by pypykatz's SAMSecret objects.

        Returns a dict keyed by RID with metadata for each user.
        """
        metadata: dict[int, dict] = {}
        max_pw_age: int = 0  # Domain max password age (signed, negative = duration, 0 = never)

        try:
            hive = RegistryHive(sam_file)

            # Read domain-level F value for password policy (max_pw_age)
            try:
                domain_key = hive.get_key("\\SAM\\Domains\\Account")
                for value in domain_key.iter_values():
                    if value.name == "F":
                        f_raw = _regipy_value_to_bytes(value.value)
                        if f_raw and len(f_raw) >= 0x28:
                            # max_pw_age at offset 0x18 as signed int64 (negative = duration)
                            max_pw_age = struct.unpack_from("<q", f_raw, 0x18)[0]
                        break
            except Exception as e:
                logger.debug(f"Could not read domain F value for password policy: {e}")

            # Enumerate per-user subkeys
            try:
                users_key = hive.get_key("\\SAM\\Domains\\Account\\Users")
                for subkey in users_key.iter_subkeys():
                    if subkey.name.upper() == "NAMES":
                        continue
                    try:
                        rid = int(subkey.name, 16)
                    except ValueError:
                        continue

                    user_meta: dict = {}

                    for value in subkey.iter_values():
                        # regipy returns REG_BINARY values as hex strings
                        raw = _regipy_value_to_bytes(value.value)
                        if raw is None:
                            continue

                        if value.name == "F":
                            # SAM_USER_FIXED_DATA: minimum 0x3C bytes
                            # Offsets from ReactOS SAM_USER_FIXED_DATA:
                            #   0x18: Password Last Set (FILETIME)
                            #   0x20: Account Expires (FILETIME)
                            #   0x38: User Account Control flags (4 bytes)
                            if len(raw) >= 0x3C:
                                pw_last_set = struct.unpack_from("<Q", raw, 0x18)[0]
                                account_expires = struct.unpack_from("<Q", raw, 0x20)[0]
                                acb_flags = struct.unpack_from("<I", raw, 0x38)[0]

                                user_meta["account_disabled"] = bool(acb_flags & ACB_DISABLED)
                                user_meta["pw_doesnt_expire"] = bool(acb_flags & ACB_PWNOEXP)
                                user_meta["password_last_set"] = _filetime_to_str(pw_last_set)
                                user_meta["account_expires"] = _filetime_to_str(account_expires)

                                # Compute password expiration from policy + last set time
                                if user_meta["pw_doesnt_expire"] or max_pw_age == 0:
                                    user_meta["password_expires"] = None
                                elif max_pw_age < 0 and pw_last_set > 0 and pw_last_set < 0x7FFFFFFFFFFFFFFF:
                                    pw_expires_ft = pw_last_set + abs(max_pw_age)
                                    user_meta["password_expires"] = _filetime_to_str(pw_expires_ft)
                                else:
                                    user_meta["password_expires"] = None

                        elif value.name == "V":
                            try:
                                uac_v = USER_ACCOUNT_V.from_bytes(raw)
                                user_meta["full_name"] = uac_v.fullname or ""
                                user_meta["comment"] = uac_v.comment or ""
                            except Exception:
                                pass

                    metadata[rid] = user_meta

            except Exception as e:
                logger.debug(f"Could not enumerate SAM users via regipy: {e}")

        except Exception as e:
            logger.debug(f"Could not open SAM hive with regipy for metadata: {e}")

        return metadata

    def _process_sam_hive(self, sam_file: str, system_file: str | None) -> dict:
        """Process SAM hive to extract local accounts using pypykatz.

        Combines pypykatz hash decryption with regipy metadata extraction to
        produce detailed per-account information including hashes, account status,
        and timestamps.
        """
        results: dict = {"accounts": [], "bootkey_available": system_file is not None}

        try:
            # Use pypykatz to parse the SAM hive with optional SYSTEM hive for decryption
            if system_file:
                registry = OfflineRegistry.from_files(system_path=system_file, sam_path=sam_file)
                bootkey = self._extract_bootkey(registry)
                results["bootkey"] = bootkey
            else:
                # Cannot parse SAM without SYSTEM - pypykatz requires SYSTEM hive for proper parsing
                logger.warning("Cannot process SAM hive without SYSTEM hive - pypykatz requires both")
                return results

            # Extract the machine SID from the SAM hive
            machine_sid = self._extract_machine_sid(sam_file)
            if machine_sid:
                results["machine_sid"] = machine_sid

            # Read additional per-user metadata (full_name, comment, flags, timestamps)
            user_metadata = self._get_sam_user_metadata(sam_file)

            # Extract user information from parsed SAM
            if hasattr(registry, "sam") and registry.sam:
                sam_obj = registry.sam
                if hasattr(sam_obj, "secrets"):
                    for user in sam_obj.secrets:  # pyright: ignore[reportAttributeAccessIssue]
                        rid = getattr(user, "rid", None)
                        meta = user_metadata.get(rid, {}) if rid else {}

                        # Convert hashes to hex strings
                        nt_hash_raw = getattr(user, "nt_hash", None)
                        lm_hash_raw = getattr(user, "lm_hash", None)
                        nt_hash = (
                            (nt_hash_raw.hex() if nt_hash_raw and hasattr(nt_hash_raw, "hex") else str(nt_hash_raw))
                            if nt_hash_raw
                            else None
                        )
                        lm_hash = (
                            (lm_hash_raw.hex() if lm_hash_raw and hasattr(lm_hash_raw, "hex") else str(lm_hash_raw))
                            if lm_hash_raw
                            else None
                        )

                        user_info = {
                            "rid": rid,
                            "username": getattr(user, "username", None),
                            "full_name": meta.get("full_name", ""),
                            "comment": meta.get("comment", ""),
                            "nt_hash": nt_hash,
                            "nt_hash_empty": nt_hash is None or nt_hash == EMPTY_NT_HASH,
                            "lm_hash": lm_hash,
                            "lm_hash_empty": lm_hash is None or lm_hash == EMPTY_LM_HASH,
                            "account_disabled": meta.get("account_disabled", False),
                            "account_expires": meta.get("account_expires"),
                            "password_last_set": meta.get("password_last_set"),
                            "password_expires": meta.get("password_expires"),
                            "pw_doesnt_expire": meta.get("pw_doesnt_expire", False),
                            "bootkey_available": system_file is not None,
                        }

                        results["accounts"].append(user_info)

        except Exception as e:
            logger.error(f"Failed to process SAM hive with pypykatz: {e}")
            # Return empty results on error
            results["accounts"] = []
            results["error"] = "Could not parse SAM hive"

        return results

    async def _process_security_hive(self, security_file: str, system_file: str | None) -> dict:
        """Process SECURITY hive to extract LSA secrets using pypykatz."""
        results = {
            "lsa_secrets": [],
            "cached_credentials": [],
            "bootkey_available": system_file is not None,
        }

        if not system_file:
            # Cannot parse SECURITY without SYSTEM - pypykatz requires SYSTEM hive
            logger.debug("Cannot process SECURITY hive without SYSTEM hive - pypykatz requires both")
            return results

        # Create persistent copies of both files that pypykatz can access
        security_copy_path = None
        system_copy_path = None

        try:
            # Create temporary copies that persist during processing
            security_fd, security_copy_path = tempfile.mkstemp(suffix=".security")
            system_fd, system_copy_path = tempfile.mkstemp(suffix=".system")

            # Close the file descriptors but keep the paths
            os.close(security_fd)
            os.close(system_fd)

            # Copy the files
            shutil.copy2(security_file, security_copy_path)
            shutil.copy2(system_file, system_copy_path)

            # Now parse with pypykatz using the persistent copies
            registry = OfflineRegistry.from_files(system_path=system_copy_path, security_path=security_copy_path)

            # Extract bootkey from SYSTEM
            bootkey = self._extract_bootkey(registry)
            if bootkey:
                results["bootkey"] = bootkey
                logger.debug("Extracted bootkey from SYSTEM hive")
            else:
                logger.warning("Failed to extract bootkey from SYSTEM hive")

            # Call get_secrets to extract and decrypt secrets
            try:
                registry.get_secrets()
                logger.debug("get_secrets() completed successfully")
            except Exception as e:
                logger.warning(f"Failed to extract secrets: {e}")
                # Continue anyway to see if we can get any data

            # Extract LSA secrets from parsed SECURITY hive
            if hasattr(registry, "security") and registry.security:
                security_obj = registry.security

                # Try to get secrets as dictionary
                try:
                    security_dict = security_obj.to_dict()
                    logger.debug(f"Security dict keys: {list(security_dict.keys()) if security_dict else 'None'}")

                    # Extract LSA secrets - they're in 'cached_secrets', not 'lsa_secrets'!
                    if security_dict and "cached_secrets" in security_dict:
                        cached_secrets = security_dict["cached_secrets"]

                        if isinstance(cached_secrets, list):
                            # cached_secrets is a list of secret objects
                            for i, secret_data in enumerate(cached_secrets):
                                # If it's a dict, inspect its keys to find the actual secret data
                                if isinstance(secret_data, dict):
                                    # Look for common secret data keys
                                    secret_value = None
                                    secret_name = f"cached_secret_{i}"
                                    secret_type = "generic"

                                    # First try common secret keys
                                    for key in [
                                        "secret",
                                        "data",
                                        "value",
                                        "cleartext",
                                        "plaintext",
                                        "decrypted",
                                    ]:
                                        if key in secret_data:
                                            secret_value = secret_data[key]
                                            break

                                    # For DPAPI secrets, extract machine_key and user_key
                                    if not secret_value and "machine_key" in secret_data and "user_key" in secret_data:
                                        machine_key = secret_data["machine_key"]
                                        user_key = secret_data["user_key"]
                                        if isinstance(machine_key, bytes) and isinstance(user_key, bytes):
                                            secret_value = {
                                                "machine_key": machine_key.hex(),
                                                "user_key": user_key.hex(),
                                            }
                                            secret_name = secret_data.get("key_name", f"cached_secret_{i}")
                                            secret_type = "dpapi_system"

                                            logger.debug(
                                                f"Found DPAPI keys - machine_key: {len(machine_key)} bytes, user_key: {len(user_key)} bytes"
                                            )

                                            # Register the DPAPI_SYSTEM credential with the DPAPI manager
                                            await self._register_dpapi_system_credential(machine_key, user_key)

                                    # For NL$KM secrets, extract raw_secret
                                    elif not secret_value and "raw_secret" in secret_data:
                                        raw_secret = secret_data["raw_secret"]
                                        if isinstance(raw_secret, bytes):
                                            secret_value = raw_secret.hex()
                                            secret_name = secret_data.get("key_name", f"cached_secret_{i}")
                                            secret_type = "hex_blob"

                                    # If still no specific key found, try to get the first non-metadata value
                                    elif not secret_value:
                                        for key, value in secret_data.items():
                                            if (
                                                key
                                                not in [
                                                    "type",
                                                    "name",
                                                    "id",
                                                    "index",
                                                    "key_name",
                                                    "history",
                                                ]
                                                and value
                                            ):
                                                secret_value = value
                                                break

                                    secret_info: dict = {
                                        "name": secret_name,
                                        "secret_type": secret_type,
                                        "decrypted": True,
                                        "value": str(secret_value) if secret_value else str(secret_data),
                                        "bootkey_available": True,
                                    }
                                    # Store structured DPAPI keys for proper formatting
                                    if secret_type == "dpapi_system" and isinstance(secret_value, dict):
                                        secret_info["machine_key"] = secret_value["machine_key"]
                                        secret_info["user_key"] = secret_value["user_key"]
                                else:
                                    secret_info = {
                                        "name": f"cached_secret_{i}",
                                        "secret_type": "generic",
                                        "decrypted": True,
                                        "value": str(secret_data) if secret_data else None,
                                        "bootkey_available": True,
                                    }
                                results["lsa_secrets"].append(secret_info)
                        elif isinstance(cached_secrets, dict):
                            # cached_secrets is a dictionary
                            for secret_name, secret_data in cached_secrets.items():
                                secret_info = {
                                    "name": secret_name,
                                    "decrypted": True,
                                    "value": str(secret_data) if secret_data else None,
                                    "bootkey_available": True,
                                }
                                results["lsa_secrets"].append(secret_info)

                    # Also check for other secret types
                    secret_keys = ["lsa_key", "NK$LM", "dcc"]
                    for key in secret_keys:
                        if security_dict and key in security_dict:
                            secret_data = security_dict[key]

                            if key == "dcc" and isinstance(secret_data, list):
                                # Parse DCC cached domain credentials into structured entries
                                dcc_entries = []
                                for entry in secret_data:
                                    if isinstance(entry, dict):
                                        hash_value = entry.get("hash_value")
                                        if isinstance(hash_value, bytes):
                                            hash_hex = hash_value.hex()
                                        elif isinstance(hash_value, str):
                                            hash_hex = hash_value
                                        else:
                                            hash_hex = str(hash_value) if hash_value else ""

                                        dcc_entries.append(
                                            {
                                                "domain": str(entry.get("domain", "")),
                                                "username": str(entry.get("username", "")),
                                                "hash_value": hash_hex,
                                                "iteration": entry.get("iteration", 0),
                                                "lastwrite": str(entry.get("lastwrite", "")),
                                            }
                                        )

                                secret_info = {
                                    "name": "dcc",
                                    "secret_type": "dcc",
                                    "decrypted": True,
                                    "value": f"{len(dcc_entries)} cached domain credential(s)",
                                    "entries": dcc_entries,
                                    "bootkey_available": True,
                                }
                            elif isinstance(secret_data, bytes):
                                # Hex blobs (lsa_key, NK$LM)
                                secret_info = {
                                    "name": key,
                                    "secret_type": "hex_blob",
                                    "decrypted": True,
                                    "value": secret_data.hex(),
                                    "bootkey_available": True,
                                }
                            else:
                                secret_info = {
                                    "name": key,
                                    "secret_type": "generic",
                                    "decrypted": True,
                                    "value": str(secret_data) if secret_data else None,
                                    "bootkey_available": True,
                                }

                            results["lsa_secrets"].append(secret_info)

                    if not results["lsa_secrets"]:
                        logger.warning(
                            "No secrets extracted from security_dict - available keys: "
                            + str(list(security_dict.keys()))
                        )

                    # Also try direct attribute access for LSA secrets
                    if hasattr(security_obj, "lsa_secrets"):
                        lsa_secrets_attr = getattr(security_obj, "lsa_secrets", {})
                        logger.debug(f"Found lsa_secrets attribute with {len(lsa_secrets_attr)} items")
                        for secret_name, secret_data in lsa_secrets_attr.items():
                            # Avoid duplicates if we already processed from dict
                            if not any(s["name"] == secret_name for s in results["lsa_secrets"]):
                                secret_info = {
                                    "name": secret_name,
                                    "decrypted": True,
                                    "value": str(secret_data) if secret_data else None,
                                    "bootkey_available": True,
                                }
                                results["lsa_secrets"].append(secret_info)

                    # Check for cached domain credentials
                    if security_dict and "cached_creds" in security_dict and security_dict["cached_creds"]:
                        results["cached_credentials_key_present"] = True
                        for cached_cred in security_dict["cached_creds"]:
                            cred_info = {
                                "domain": cached_cred.get("domain"),
                                "username": cached_cred.get("username"),
                                "decrypted": True,
                            }
                            results["cached_credentials"].append(cred_info)

                except Exception as e:
                    logger.error(f"Failed to extract security dictionary: {e}")
                    # Try string representation as fallback
                    try:
                        security_str = str(security_obj)
                        logger.warning(f"Security string representation length: {len(security_str)}")
                        if security_str and len(security_str) > 10:
                            # If we have substantial content, create a basic entry
                            secret_info = {
                                "name": "parsed_from_string_representation",
                                "decrypted": True,
                                "value": "LSA secrets present - check raw data",
                                "bootkey_available": True,
                            }
                            results["lsa_secrets"].append(secret_info)
                    except Exception as e2:
                        logger.error(f"Failed to get security string representation: {e2}")

                # Also check for cached credentials via attribute access
                if hasattr(security_obj, "cached_creds"):
                    cached_creds_attr = getattr(security_obj, "cached_creds", [])
                    if cached_creds_attr:
                        results["cached_credentials_key_present"] = True
                        try:
                            for cached_cred in cached_creds_attr:
                                cred_info = {
                                    "domain": getattr(cached_cred, "domain", None),
                                    "username": getattr(cached_cred, "username", None),
                                    "decrypted": True,
                                }
                                results["cached_credentials"].append(cred_info)
                        except Exception as e:
                            logger.error(f"Failed to extract cached credentials: {e}")
            else:
                logger.warning("No security object found in registry after parsing")

        except Exception as e:
            logger.error(f"Failed to process SECURITY hive with pypykatz: {e}")
            # Return empty results on error
            results["lsa_secrets"] = []
            results["error"] = "Could not parse SECURITY hive"

        finally:
            # Clean up temporary files
            for temp_path in [security_copy_path, system_copy_path]:
                if temp_path and os.path.exists(temp_path):
                    try:
                        os.unlink(temp_path)
                    except Exception as e:
                        logger.warning(f"Failed to clean up temporary file {temp_path}: {e}")

        return results

    def _process_system_hive(self, system_file: str) -> dict:
        """Process SYSTEM hive to extract bootkey and system information using pypykatz."""
        results = {
            "bootkey": None,
            "computer_name": None,
            "current_control_set": None,
            "services": [],
        }

        try:
            # Use pypykatz to parse the SYSTEM hive
            registry = OfflineRegistry.from_files(system_path=system_file)

            # Extract bootkey
            bootkey = self._extract_bootkey(registry)
            if bootkey:
                results["bootkey"] = bootkey

            # Extract system information from parsed SYSTEM hive
            if hasattr(registry, "system") and registry.system:
                system_obj = registry.system

                # Get computer name if available
                if hasattr(system_obj, "machinename"):
                    results["computer_name"] = system_obj.machinename  # pyright: ignore[reportAttributeAccessIssue]

                # Get current control set info if available
                if hasattr(system_obj, "currentcontrol"):
                    results["current_control_set"] = system_obj.currentcontrol  # pyright: ignore[reportAttributeAccessIssue]

                # Extract some basic service info if available
                interesting_services = [
                    "NTDS",
                    "DNS",
                    "W32Time",
                    "LanmanServer",
                    "Spooler",
                ]
                for service_name in interesting_services:
                    service_info = {
                        "name": service_name,
                        "display_name": None,
                        "start_type": None,
                        "status": "present_in_system_hive",
                    }
                    results["services"].append(service_info)

        except Exception:
            logger.exception(message="Failed to process SYSTEM hive with pypykatz")
            # Return empty results on error
            results = {
                "bootkey": None,
                "error": "Could not parse SYSTEM hive",
                "computer_name": None,
                "current_control_set": None,
                "services": [],
            }

        return results

    def _format_sam_accounts_markdown(self, accounts: list[dict], limit: int = 10) -> str:
        """Format SAM accounts as detailed markdown."""
        output = ""
        for account in accounts[:limit]:
            username = account.get("username", "Unknown")
            rid = account.get("rid", "?")
            disabled = account.get("account_disabled", False)
            status_tag = " (DISABLED)" if disabled else ""
            output += f"### RID {rid}: {username}{status_tag}\n\n"

            if account.get("full_name"):
                output += f"- **Full Name**: {account['full_name']}\n"
            if account.get("comment"):
                output += f"- **Comment**: {account['comment']}\n"

            if account.get("nt_hash_empty"):
                output += "- **NT Hash**: `" + (account.get("nt_hash") or "") + "` (empty password)\n"
            elif account.get("nt_hash"):
                output += f"- **NT Hash**: `{account['nt_hash']}`\n"
            if account.get("lm_hash_empty"):
                output += "- **LM Hash**: Empty (no LM hash stored)\n"
            elif account.get("lm_hash"):
                output += f"- **LM Hash**: `{account['lm_hash']}`\n"

            account_expires = account.get("account_expires")
            output += f"- **Account Expires**: {account_expires or 'Never'}\n"

            pw_last_set = account.get("password_last_set")
            output += f"- **Password Last Set**: {pw_last_set or 'Never'}\n"

            if account.get("pw_doesnt_expire"):
                output += "- **Password Expires**: Never (password set to not expire)\n"
            else:
                pw_expires = account.get("password_expires")
                output += f"- **Password Expires**: {pw_expires or 'N/A'}\n"

            output += "\n"

        if len(accounts) > limit:
            output += f"*... and {len(accounts) - limit} more accounts*\n\n"
        return output

    def _format_sam_accounts_text(self, accounts: list[dict], indent: str = "  ") -> list[str]:
        """Format SAM accounts as detailed plain text lines."""
        lines: list[str] = []
        for account in accounts:
            username = account.get("username", "Unknown")
            rid = account.get("rid", "?")
            disabled = account.get("account_disabled", False)
            status_tag = "  [DISABLED]" if disabled else ""
            lines.append(f"\n{indent}RID {rid}: {username}{status_tag}")

            if account.get("full_name"):
                lines.append(f"{indent}  Full Name: {account['full_name']}")
            if account.get("comment"):
                lines.append(f"{indent}  Comment: {account['comment']}")

            if account.get("nt_hash_empty"):
                lines.append(f"{indent}  NT Hash: {account.get('nt_hash', '')} (empty password)")
            elif account.get("nt_hash"):
                lines.append(f"{indent}  NT Hash: {account['nt_hash']}")
            if account.get("lm_hash_empty"):
                lines.append(f"{indent}  LM Hash: (empty)")
            elif account.get("lm_hash"):
                lines.append(f"{indent}  LM Hash: {account['lm_hash']}")

            account_expires = account.get("account_expires")
            lines.append(f"{indent}  Account Expires: {account_expires or 'Never'}")

            pw_last_set = account.get("password_last_set")
            lines.append(f"{indent}  Password Last Set: {pw_last_set or 'Never'}")

            if account.get("pw_doesnt_expire"):
                lines.append(f"{indent}  Password Expires: Never (password set to not expire)")
            else:
                pw_expires = account.get("password_expires")
                lines.append(f"{indent}  Password Expires: {pw_expires or 'N/A'}")
        return lines

    def _format_lsa_secrets_text(self, secrets: list[dict], indent: str = "    ") -> list[str]:
        """Format LSA secrets as detailed plain text lines for displayable parsed output."""
        lines: list[str] = []
        for secret in secrets:
            name = secret.get("name", "Unknown")
            secret_type = secret.get("secret_type", "generic")

            if secret_type == "dcc":
                entries = secret.get("entries", [])
                lines.append(f"\n{indent}Cached Domain Credentials (DCC2): {len(entries)} account(s)")
                for entry in entries:
                    domain = entry.get("domain", "")
                    username = entry.get("username", "")
                    hash_value = entry.get("hash_value", "")
                    iteration = entry.get("iteration", 0)
                    lastwrite = entry.get("lastwrite", "")
                    lines.append(f"{indent}  {domain}\\{username}")
                    if iteration:
                        lines.append(f"{indent}    Hash (DCC2): $DCC2${iteration}#{username}#{hash_value}")
                    elif hash_value:
                        lines.append(f"{indent}    Hash: {hash_value}")
                    if lastwrite:
                        lines.append(f"{indent}    Last Write: {lastwrite}")

            elif secret_type == "dpapi_system":
                machine_key = secret.get("machine_key", "")
                user_key = secret.get("user_key", "")
                lines.append(f"\n{indent}{name}:")
                lines.append(f"{indent}  Machine Key: {machine_key}")
                lines.append(f"{indent}  User Key: {user_key}")

            elif secret_type == "hex_blob" or name in ("NK$LM", "NL$KM", "lsa_key"):
                value = secret.get("value", "")
                lines.append(f"\n{indent}{name}:")
                if value and len(value) > HEX_BLOB_TRUNCATE_CHARS:
                    lines.append(f"{indent}  {value[:HEX_BLOB_TRUNCATE_CHARS]}...")
                    lines.append(f"{indent}  ({len(value) // 2} bytes)")
                elif value:
                    lines.append(f"{indent}  {value}")
                else:
                    lines.append(f"{indent}  (empty)")

            else:
                # Generic secret
                value = secret.get("value", "")
                if not secret.get("decrypted", False):
                    lines.append(f"\n{indent}{name}: (encrypted)")
                elif value and len(value) > GENERIC_SECRET_TRUNCATE_CHARS:
                    lines.append(f"\n{indent}{name}:")
                    lines.append(f"{indent}  {value[:GENERIC_SECRET_TRUNCATE_CHARS]}...")
                elif value:
                    lines.append(f"\n{indent}{name}: {value}")
                else:
                    lines.append(f"\n{indent}{name}: (no value)")

        return lines

    def _format_lsa_secrets_markdown(self, secrets: list[dict], limit: int = 10) -> str:
        """Format LSA secrets as markdown for finding summary."""
        output = ""
        for secret in secrets[:limit]:
            name = secret.get("name", "Unknown")
            secret_type = secret.get("secret_type", "generic")

            if secret_type == "dcc":
                entries = secret.get("entries", [])
                output += "### Cached Domain Credentials (DCC2)\n\n"
                output += f"**{len(entries)}** cached account(s):\n\n"
                for entry in entries:
                    domain = entry.get("domain", "")
                    username = entry.get("username", "")
                    hash_value = entry.get("hash_value", "")
                    iteration = entry.get("iteration", 0)
                    lastwrite = entry.get("lastwrite", "")
                    output += f"- **{domain}\\\\{username}**\n"
                    if iteration:
                        output += f"  - Hash (DCC2): `$DCC2${iteration}#{username}#{hash_value}`\n"
                    elif hash_value:
                        output += f"  - Hash: `{hash_value}`\n"
                    if lastwrite:
                        output += f"  - Last Write: {lastwrite}\n"
                output += "\n"

            elif secret_type == "dpapi_system":
                machine_key = secret.get("machine_key", "")
                user_key = secret.get("user_key", "")
                output += f"### {name}\n\n"
                output += f"- **Machine Key**: `{machine_key}`\n"
                output += f"- **User Key**: `{user_key}`\n\n"

            elif secret_type == "hex_blob" or name in ("NK$LM", "NL$KM", "lsa_key"):
                value = secret.get("value", "")
                output += f"### {name}\n\n"
                if value and len(value) > HEX_BLOB_TRUNCATE_CHARS:
                    output += f"`{value[:HEX_BLOB_TRUNCATE_CHARS]}...` ({len(value) // 2} bytes)\n\n"
                elif value:
                    output += f"`{value}`\n\n"
                else:
                    output += "(empty)\n\n"

            else:
                # Generic secret
                value = secret.get("value", "")
                if not secret.get("decrypted", False):
                    output += f"- **{name}**: *(encrypted)*\n"
                elif value and len(value) > GENERIC_SECRET_TRUNCATE_CHARS:
                    output += f"- **{name}**: `{value[:GENERIC_SECRET_TRUNCATE_CHARS]}...`\n"
                elif value:
                    output += f"- **{name}**: `{value}`\n"
                else:
                    output += f"- **{name}**: *(no value)*\n"

        if len(secrets) > limit:
            output += f"\n*... and {len(secrets) - limit} more secrets*\n\n"

        return output

    def _create_finding_summary(self, hive_type: str, analysis_results: dict, file_enriched) -> str:
        """Create markdown summary for registry hive analysis."""
        summary = f"# Windows Registry Hive Analysis: {hive_type}\n\n"
        summary += f"**File**: `{file_enriched.file_name}`\n\n"
        summary += f"**Hive Type**: {hive_type}\n\n"

        if hive_type == "SYSTEM":
            if analysis_results.get("bootkey"):
                summary += f"**Bootkey**: `{analysis_results['bootkey']}`\n\n"
            if analysis_results.get("computer_name"):
                summary += f"**Computer Name**: `{analysis_results['computer_name']}`\n\n"
            if analysis_results.get("current_control_set"):
                summary += f"**Current Control Set**: {analysis_results['current_control_set']}\n\n"

            services = analysis_results.get("services", [])
            if services:
                summary += "## System Services\n\n"
                for service in services:
                    summary += f"* **{service['name']}**: {service.get('display_name', 'N/A')} (Start: {service.get('start_type', 'N/A')})\n"
                summary += "\n"

            # Include SAM analysis if processed
            sam_analysis = analysis_results.get("sam_analysis")
            if sam_analysis:
                accounts = sam_analysis.get("accounts", [])
                summary += "## Paired SAM Analysis\n\n"
                summary += f"**Local Accounts Found**: {len(accounts)}\n\n"
                if sam_analysis.get("machine_sid"):
                    summary += f"**Machine SID**: `{sam_analysis['machine_sid']}`\n\n"
                if accounts:
                    summary += self._format_sam_accounts_markdown(accounts, limit=10)

            # Include SECURITY analysis if processed
            security_analysis = analysis_results.get("security_analysis")
            if security_analysis:
                secrets = security_analysis.get("lsa_secrets", [])
                summary += "## Paired SECURITY Analysis\n\n"
                summary += f"**LSA Secrets Found**: {len(secrets)}\n\n"
                if secrets:
                    summary += self._format_lsa_secrets_markdown(secrets, limit=10)

                if security_analysis.get("cached_credentials_key_present"):
                    summary += "**Cached Domain Credentials**: Key present (NL$KM)\n\n"

        elif hive_type == "SAM":
            accounts = analysis_results.get("accounts", [])
            summary += f"**Local Accounts Found**: {len(accounts)}\n\n"
            if analysis_results.get("machine_sid"):
                summary += f"**Machine SID**: `{analysis_results['machine_sid']}`\n\n"
            if analysis_results.get("bootkey_available"):
                summary += "**Note**: Linked SYSTEM hive found - password decryption possible\n\n"
            else:
                summary += "**Note**: No linked SYSTEM hive - password hashes encrypted\n\n"

            if accounts:
                summary += "## Local User Accounts\n\n"
                summary += self._format_sam_accounts_markdown(accounts, limit=30)
                summary += "\n"

        elif hive_type == "SECURITY":
            secrets = analysis_results.get("lsa_secrets", [])
            summary += f"**LSA Secrets Found**: {len(secrets)}\n\n"
            if analysis_results.get("bootkey_available"):
                summary += "**Note**: Linked SYSTEM hive found - LSA secret decryption possible\n\n"
            else:
                summary += "**Note**: No linked SYSTEM hive - LSA secrets encrypted\n\n"

            if secrets:
                summary += "## LSA Secrets\n\n"
                summary += self._format_lsa_secrets_markdown(secrets, limit=10)

            if analysis_results.get("cached_credentials_key_present"):
                summary += "**Cached Domain Credentials**: Key present (NL$KM)\n\n"

        return summary

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process registry hive file and extract relevant information."""
        try:
            file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

            # Use provided file_path if available, otherwise download
            if file_path:
                return await self._analyze_registry_hive_file(file_path, file_enriched)
            else:
                # Download the file to a temporary location
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return await self._analyze_registry_hive_file(temp_file.name, file_enriched)

        except Exception:
            logger.exception(message="Error processing registry hive file")
            return None

    async def _analyze_registry_hive_file(self, hive_file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze registry hive file and generate enrichment result."""
        enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

        # Identify hive type
        hive_type = self._identify_hive_type(hive_file_path)
        if not hive_type:
            logger.warning(f"Could not identify registry hive type for {file_enriched.file_name}")
            return None

        analysis_results = {}
        linked_system_object_id = None

        # Create proactive file linkings
        await self._create_proactive_file_linkings(file_enriched, hive_type)

        # Process based on hive type
        if hive_type == "SYSTEM":
            # Process SYSTEM hive first
            analysis_results = self._process_system_hive(hive_file_path)

            # Also check for and process existing SAM/SECURITY hives
            drive = get_drive_from_path(file_enriched.path) or ""
            # if drive:
            sam_path = f"{drive}/Windows/System32/Config/SAM"
            security_path = f"{drive}/Windows/System32/Config/SECURITY"

            sam_object_id = await self._find_existing_hive(file_enriched, sam_path)
            security_object_id = await self._find_existing_hive(file_enriched, security_path)

            # Process SAM if found
            if sam_object_id:
                try:
                    with self.storage.download(sam_object_id) as sam_temp_file:
                        sam_results = self._process_sam_hive(sam_temp_file.name, hive_file_path)
                        analysis_results["sam_analysis"] = sam_results
                        logger.debug(f"Processed paired SAM hive for SYSTEM: {sam_path}")
                except Exception as e:
                    logger.error(f"Failed to process paired SAM hive: {e}")

            # Process SECURITY if found
            if security_object_id:
                try:
                    with self.storage.download(security_object_id) as security_temp_file:
                        sam_results = await self._process_security_hive(security_temp_file.name, hive_file_path)
                        analysis_results["security_analysis"] = sam_results
                        logger.debug(f"Processed paired SECURITY hive for SYSTEM: {security_path}")
                except Exception as e:
                    logger.error(f"Failed to process paired SECURITY hive: {e}")

        elif hive_type in ["SAM", "SECURITY"]:
            # Look for SYSTEM hive
            drive = get_drive_from_path(file_enriched.path) or ""
            system_object_id = None

            # if drive:
            system_path = f"{drive}/Windows/System32/Config/SYSTEM"
            system_object_id = await self._find_existing_hive(file_enriched, system_path)

            if system_object_id:
                # Download the SYSTEM hive
                try:
                    with self.storage.download(system_object_id) as system_temp_file:
                        if hive_type == "SAM":
                            analysis_results = self._process_sam_hive(hive_file_path, system_temp_file.name)
                        else:  # SECURITY
                            analysis_results = await self._process_security_hive(hive_file_path, system_temp_file.name)
                        logger.debug(f"Processed {hive_type} hive with SYSTEM bootkey")

                except Exception as e:
                    logger.error(f"Error downloading SYSTEM hive: {e}")
                    # Process without SYSTEM hive
                    if hive_type == "SAM":
                        analysis_results = self._process_sam_hive(hive_file_path, None)
                    else:  # SECURITY
                        analysis_results = await self._process_security_hive(hive_file_path, None)
                    logger.debug(f"Processed {hive_type} hive without SYSTEM bootkey (download error)")

            else:
                # Process without SYSTEM hive
                if hive_type == "SAM":
                    analysis_results = self._process_sam_hive(hive_file_path, None)
                else:  # SECURITY
                    analysis_results = await self._process_security_hive(hive_file_path, None)
                logger.debug(f"Processed {hive_type} hive without SYSTEM bootkey")

            # Store reference to system hive if found
            if system_object_id:
                linked_system_object_id = system_object_id

        else:
            # For other hive types, just note the type
            analysis_results = {"hive_type": hive_type, "processed": False}

        # Create finding if we have results
        if analysis_results:
            summary_markdown = self._create_finding_summary(hive_type, analysis_results, file_enriched)

            # Determine finding category and severity
            if hive_type == "SYSTEM" and analysis_results.get("bootkey"):
                category = FindingCategory.CREDENTIAL
                severity = 6
                finding_name = "system_hive_bootkey_extracted"
            elif hive_type == "SAM" and analysis_results.get("accounts"):
                category = FindingCategory.CREDENTIAL
                severity = 7 if analysis_results.get("bootkey_available") else 3
                finding_name = "sam_hive_accounts_detected"
            elif hive_type == "SECURITY" and analysis_results.get("lsa_secrets"):
                category = FindingCategory.CREDENTIAL
                severity = 7 if analysis_results.get("bootkey_available") else 3
                finding_name = "security_hive_secrets_detected"
            else:
                category = FindingCategory.INFORMATIONAL
                severity = 1
                finding_name = f"registry_hive_{hive_type.lower()}_processed"

            # Create display data
            display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

            # Create finding
            finding = Finding(
                category=category,
                finding_name=finding_name,
                origin_type=FindingOrigin.ENRICHMENT_MODULE,
                origin_name=self.name,
                object_id=file_enriched.object_id,
                severity=severity,
                raw_data={
                    "hive_type": hive_type,
                    "analysis_results": analysis_results,
                    "linked_system_hive": linked_system_object_id is not None,
                },
                data=[display_data],
            )

            enrichment_result.findings = [finding]
            enrichment_result.results = {
                "hive_type": hive_type,
                "analysis_results": analysis_results,
            }

            # Create displayable transform
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_file:
                yaml_output = []
                yaml_output.append(f"Registry Hive Analysis: {hive_type}")
                yaml_output.append("=" * (25 + len(hive_type)))
                yaml_output.append("")
                yaml_output.append(f"File: {file_enriched.file_name}")
                yaml_output.append(f"Hive Type: {hive_type}")
                yaml_output.append("")

                if hive_type == "SYSTEM":
                    if analysis_results.get("bootkey"):
                        yaml_output.append(f"Bootkey: {analysis_results['bootkey']}")
                    if analysis_results.get("computer_name"):
                        yaml_output.append(f"Computer Name: {analysis_results['computer_name']}")
                    if analysis_results.get("services"):
                        yaml_output.append("\nSystem Services:")
                        for service in analysis_results["services"]:
                            yaml_output.append(f"  {service['name']}: {service.get('display_name', 'N/A')}")

                    # Include paired SAM analysis
                    sam_analysis = analysis_results.get("sam_analysis")
                    if sam_analysis:
                        accounts = sam_analysis.get("accounts", [])
                        yaml_output.append("\nPaired SAM Analysis:")
                        yaml_output.append(f"  Local Accounts Found: {len(accounts)}")
                        if sam_analysis.get("machine_sid"):
                            yaml_output.append(f"  Machine SID: {sam_analysis['machine_sid']}")
                        if accounts:
                            yaml_output.append("  Local User Accounts:")
                            yaml_output.extend(self._format_sam_accounts_text(accounts, indent="    "))

                    # Include paired SECURITY analysis
                    security_analysis = analysis_results.get("security_analysis")
                    if security_analysis:
                        secrets = security_analysis.get("lsa_secrets", [])
                        yaml_output.append("\nPaired SECURITY Analysis:")
                        yaml_output.append(f"  LSA Secrets Found: {len(secrets)}")
                        if secrets:
                            yaml_output.append("  LSA Secrets:")
                            yaml_output.extend(self._format_lsa_secrets_text(secrets, indent="    "))

                elif hive_type == "SAM":
                    accounts = analysis_results.get("accounts", [])
                    yaml_output.append(f"Local Accounts Found: {len(accounts)}")
                    if analysis_results.get("machine_sid"):
                        yaml_output.append(f"Machine SID: {analysis_results['machine_sid']}")
                    yaml_output.append(f"Bootkey Available: {analysis_results.get('bootkey_available', False)}")
                    if accounts:
                        yaml_output.append("\nLocal User Accounts:")
                        yaml_output.extend(self._format_sam_accounts_text(accounts, indent="  "))

                elif hive_type == "SECURITY":
                    secrets = analysis_results.get("lsa_secrets", [])
                    yaml_output.append(f"LSA Secrets Found: {len(secrets)}")
                    yaml_output.append(f"Bootkey Available: {analysis_results.get('bootkey_available', False)}")
                    if secrets:
                        yaml_output.append("\nLSA Secrets:")
                        yaml_output.extend(self._format_lsa_secrets_text(secrets, indent="    "))

                display_content = textwrap.indent("\n".join(yaml_output), "   ")
                tmp_file.write(display_content)
                tmp_file.flush()

                display_object_id = self.storage.upload_file(tmp_file.name)

                displayable_parsed = Transform(
                    type="displayable_parsed",
                    object_id=str(display_object_id),
                    metadata={
                        "file_name": f"{file_enriched.file_name}_{hive_type.lower()}_analysis.txt",
                        "display_type_in_dashboard": "monaco",
                        "default_display": True,
                    },
                )
                enrichment_result.transforms = [displayable_parsed]

        return enrichment_result

    async def _register_dpapi_system_credential(self, machine_key: bytes, user_key: bytes):
        """Register a DPAPI_SYSTEM credential with the DPAPI manager.

        Args:
            machine_key: The machine key component (20 bytes)
            user_key: The user key component (20 bytes)
        """

        try:
            # Create DPAPI system credential from the machine and user keys
            logger.debug(
                "Registering DPAPI_SYSTEM credential with DPAPI manager",
                machine_key=machine_key.hex(),
                user_key=user_key.hex(),
            )
            dpapi_system_cred = DpapiSystemCredential(machine_key=machine_key, user_key=user_key)

            # Register with the DPAPI manager - it will automatically decrypt compatible masterkeys
            await self.dpapi_manager.upsert_system_credential(dpapi_system_cred)

            logger.info("Successfully registered DPAPI_SYSTEM credential with DPAPI manager")

        except Exception as e:
            logger.exception(f"Failed to register DPAPI_SYSTEM credential: {e}")


def create_enrichment_module() -> EnrichmentModule:
    return RegistryHiveAnalyzer()

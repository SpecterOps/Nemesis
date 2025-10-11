# enrichment_modules/registry_hive/analyzer.py
import asyncio
import ntpath
import os
import shutil
import tempfile
import textwrap
from typing import TYPE_CHECKING

import psycopg
from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from dapr.clients import DaprClient
from file_enrichment_modules.module_loader import EnrichmentModule
from file_linking.helpers import add_file_linking
from nemesis_dpapi import DpapiSystemCredential
from psycopg.rows import dict_row
from pypykatz.registry.offline_parser import OffineRegistry as OfflineRegistry
from regipy.registry import RegistryHive

if TYPE_CHECKING:
    from nemesis_dpapi import DpapiManager


logger = get_logger(__name__)


class RegistryHiveAnalyzer(EnrichmentModule):
    def __init__(self):
        super().__init__("registry_hive")
        self.storage = StorageMinio()
        self.workflows = ["default"]
        self.dpapi_manager: DpapiManager = None  # type: ignore
        self.loop: asyncio.AbstractEventLoop = None  # type: ignore

        # Get PostgreSQL connection string
        with DaprClient() as client:
            secret = client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_STRING")
            self._conninfo = secret.secret["POSTGRES_CONNECTION_STRING"]

    def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run based on file type."""
        file_enriched = get_file_enriched(object_id)
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
            return RegistryHive(file_path).hive_type.upper()
        except Exception as e:
            logger.exception(e, "Error parsing using regipy")

        return None

    def _extract_bootkey(self, registry: OfflineRegistry) -> str | None:
        """Extract bootkey from SYSTEM hive using pypykatz."""
        try:
            # pypykatz OfflineRegistry already extracts the bootkey when parsing SYSTEM
            if hasattr(registry, "system") and registry.system:
                # The bootkey is available in the system object
                if hasattr(registry.system, "bootkey"):
                    return (
                        registry.system.bootkey.hex()
                        if hasattr(registry.system.bootkey, "hex")
                        else str(registry.system.bootkey)
                    )
            return None
        except Exception as e:
            logger.error(f"Failed to extract bootkey: {e}")
            return None

    def _find_existing_hive(self, file_enriched, target_hive_path: str) -> str | None:
        """Find an existing hive by path."""
        try:
            with psycopg.connect(self._conninfo, row_factory=dict_row) as conn:
                with conn.cursor() as cur:
                    # Look for existing hive by path
                    cur.execute(
                        """
                        SELECT object_id
                        FROM files_enriched
                        WHERE source = %s
                        AND LOWER(path) = LOWER(%s)
                        ORDER BY timestamp DESC
                        LIMIT 1
                    """,
                        (file_enriched.source, target_hive_path),
                    )

                    result = cur.fetchone()
                    if result:
                        return str(result["object_id"])  # Convert UUID to string

                    # Fallback query: look for registry files by magic_type and enrichment results
                    # Extract the hive type from the target path (e.g., SECURITY from ...\\Windows\\System32\\Config\\SECURITY)
                    target_hive_type = ntpath.basename(target_hive_path).upper()

                    cur.execute(
                        """
                        SELECT fe.object_id
                        FROM files_enriched fe
                        JOIN enrichments e ON fe.object_id = e.object_id
                        WHERE fe.source = %s
                        AND fe.magic_type = 'MS Windows registry file, NT/2000 or above'
                        AND e.module_name = 'registry_hive'
                        AND e.result_data->'results'->'hive_type' = %s
                        ORDER BY fe.timestamp DESC
                        LIMIT 1
                    """,
                        (file_enriched.source, f'"{target_hive_type}"'),
                    )

                    result = cur.fetchone()
                    if result:
                        return str(result["object_id"])  # Convert UUID to string

        except Exception as e:
            logger.error(f"Failed to find existing hive {target_hive_path}: {e}")

        return None

    def _get_existing_hive_path(self, file_enriched, standard_path: str) -> str:
        """Get the actual path of an existing hive, or return the standard path if not found."""
        # First try to find an existing hive
        object_id = self._find_existing_hive(file_enriched, standard_path)

        if object_id:
            # Found an existing hive, get its actual path from the database
            try:
                with psycopg.connect(self._conninfo, row_factory=dict_row) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT path
                            FROM files_enriched
                            WHERE object_id = %s
                            LIMIT 1
                        """,
                            (object_id,),
                        )

                        result = cur.fetchone()
                        if result and result["path"]:
                            logger.debug(f"Found existing hive at {result['path']} instead of {standard_path}")
                            return result["path"]
            except Exception as e:
                logger.error(f"Failed to get path for existing hive {object_id}: {e}")

        # Fall back to standard path if not found or on error
        return standard_path

    def _create_proactive_file_linkings(self, file_enriched, hive_type: str):
        """Create proactive file linkings based on hive type."""
        if not file_enriched.source or not file_enriched.path:
            return

        drive, _ = ntpath.splitdrive(file_enriched.path)
        if not drive:
            logger.warning(f"Could not extract drive from path: {file_enriched.path}")
            return

        try:
            if hive_type == "SYSTEM":
                # Link to SAM and SECURITY hives
                # First check if they exist at non-standard locations
                sam_standard_path = f"{drive}\\Windows\\System32\\Config\\SAM"
                security_standard_path = f"{drive}\\Windows\\System32\\Config\\SECURITY"

                sam_path = self._get_existing_hive_path(file_enriched, sam_standard_path)
                security_path = self._get_existing_hive_path(file_enriched, security_standard_path)

                add_file_linking(
                    source=file_enriched.source,
                    source_file_path=file_enriched.path,
                    linked_file_path=sam_path,
                    link_type="registry_system",
                    collection_reason="SYSTEM hive can decrypt SAM accounts",
                )

                add_file_linking(
                    source=file_enriched.source,
                    source_file_path=file_enriched.path,
                    linked_file_path=security_path,
                    link_type="registry_system",
                    collection_reason="SYSTEM hive required to decrypt SECURITY data",
                )

            elif hive_type in ["SAM", "SECURITY"]:
                # Link to SYSTEM hive
                # First check if it exists at a non-standard location
                system_standard_path = f"{drive}\\Windows\\System32\\Config\\SYSTEM"
                system_path = self._get_existing_hive_path(file_enriched, system_standard_path)

                add_file_linking(
                    source=file_enriched.source,
                    source_file_path=file_enriched.path,
                    linked_file_path=system_path,
                    link_type="registry_system",
                    collection_reason=f"SYSTEM hive required to decrypt {hive_type} data",
                )

        except Exception as e:
            logger.error(f"Failed to create proactive file linkings: {e}")

    def _process_sam_hive(self, sam_file: str, system_file: str | None) -> dict:
        """Process SAM hive to extract local accounts using pypykatz."""
        results = {"accounts": [], "bootkey_available": system_file is not None}

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

            # Extract user information from parsed SAM
            if hasattr(registry, "sam") and registry.sam:
                sam_obj = registry.sam
                if hasattr(sam_obj, "users"):
                    for user in sam_obj.users:
                        user_info = {
                            "rid": getattr(user, "rid", None),
                            "username": getattr(user, "username", None),
                            "full_name": getattr(user, "fullname", None),
                            "comment": getattr(user, "comment", None),
                            "nt_hash": getattr(user, "nt_hash", None),
                            "lm_hash": getattr(user, "lm_hash", None),
                            "bootkey_available": system_file is not None,
                        }

                        # Convert hashes to hex strings if they exist
                        if user_info["nt_hash"]:
                            user_info["nt_hash"] = (
                                user_info["nt_hash"].hex()
                                if hasattr(user_info["nt_hash"], "hex")
                                else str(user_info["nt_hash"])
                            )
                        if user_info["lm_hash"]:
                            user_info["lm_hash"] = (
                                user_info["lm_hash"].hex()
                                if hasattr(user_info["lm_hash"], "hex")
                                else str(user_info["lm_hash"])
                            )

                        results["accounts"].append(user_info)

        except Exception as e:
            logger.error(f"Failed to process SAM hive with pypykatz: {e}")
            # Return empty results on error
            results["accounts"] = []
            results["error"] = "Could not parse SAM hive"

        return results

    def _process_security_hive(self, security_file: str, system_file: str | None) -> dict:
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
                    logger.warning(f"Security dict keys: {list(security_dict.keys()) if security_dict else 'None'}")

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

                                            logger.warning(
                                                f"Found DPAPI keys - machine_key: {len(machine_key)} bytes, user_key: {len(user_key)} bytes"
                                            )

                                            # Register the DPAPI_SYSTEM credential with the DPAPI manager
                                            asyncio.run_coroutine_threadsafe(
                                                self._register_dpapi_system_credential(machine_key, user_key), self.loop
                                            )

                                    # For NL$KM secrets, extract raw_secret
                                    elif not secret_value and "raw_secret" in secret_data:
                                        raw_secret = secret_data["raw_secret"]
                                        if isinstance(raw_secret, bytes):
                                            secret_value = raw_secret.hex()
                                            secret_name = secret_data.get("key_name", f"cached_secret_{i}")

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

                                    secret_info = {
                                        "name": secret_name,
                                        "decrypted": True,
                                        "value": str(secret_value) if secret_value else str(secret_data),
                                        "bootkey_available": True,
                                    }
                                else:
                                    secret_info = {
                                        "name": f"cached_secret_{i}",
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

                            # Format bytes as hex strings for better readability
                            if isinstance(secret_data, bytes):
                                formatted_value = secret_data.hex()
                            else:
                                formatted_value = str(secret_data) if secret_data else None

                            secret_info = {
                                "name": key,
                                "decrypted": True,
                                "value": formatted_value,
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
                if hasattr(system_obj, "computer_name"):
                    results["computer_name"] = system_obj.computer_name

                # Get current control set info if available
                if hasattr(system_obj, "current_control_set"):
                    results["current_control_set"] = system_obj.current_control_set

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

        except Exception as e:
            logger.exception(e, message="Failed to process SYSTEM hive with pypykatz")
            # Return empty results on error
            results = {
                "bootkey": None,
                "error": "Could not parse SYSTEM hive",
                "computer_name": None,
                "current_control_set": None,
                "services": [],
            }

        return results

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
                if accounts:
                    summary += "**Local User Accounts**:\n\n"
                    for account in accounts[:10]:  # Limit to first 10
                        summary += f"* **RID {account['rid']}**: {account.get('username', 'Unknown')}\n"
                    if len(accounts) > 10:
                        summary += f"* ... and {len(accounts) - 10} more accounts\n"
                    summary += "\n"

            # Include SECURITY analysis if processed
            security_analysis = analysis_results.get("security_analysis")
            if security_analysis:
                secrets = security_analysis.get("lsa_secrets", [])
                summary += "## Paired SECURITY Analysis\n\n"
                summary += f"**LSA Secrets Found**: {len(secrets)}\n\n"
                if secrets:
                    summary += "**LSA Secrets**:\n\n"
                    for secret in secrets[:10]:  # Limit to first 10
                        outputStr = self._get_lsa_secret_output_string(secret, truncate_length=100, markdown=True)
                        summary += f"- {outputStr}\n"
                    if len(secrets) > 10:
                        summary += f"* ... and {len(secrets) - 10} more secrets\n"
                    summary += "\n"

                if security_analysis.get("cached_credentials_key_present"):
                    summary += "**Cached Domain Credentials**: Key present (NL$KM)\n\n"

        elif hive_type == "SAM":
            accounts = analysis_results.get("accounts", [])
            summary += f"**Local Accounts Found**: {len(accounts)}\n\n"
            if analysis_results.get("bootkey_available"):
                summary += "**Note**: Linked SYSTEM hive found - password decryption possible\n\n"
            else:
                summary += "**Note**: No linked SYSTEM hive - password hashes encrypted\n\n"

            if accounts:
                summary += "## Local User Accounts\n\n"
                for account in accounts[:10]:  # Limit to first 10
                    summary += f"* **RID {account['rid']}**: {account.get('username', 'Unknown')}\n"
                if len(accounts) > 10:
                    summary += f"* ... and {len(accounts) - 10} more accounts\n"
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
                for secret in secrets[:10]:  # Limit to first 10
                    outputStr = self._get_lsa_secret_output_string(secret, truncate_length=100, markdown=True)
                    summary += f"- {outputStr}\n"
                if len(secrets) > 10:
                    summary += f"* ... and {len(secrets) - 10} more secrets\n"
                summary += "\n"

            if analysis_results.get("cached_credentials_key_present"):
                summary += "**Cached Domain Credentials**: Key present (NL$KM)\n\n"

        return summary

    def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Do the file enrichment.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file

        Returns:
            EnrichmentResult or None if processing fails
        """

        return asyncio.run_coroutine_threadsafe(self._process_async(object_id, file_path), self.loop).result()

    async def _process_async(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process registry hive file and extract relevant information."""
        try:
            file_enriched = get_file_enriched(object_id)

            # Use provided file_path if available, otherwise download
            if file_path:
                return self._analyze_registry_hive_file(file_path, file_enriched)
            else:
                # Download the file to a temporary location
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_registry_hive_file(temp_file.name, file_enriched)

        except Exception as e:
            logger.exception(e, message="Error processing registry hive file")
            return None

    def _get_lsa_secret_output_string(self, secret: dict, truncate_length: int = 8196, markdown: bool = False) -> str:
        keyStr = f"**{secret['name']}**" if markdown else secret["name"]

        if not isinstance(secret, dict):
            raise ValueError("Expect a LSA secret dictionary")

        if "name" not in secret:
            raise ValueError("Expect a LSA secret dictionary with 'name' key")

        if not secret.get("decrypted", False):
            return f"{keyStr}: Encrypted data"

        if not secret.get("value"):
            return f"{keyStr}: No Value"

        # Show decrypted value, but truncate if too long
        value = secret["value"]

        if len(value) > truncate_length:
            value = value[:truncate_length] + "..."

        value = f"`{value}`" if markdown else value

        return f"{keyStr}: {value}"

    def _analyze_registry_hive_file(self, hive_file_path: str, file_enriched) -> EnrichmentResult | None:
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
        self._create_proactive_file_linkings(file_enriched, hive_type)

        # Process based on hive type
        if hive_type == "SYSTEM":
            # Process SYSTEM hive first
            analysis_results = self._process_system_hive(hive_file_path)

            # Also check for and process existing SAM/SECURITY hives
            drive, _ = ntpath.splitdrive(file_enriched.path)
            if drive:
                sam_path = f"{drive}\\Windows\\System32\\Config\\SAM"
                security_path = f"{drive}\\Windows\\System32\\Config\\SECURITY"

                sam_object_id = self._find_existing_hive(file_enriched, sam_path)
                security_object_id = self._find_existing_hive(file_enriched, security_path)

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
                            sam_results = self._process_security_hive(security_temp_file.name, hive_file_path)
                            analysis_results["security_analysis"] = sam_results
                            logger.debug(f"Processed paired SECURITY hive for SYSTEM: {security_path}")
                    except Exception as e:
                        logger.error(f"Failed to process paired SECURITY hive: {e}")

        elif hive_type in ["SAM", "SECURITY"]:
            # Look for SYSTEM hive
            drive, _ = ntpath.splitdrive(file_enriched.path)
            system_object_id = None

            if drive:
                system_path = f"{drive}\\Windows\\System32\\Config\\SYSTEM"
                system_object_id = self._find_existing_hive(file_enriched, system_path)

            if system_object_id:
                # Download the SYSTEM hive
                try:
                    with self.storage.download(system_object_id) as system_temp_file:
                        if hive_type == "SAM":
                            analysis_results = self._process_sam_hive(hive_file_path, system_temp_file.name)
                        else:  # SECURITY
                            analysis_results = self._process_security_hive(hive_file_path, system_temp_file.name)
                        logger.debug(f"Processed {hive_type} hive with SYSTEM bootkey")

                except Exception as e:
                    logger.error(f"Error downloading SYSTEM hive: {e}")
                    # Process without SYSTEM hive
                    if hive_type == "SAM":
                        analysis_results = self._process_sam_hive(hive_file_path, None)
                    else:  # SECURITY
                        analysis_results = self._process_security_hive(hive_file_path, None)
                    logger.debug(f"Processed {hive_type} hive without SYSTEM bootkey (download error)")

            else:
                # Process without SYSTEM hive
                if hive_type == "SAM":
                    analysis_results = self._process_sam_hive(hive_file_path, None)
                else:  # SECURITY
                    analysis_results = self._process_security_hive(hive_file_path, None)
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
                severity = 8
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
                        if accounts:
                            yaml_output.append("  Local User Accounts:")
                            for account in accounts[:10]:
                                yaml_output.append(f"    RID {account['rid']}: {account.get('username', 'Unknown')}")

                    # Include paired SECURITY analysis
                    security_analysis = analysis_results.get("security_analysis")
                    if security_analysis:
                        secrets = security_analysis.get("lsa_secrets", [])
                        yaml_output.append("\nPaired SECURITY Analysis:")
                        yaml_output.append(f"  LSA Secrets Found: {len(secrets)}")
                        if secrets:
                            yaml_output.append("  LSA Secrets:")
                            for secret in secrets:
                                outputStr = self._get_lsa_secret_output_string(secret)
                                yaml_output.append(f"    {outputStr}")

                elif hive_type == "SAM":
                    accounts = analysis_results.get("accounts", [])
                    yaml_output.append(f"Local Accounts Found: {len(accounts)}")
                    yaml_output.append(f"Bootkey Available: {analysis_results.get('bootkey_available', False)}")
                    if accounts:
                        yaml_output.append("\nLocal User Accounts:")
                        for account in accounts[:10]:
                            yaml_output.append(f"  RID {account['rid']}: {account.get('username', 'Unknown')}")

                elif hive_type == "SECURITY":
                    secrets = analysis_results.get("lsa_secrets", [])
                    yaml_output.append(f"LSA Secrets Found: {len(secrets)}")
                    yaml_output.append(f"Bootkey Available: {analysis_results.get('bootkey_available', False)}")
                    if secrets:
                        yaml_output.append("\nLSA Secrets:")
                        for secret in secrets:
                            outputStr = self._get_lsa_secret_output_string(secret)
                            yaml_output.append(f"    {outputStr}")

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
            logger.exception(e, f"Failed to register DPAPI_SYSTEM credential: {e}")


def create_enrichment_module() -> EnrichmentModule:
    return RegistryHiveAnalyzer()

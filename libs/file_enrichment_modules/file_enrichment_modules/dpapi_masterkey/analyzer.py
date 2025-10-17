# enrichment_modules/dpapi_masterkey/analyzer.py
import posixpath
import re
from typing import TYPE_CHECKING

import psycopg
from common.db import get_postgres_connection_str
from common.helpers import get_drive_from_path
from common.logger import get_logger
from common.models import EnrichmentResult
from common.state_helpers import get_file_enriched, get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule
from file_linking.helpers import add_file_linking
from nemesis_dpapi import DpapiManager, MasterKey, MasterKeyFile, MasterKeyType
from psycopg.rows import dict_row

if TYPE_CHECKING:
    import asyncio

    from nemesis_dpapi import DpapiManager


logger = get_logger(__name__)


class DPAPIMasterkeyAnalyzer(EnrichmentModule):
    def __init__(self, standalone: bool = False):
        super().__init__("dpapi_masterkey")
        self.storage = StorageMinio()
        self.dpapi_manager: DpapiManager = None  # type: ignore
        self.loop: asyncio.AbstractEventLoop = None  # type: ignore

        # the workflows this module should automatically run in
        self.workflows = ["default"]

        # GUID regex pattern
        self.guid_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )
        self._conninfo = get_postgres_connection_str()

    def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Check if this file should be processed as a DPAPI masterkey file.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file
        """
        file_enriched = get_file_enriched(object_id)

        # Check file size - masterkey files are typically small (usually less than 2KB)
        if file_enriched.size > 2048:
            return False

        if file_enriched.is_plaintext:
            return False

        # Check if filename matches GUID pattern
        file_name_lower = file_enriched.file_name.lower() if file_enriched.file_name else ""
        return self.guid_pattern.match(file_name_lower) is not None

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
                    # Extract the hive type from the target path (e.g., SECURITY from .../Windows/System32/Config/SECURITY)
                    target_hive_type = posixpath.basename(target_hive_path).upper()

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

    async def _create_proactive_file_linkings(self, file_enriched):
        """Create proactive file linkings for the related registry hives."""
        if not file_enriched.source or not file_enriched.path:
            return

        drive = get_drive_from_path(file_enriched.path) or ""
        # if not drive:
        #     logger.warning(f"Could not extract drive from path: {file_enriched.path}")
        #     return

        try:
            # Link to SYSTEM and SECURITY hives, needed to decrypt the SYSTEM masterkeys
            system_standard_path = f"{drive}/Windows/System32/Config/SYSTEM"
            security_standard_path = f"{drive}/Windows/System32/Config/SECURITY"

            system_path = self._get_existing_hive_path(file_enriched, system_standard_path)
            security_path = self._get_existing_hive_path(file_enriched, security_standard_path)

            await add_file_linking(
                source=file_enriched.source,
                source_file_path=file_enriched.path,
                linked_file_path=system_path,
                link_type="system_hive",
                collection_reason="Needed to decrypt the DPAPI_SYSTEM secret",
            )

            await add_file_linking(
                source=file_enriched.source,
                source_file_path=file_enriched.path,
                linked_file_path=security_path,
                link_type="security_hive",
                collection_reason="Needed to decrypt the DPAPI_SYSTEM secret",
            )

        except Exception as e:
            logger.error(f"Failed to create proactive file linkings: {e}")

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process masterkey file and add to DPAPI manager.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file

        Returns:
            EnrichmentResult or None if processing fails
        """
        return await self._process_async(object_id, file_path)

    async def _process_async(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process masterkey file and add to DPAPI manager.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file
        """

        try:
            file_enriched = await get_file_enriched_async(object_id)
            file_enriched = await get_file_enriched_async(object_id)
            enrichment_result = EnrichmentResult(module_name=self.name)

            # Parse the masterkey file
            if file_path:
                # Use provided file path
                masterkey_file = MasterKeyFile.from_file(file_path)
                if masterkey_file.policy.value & 2:
                    await self._create_proactive_file_linkings(file_enriched)
            else:
                # Download the file and parse it
                with self.storage.download(file_enriched.object_id) as temp_file:
                    masterkey_file = MasterKeyFile.from_file(temp_file.name)

            backup_key = masterkey_file.domain_backup_key
            mk = MasterKey(
                guid=masterkey_file.masterkey_guid,
                encrypted_key_usercred=masterkey_file.master_key,
                encrypted_key_backup=backup_key.raw_bytes if backup_key else None,
                backup_key_guid=backup_key.guid_key if backup_key else None,
                masterkey_type=MasterKeyType.from_path(file_enriched.path),
            )

            # The DPAPI manager handles all decryption automatically
            await self.dpapi_manager.upsert_masterkey(mk)

            # Check if it was decrypted
            stored_mks = await self.dpapi_manager.get_masterkeys(guid=masterkey_file.masterkey_guid)
            was_decrypted = len(stored_mks) > 0 and stored_mks[0].is_decrypted

            if was_decrypted:
                logger.info(f"Successfully processed and decrypted masterkey {masterkey_file.masterkey_guid}")
            else:
                logger.debug(
                    f"Successfully processed masterkey {masterkey_file.masterkey_guid} (not decrypted - may need additional keys)"
                )

            # Prepare results data
            results_data = {
                "masterkey_guid": str(masterkey_file.masterkey_guid),
                "version": masterkey_file.version,
                "policy": masterkey_file.policy.value if masterkey_file.policy else 0,
                "has_master_key": masterkey_file.master_key is not None,
                "has_local_key": masterkey_file.local_key is not None,
                "has_backup_key": masterkey_file.backup_key is not None,
                "has_domain_backup_key": masterkey_file.domain_backup_key is not None,
            }

            enrichment_result.results = results_data
            return enrichment_result

        except Exception as e:
            logger.exception(e, message="Error in DPAPI masterkey process()")


def create_enrichment_module(standalone: bool = False) -> EnrichmentModule:
    """Factory function that creates the analyzer in either standalone or service mode."""
    return DPAPIMasterkeyAnalyzer(standalone=standalone)

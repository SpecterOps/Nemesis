# enrichment_modules/dpapi_masterkey/analyzer.py
import asyncio
import re
from typing import TYPE_CHECKING

from common.logger import get_logger
from common.models import EnrichmentResult
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from dapr.clients import DaprClient
from file_enrichment_modules.module_loader import EnrichmentModule
from nemesis_dpapi import DpapiManager, MasterKey, MasterKeyFile
from nemesis_dpapi.eventing import DaprDpapiEventPublisher

if TYPE_CHECKING:
    from nemesis_dpapi import DpapiManager


logger = get_logger(__name__)


class DPAPIMasterkeyAnalyzer(EnrichmentModule):
    def __init__(self, standalone: bool = False):
        super().__init__("dpapi_masterkey")
        self.storage = StorageMinio()
        self.dpapi_manager: DpapiManager | None = None
        # the workflows this module should automatically run in
        self.workflows = ["default"]

        # GUID regex pattern
        self.guid_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )

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

        # Check if filename matches GUID pattern
        file_name_lower = file_enriched.file_name.lower() if file_enriched.file_name else ""
        return self.guid_pattern.match(file_name_lower) is not None

    def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process masterkey file and add to DPAPI manager.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file

        Returns:
            EnrichmentResult or None if processing fails
        """

        loop = None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running loop
            pass

        if loop:
            return asyncio.run_coroutine_threadsafe(self._process_async(object_id, file_path), loop).result()
        else:
            # No running loop, create a new event loop
            return asyncio.run(self._process_async(object_id, file_path))

    async def _process_async(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process masterkey file and add to DPAPI manager.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file
        """
        with DaprClient() as client:
            secret = client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_STRING")
            postgres_connection_string = secret.secret["POSTGRES_CONNECTION_STRING"]

            if not postgres_connection_string.startswith("postgres://"):
                raise ValueError(
                    "POSTGRES_CONNECTION_STRING must start with 'postgres://' to be used with the DpapiManager"
                )

            self.dpapi_manager = DpapiManager(
                storage_backend=postgres_connection_string, publisher=DaprDpapiEventPublisher(client)
            )

            try:
                file_enriched = get_file_enriched(object_id)
                enrichment_result = EnrichmentResult(module_name=self.name)

                # Parse the masterkey file
                if file_path:
                    # Use provided file path
                    masterkey_file = self._parse_masterkey_file(file_path)
                else:
                    # Download the file and parse it
                    with self.storage.download(file_enriched.object_id) as temp_file:
                        masterkey_file = self._parse_masterkey_file(temp_file.name)

                if not masterkey_file:
                    return None

                # Create MasterKey object and add to DPAPI manager
                if self.dpapi_manager:
                    mk = MasterKey(
                        guid=masterkey_file.masterkey_guid,
                        encrypted_key_usercred=masterkey_file.master_key,
                        encrypted_key_backup=masterkey_file.domain_backup_key,
                    )

                    # The DPAPI manager handles all decryption automatically
                    await self.dpapi_manager.upsert_masterkey(mk)

                    # Check if it was decrypted
                    stored_mk = await self.dpapi_manager.get_masterkey(masterkey_file.masterkey_guid)
                    was_decrypted = stored_mk and stored_mk.is_decrypted

                    if was_decrypted:
                        logger.info(f"Successfully processed and decrypted masterkey {masterkey_file.masterkey_guid}")
                    else:
                        logger.debug(
                            f"Successfully processed masterkey {masterkey_file.masterkey_guid} (not decrypted - may need additional keys)"
                        )
                else:
                    logger.warning("[dpapi_masterkey] self.dpapi_manager not initialized!")

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

    def _parse_masterkey_file(self, file_path: str) -> MasterKeyFile | None:
        """Parse a masterkey file using nemesis_dpapi.

        Args:
            file_path: Path to the masterkey file

        Returns:
            Parsed MasterKeyFile or None if parsing fails
        """
        try:
            return MasterKeyFile.parse(file_path)
        except Exception as e:
            logger.warning(f"Failed to parse masterkey file {file_path}: {e}")
            return None


def create_enrichment_module(standalone: bool = False) -> EnrichmentModule:
    """Factory function that creates the analyzer in either standalone or service mode."""
    return DPAPIMasterkeyAnalyzer(standalone=standalone)

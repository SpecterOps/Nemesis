# enrichment_modules/chromium_logins/analyzer.py

import asyncio
from typing import TYPE_CHECKING

import yara_x
from chromium import process_chromium_local_state
from common.logger import get_logger
from common.models import EnrichmentResult
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from dapr.clients import DaprClient
from file_enrichment_modules.module_loader import EnrichmentModule
from nemesis_dpapi import DpapiManager

if TYPE_CHECKING:
    from nemesis_dpapi import DpapiManager

logger = get_logger(__name__)


class ChromeLocalStateParser(EnrichmentModule):
    def __init__(self):
        super().__init__("chrome_local_state_parser")
        self.storage = StorageMinio()

        # the workflows this module should automatically run in
        self.workflows = ["default"]

        self.dpapi_manager: DpapiManager | None = None

        # Yara rule to check for Chrome Login Data tables
        self.yara_rule = yara_x.compile("""
rule Chrome_Local_State
{
    meta:
        description = "Detects Chrome/Chromium Local State json"

    strings:
        $local_state_1 = "\\"os_crypt\\""
        $local_state_2 = "\\"encrypted_key\\""
        $local_state_3 = "\\"user_experience_metrics\\""

    condition:
        all of them
}
        """)

    def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file
        """

        file_enriched = get_file_enriched(object_id)

        # Check if file is < 5 megs and JSON magic type
        if not ((file_enriched.size < 5000000) and ("json" in file_enriched.magic_type.lower())):
            return False

        if file_path:
            # Use provided file path
            with open(file_path, "rb") as f:
                file_bytes = f.read()
        else:
            # Fallback to downloading the file itself
            file_bytes = self.storage.download_bytes(file_enriched.object_id)

        # Verify Chrome Local State using Yara
        should_run = len(self.yara_rule.scan(file_bytes).matching_rules) > 0

        return should_run

    def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process Chrome Local State files.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file
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
        """Async helper for process method."""

        with DaprClient() as client:
            secret = client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_STRING")
            postgres_connection_string = secret.secret["POSTGRES_CONNECTION_STRING"]

        if not postgres_connection_string.startswith("postgres://"):
            raise ValueError(
                "POSTGRES_CONNECTION_STRING must start with 'postgres://' to be used with the DpapiManager"
            )

        self.dpapi_manager = DpapiManager(storage_backend=postgres_connection_string)
        try:
            # Use the chromium library to process and insert into database
            state_key_data = await process_chromium_local_state(self.dpapi_manager, object_id, file_path)

            # Create enrichment result with parsed data
            enrichment = EnrichmentResult(module_name=self.name)
            enrichment.results = {"parsed": state_key_data}

            return enrichment

        except Exception as e:
            logger.exception(e, message="Error processing Chrome Local State file")


def create_enrichment_module() -> EnrichmentModule:
    return ChromeLocalStateParser()

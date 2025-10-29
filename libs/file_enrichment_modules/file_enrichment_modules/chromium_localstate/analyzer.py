# enrichment_modules/chromium_logins/analyzer.py

from typing import TYPE_CHECKING

import yara_x
from chromium import process_chromium_local_state
from common.logger import get_logger
from common.models import EnrichmentResult
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule
from nemesis_dpapi import DpapiManager

if TYPE_CHECKING:

    from nemesis_dpapi import DpapiManager

logger = get_logger(__name__)


class ChromeLocalStateParser(EnrichmentModule):
    name: str = "chrome_local_state_parser"
    dependencies: list[str] = []

    def __init__(self):
        self.storage = StorageMinio()

        # the workflows this module should automatically run in
        self.workflows = ["default"]

        self.dpapi_manager: DpapiManager = None  # type: ignore
        self.asyncpg_pool = None  # type: ignore

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

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file
        """

        file_enriched = await get_file_enriched_async(object_id)

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

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Async helper for process method."""

        try:
            # Use the chromium library to process and insert into database
            state_key_data = await process_chromium_local_state(
                self.dpapi_manager, object_id, file_path, self.asyncpg_pool
            )

            if state_key_data:
                # Debug: Check for coroutines in state_key_data
                import inspect

                for key, value in state_key_data.items():
                    if inspect.iscoroutine(value):
                        logger.error(f"FOUND COROUTINE IN state_key_data['{key}']!")

                enrichment = EnrichmentResult(module_name=self.name)
                enrichment.results = {"parsed": state_key_data}

                return enrichment

        except Exception:
            logger.exception(message="Error processing Chrome Local State file")


def create_enrichment_module() -> EnrichmentModule:
    return ChromeLocalStateParser()

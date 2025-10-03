# enrichment_modules/dpapi/analyzer.py
import asyncio

import yara_x
from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from dapr.clients import DaprClient
from file_enrichment_modules.dpapi_blob.dpapi_helpers import carve_dpapi_blobs_from_file
from file_enrichment_modules.module_loader import EnrichmentModule
from nemesis_dpapi import Blob, BlobDecryptionError, DpapiManager, MasterKeyNotDecryptedError, MasterKeyNotFoundError

logger = get_logger(__name__)


class DpapiBlobAnalyzer(EnrichmentModule):
    def __init__(self, standalone: bool = False):
        super().__init__("dpapi_analyzer")
        self.storage = StorageMinio()
        self.dapr_client = DaprClient()
        self.size_limit = 50000000  # only check the first 50 megs for DPAPI blobs, for performance
        self.max_blobs = 100
        self.dpapi_manager: DpapiManager | None = None
        # the workflows this module should automatically run in
        self.workflows = ["default"]

        # Yara rule to check for DPAPI blob content
        self.yara_rule = yara_x.compile("""
rule has_dpapi_blob
{
    strings:
        $dpapi_header = { 01 00 00 00 D0 8C 9D DF 01 15 D1 11 8C 7A 00 C0 4F C2 97 EB }
        $dpapi_header_b64_1 = "AAAA0Iyd3wEV0RGMegDAT8KX6"
        $dpapi_header_b64_2 = "AQAAANCMnd8BFdERjHoAwE/Cl+"
        $dpapi_header_b64_3 = "EAAADQjJ3fARXREYx6AMBPwpfr"
    condition:
        $dpapi_header or $dpapi_header_b64_1 or $dpapi_header_b64_2 or $dpapi_header_b64_3
}
""")

    def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Check if this file should be processed by scanning for DPAPI blobs.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file
        """
        file_enriched = get_file_enriched(object_id)
        if file_enriched.size > self.size_limit:
            logger.debug(
                f"[dpapi_analyzer] file {file_enriched.path} ({file_enriched.object_id} / {file_enriched.size} bytes) exceeds the size limit of {self.size_limit} bytes, only analyzing the first {self.size_limit} bytes"
            )

        if file_path:
            # Use provided file path - read only the needed bytes
            with open(file_path, "rb") as f:
                num_bytes = min(file_enriched.size, self.size_limit)
                file_bytes = f.read(num_bytes)
        else:
            # Fallback to downloading the file itself
            num_bytes = file_enriched.size if file_enriched.size < self.size_limit else self.size_limit
            file_bytes = self.storage.download_bytes(file_enriched.object_id, length=num_bytes)

        should_run = len(self.yara_rule.scan(file_bytes).matching_rules) > 0
        return should_run

    def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process LSASS dump file and extract credentials.

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
        """Process file in either workflow or standalone mode.

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

        self.dpapi_manager = DpapiManager(storage_backend=postgres_connection_string)

        try:
            file_enriched = get_file_enriched(object_id)

            enrichment_result = EnrichmentResult(module_name=self.name)

            # TODO: handle carving _large_ dpapi blobs + uploading to the datalake

            if file_path:
                # Use provided file path (if file already downloaded)
                carved_blobs = await carve_dpapi_blobs_from_file(file_path, file_enriched.object_id, self.max_blobs)

            else:
                # Fallback to downloading the file itself
                with self.storage.download(file_enriched.object_id) as temp_file:
                    carved_blobs = await carve_dpapi_blobs_from_file(
                        temp_file.name, file_enriched.object_id, self.max_blobs
                    )

            for carved_blob in carved_blobs:
                try:
                    dpapi_blob_raw = carved_blob["dpapi_blob_raw"]
                    del carved_blob["dpapi_blob_raw"]  # because of result serialization
                    carved_blob_dec = await self.dpapi_manager.decrypt_blob(Blob.parse(dpapi_blob_raw))

                    if carved_blob_dec:
                        logger.info(
                            "Successfully decrypted blob",
                            masterkey_guid=carved_blob["dpapi_master_key_guid"],
                            # b64_dec_blob=base64.b64encode(carved_blob_dec).decode("utf-8"),
                        )
                        # TODO: do something with the decrypted blob?
                except BlobDecryptionError as e:
                    logger.warning(
                        f"Could not decrypt local state DPAPI blob with its masterkey. Error: {e}",
                        masterkey_guid=carved_blob["dpapi_master_key_guid"],
                        error_type=type(e).__name__,
                    )
                except (MasterKeyNotDecryptedError, MasterKeyNotFoundError) as e:
                    logger.debug(
                        f"Blob with GUID masterkey {carved_blob['dpapi_master_key_guid']} not decrypted.",
                        reason=type(e).__name__,
                    )
                except Exception as e:
                    logger.warning(
                        f"Unhandled error while decrypting DPAPI blob with masterkey. Error: {e}",
                        masterkey_guid=carved_blob["dpapi_master_key_guid"],
                        error_type=type(e).__name__,
                    )

            masterkey_guids = sorted({blob["dpapi_master_key_guid"] for blob in carved_blobs if blob["success"]})

            if carved_blobs:
                summary_markdown = f"""
# DPAPI Blobs Found : {len(carved_blobs)}
# Masterkey GUIDs
List of unique masterkey GUIDs associated with the found blobs:
```text
{"\n".join(masterkey_guids)}
```
"""
                enrichment_result.results = {"blobs": carved_blobs}

                display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

                finding = Finding(
                    category=FindingCategory.EXTRACTED_DATA,
                    finding_name="dpapi_data",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=file_enriched.object_id,
                    severity=5,
                    raw_data=enrichment_result.results,
                    data=[display_data],
                )

                enrichment_result.findings = [finding]

                return enrichment_result

        except Exception as e:
            logger.exception(e, message="Error in DPAPI process()")


def create_enrichment_module(standalone: bool = False) -> EnrichmentModule:
    """Factory function that creates the analyzer in either standalone or service mode."""
    return DpapiBlobAnalyzer(standalone=standalone)

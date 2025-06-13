# enrichment_modules/dpapi/analyzer.py
import asyncio

import structlog
import yara_x
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from dapr.clients import DaprClient

from file_enrichment_modules.dpapi.dpapi_helpers import carve_dpapi_blobs_from_file
from file_enrichment_modules.module_loader import EnrichmentModule

logger = structlog.get_logger(module=__name__)


class DPAPIAnalyzer(EnrichmentModule):
    def __init__(self, standalone: bool = False):
        super().__init__("dpapi_analyzer")
        self.storage = StorageMinio()
        self.dapr_client = DaprClient()
        self.size_limit = 50000000  # only check the first 50 megs for DPAPI blobs, for performance
        self.max_blobs = 100
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

    def should_process(self, object_id: str) -> bool:
        file_enriched = get_file_enriched(object_id)
        if file_enriched.size > self.size_limit:
            logger.warning(
                f"[dpapi_analyzer] file {file_enriched.path} ({file_enriched.object_id} / {file_enriched.size} bytes) exceeds the size limit of {self.size_limit} bytes, only analyzing the first {self.size_limit} bytes"
            )

        num_bytes = file_enriched.size if file_enriched.size < self.size_limit else self.size_limit
        file_bytes = self.storage.download_bytes(file_enriched.object_id, length=num_bytes)

        should_run = len(self.yara_rule.scan(file_bytes).matching_rules) > 0
        logger.debug(f"[dpapi_analyzer] should_run: {should_run}")
        return should_run

    def process(self, object_id: str) -> EnrichmentResult | None:
        """Process file in either workflow or standalone mode."""
        try:
            file_enriched = get_file_enriched(object_id)

            enrichment_result = EnrichmentResult(module_name=self.name)

            # TODO: handle carving _large_ dpapi blobs + uploading to the datalake

            with self.storage.download(file_enriched.object_id) as temp_file:
                blobs = asyncio.run(
                    carve_dpapi_blobs_from_file(temp_file.name, file_enriched.object_id, self.max_blobs)
                )
                masterkey_guids = sorted(set([blob["dpapi_master_key_guid"] for blob in blobs if blob["success"]]))

                if blobs:
                    summary_markdown = f"""
# DPAPI Blobs Found : {len(blobs)}
# Masterkey GUIDs
List of unique masterkey GUIDs associated with the found blobs:
```text
{"\n".join(masterkey_guids)}
```
"""
                    enrichment_result.results = {"blobs": blobs}

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
    return DPAPIAnalyzer(standalone=standalone)

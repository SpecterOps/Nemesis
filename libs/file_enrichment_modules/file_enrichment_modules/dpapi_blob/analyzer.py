# enrichment_modules/dpapi/analyzer.py
import asyncio
import base64
import csv
import tempfile

import yara_x
from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched, get_file_enriched_async
from common.storage import StorageMinio
from dapr.clients import DaprClient
from file_enrichment_modules.dpapi_blob.dpapi_helpers import carve_dpapi_blobs_from_file
from file_enrichment_modules.module_loader import EnrichmentModule
from nemesis_dpapi import Blob, BlobDecryptionError, DpapiManager, MasterKeyNotDecryptedError, MasterKeyNotFoundError

logger = get_logger(__name__)


class DpapiBlobAnalyzer(EnrichmentModule):
    name: str = "dpapi_analyzer"
    dependencies: list[str] = []
    def __init__(self, standalone: bool = False):
        self.storage = StorageMinio()
        self.dapr_client = DaprClient()
        self.size_limit = 50000000  # only check the first 50 megs for DPAPI blobs, for performance
        self.max_blobs = 100
        self.dpapi_manager: DpapiManager = None  # type: ignore
        self.loop: asyncio.AbstractEventLoop = None  # type: ignore
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

    def _format_hex_dump(self, data: bytes, offset: int = 0) -> str:
        """Generate hexdump-style output for blob data.

        Args:
            data: The bytes to format
            offset: Starting offset for display

        Returns:
            Formatted hex dump string
        """
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            # Pad hex part to align ASCII
            hex_part = hex_part.ljust(48)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'{offset+i:08x}  {hex_part}  {ascii_part}')
        return '\n'.join(lines)

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Check if this file should be processed by scanning for DPAPI blobs.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file
        """
        file_enriched = await get_file_enriched_async(object_id)
        logger.debug(f"File {object_id} should be processed by DPAPI blob analyzer")
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

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process file in either workflow or standalone mode.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file
        """

        try:
            logger.info(f"Starting DPAPI blob analysis for object_id {object_id}")
            file_enriched = await get_file_enriched_async(object_id)
            logger.info(f"Retrieved enriched file data for object_id {object_id}")

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

            # Track decrypted blobs and their data
            decrypted_blobs = []

            for carved_blob in carved_blobs:
                try:
                    dpapi_blob_raw = carved_blob["dpapi_blob_raw"]
                    carved_blob["is_decrypted"] = False
                    carved_blob["decrypted_data"] = None
                    # Calculate blob length from raw data
                    carved_blob["blob_length"] = len(dpapi_blob_raw) if dpapi_blob_raw else 0

                    carved_blob_dec = await self.dpapi_manager.decrypt_blob(Blob.from_bytes(dpapi_blob_raw))

                    if carved_blob_dec:
                        carved_blob["is_decrypted"] = True
                        carved_blob["decrypted_data"] = carved_blob_dec
                        decrypted_blobs.append(carved_blob)
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

                # Remove raw blob data to avoid serialization issues
                del carved_blob["dpapi_blob_raw"]

            masterkey_guids = sorted({blob["dpapi_master_key_guid"] for blob in carved_blobs if blob["success"]})

            if carved_blobs:
                transforms = []

                # Create CSV transform for all blobs (up to 10000)
                blobs_for_csv = carved_blobs[:10000]
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="") as tmp_csv:
                    writer = csv.writer(tmp_csv)

                    # Write header
                    writer.writerow(["masterkey_guid", "blob_offset", "blob_length", "is_decrypted", "base64_content"])

                    # Write blob data
                    for blob in blobs_for_csv:
                        base64_content = ""
                        # Include base64 content if blob is 1000 bytes or less
                        if blob.get("decrypted_data") and len(blob["decrypted_data"]) <= 1000:
                            base64_content = base64.b64encode(blob["decrypted_data"]).decode("utf-8")

                        writer.writerow([
                            blob["dpapi_master_key_guid"],
                            blob.get("blob_offset", 0),
                            blob.get("blob_length", 0),
                            blob.get("is_decrypted", False),
                            base64_content,
                        ])

                    tmp_csv.flush()
                    csv_object_id = self.storage.upload_file(tmp_csv.name)

                    transforms.append(
                        Transform(
                            type="dpapi_blobs.csv",
                            object_id=f"{csv_object_id}",
                            metadata={
                                "file_name": f"{file_enriched.file_name}_dpapi_blobs.csv",
                                "offer_as_download": True,
                            },
                        )
                    )

                # Create markdown transform for decrypted blobs (up to 1000)
                if decrypted_blobs:
                    report_lines = []
                    report_lines.append(f"# Decrypted DPAPI Blobs: {file_enriched.file_name}")
                    report_lines.append(f"\nTotal decrypted blobs: {len(decrypted_blobs)}")

                    blobs_for_markdown = decrypted_blobs[:1000]

                    for idx, blob in enumerate(blobs_for_markdown, 1):
                        report_lines.append(f"\n## Blob {idx}")
                        report_lines.append(f"- **Masterkey GUID**: `{blob['dpapi_master_key_guid']}`")
                        report_lines.append(f"- **Offset**: {blob.get('blob_offset', 0)}")
                        report_lines.append(f"- **Length**: {blob.get('blob_length', 0)} bytes")

                        if blob.get("decrypted_data"):
                            if len(blob["decrypted_data"]) <= 1000:
                                report_lines.append("```")
                                report_lines.append(self._format_hex_dump(blob["decrypted_data"]))
                                report_lines.append("```")
                            else:
                                report_lines.append("\n*Blob is > 1000 bytes*")

                    # Add truncation notice if needed
                    if len(decrypted_blobs) > 1000:
                        report_lines.append("\n---")
                        report_lines.append("\n**Note**: Over 1000 blobs carved, output truncated")

                    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_md:
                        tmp_md.write("\n".join(report_lines))
                        tmp_md.flush()
                        md_object_id = self.storage.upload_file(tmp_md.name)

                        transforms.append(
                            Transform(
                                type="dpapi_decrypted_blobs",
                                object_id=f"{md_object_id}",
                                metadata={
                                    "file_name": f"{file_enriched.file_name}_decrypted_blobs.md",
                                    "display_type_in_dashboard": "markdown",
                                    "default_display": True,
                                },
                            )
                        )

                enrichment_result.transforms = transforms

                summary_markdown = f"""
# DPAPI Blobs Found : {len(carved_blobs)}
# Masterkey GUIDs
List of unique masterkey GUIDs associated with the found blobs:
```text
{"\n".join(masterkey_guids)}
```
"""
                # Clean up decrypted_data before storing in results to avoid serialization issues
                results_blobs = []
                for blob in carved_blobs:
                    blob_copy = blob.copy()
                    if "decrypted_data" in blob_copy:
                        del blob_copy["decrypted_data"]
                    results_blobs.append(blob_copy)

                enrichment_result.results = {"blobs": results_blobs}

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

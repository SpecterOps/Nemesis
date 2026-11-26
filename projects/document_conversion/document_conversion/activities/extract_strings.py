"""Text extraction activities."""

import asyncio
import os
import tempfile

import document_conversion.global_vars as global_vars
from common.helpers import as_uuid
from common.logger import get_logger
from common.models import Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageS3
from common.workflows.setup import workflow_activity
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext

logger = get_logger(__name__)

storage = StorageS3()


@workflow_activity
async def extract_strings(ctx: WorkflowActivityContext, file_input: dict) -> dict | None:
    """Runs "strings" on a binary to extract strings."""

    assert global_vars.tracking_service is not None, "tracking_service must be initialized"

    object_id = as_uuid(file_input.get("object_id"))

    try:
        file_enriched = await get_file_enriched_async(object_id, global_vars.asyncpg_pool)

        if file_enriched.is_container:
            return None

        with storage.download(file_enriched.object_id) as temp_file:
            # Create temp file for streaming strings output
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as tmp_file:
                tmp_file_path = tmp_file.name

                # Stream strings directly to temp file with filtering
                await extract_all_strings(temp_file.name, tmp_file, min_len=5)

                if os.path.getsize(tmp_file_path) == 0:
                    logger.info("Temporary strings file is empty", object_id=file_enriched.object_id)
                    return None

                object_id = storage.upload_file(tmp_file_path)

        transform = Transform(
            type="extracted_strings",
            object_id=object_id,
            metadata={
                "file_name": "strings.txt",
                "display_type_in_dashboard": "monaco",
                "display_title": "Strings",
            },
        )

        # Record success in database
        await global_vars.tracking_service.update_enrichment_results(
            instance_id=ctx.workflow_id,
            success_list=["extract_strings"],
        )

        logger.debug(
            "String extraction completed successfully",
            object_id=file_enriched.object_id,
            transform_object_id=transform.object_id,
        )

        return transform.model_dump()

    except Exception as e:
        logger.exception(message="Error extracting strings", object_id=object_id)

        # Record failure in database
        try:
            await global_vars.tracking_service.update_enrichment_results(
                instance_id=ctx.workflow_id,
                failure_list=[f"extract_strings:{str(e)[:100]}"],
            )
        except Exception as db_error:
            logger.error(f"Failed to update extract_strings module failure in database: {str(db_error)}")

        raise


_READ_CHUNK = 1024 * 1024


def _write_strings(output_file, lines: list[bytes]) -> None:
    """Write the non-blank lines (decoded, without line endings), one per line."""
    kept = [text for text in (line.decode("utf-8").rstrip("\r") for line in lines) if text.strip()]
    if kept:
        output_file.write("\n".join(kept) + "\n")


async def extract_all_strings(filename: str, output_file, min_len: int = 5):
    """
    Extracts all single-byte ASCII strings and UTF-16 (both LE and BE) strings
    from a file using the `strings` utility, streaming filtered results directly
    to the output file.

    Args:
        filename: Path to the file to extract strings from
        output_file: File handle to write filtered strings to
        min_len: Minimum string length to extract (default: 5)
    """
    commands = [
        ["strings", "-a", "-n", str(min_len), filename],  # ASCII
        ["strings", "-a", "-n", str(min_len), "-e", "l", filename],  # UTF-16 LE
        ["strings", "-a", "-n", str(min_len), "-e", "b", filename],  # UTF-16 BE
    ]

    for cmd in commands:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=1024 * 1024 * 10,  # 10MB buffer
        )

        # Stream the output in large chunks (one await per line cost more CPU than the filtering itself)
        assert process.stdout is not None, "stdout must not be None when PIPE is used"
        partial = b""
        while chunk := await process.stdout.read(_READ_CHUNK):
            lines = (partial + chunk).split(b"\n")
            partial = lines.pop()  # incomplete last line: completed by the next chunk
            _write_strings(output_file, lines)
        _write_strings(output_file, [partial])

        # Wait for the process to complete
        await process.wait()

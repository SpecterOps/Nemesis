"""Plaintext file handling activity."""

import io
import json
from uuid import UUID

from common.helpers import as_uuid, create_text_reader
from common.logger import get_logger
from common.models import TitusInput
from common.queues import TITUS_INPUT_TOPIC, TITUS_PUBSUB
from common.state_helpers import get_file_enriched_async
from common.workflows.setup import workflow_activity
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext

from .. import global_vars

logger = get_logger(__name__)

# Upper bound on the UTF-8 size of one plaintext_content row. The table's generated to_tsvector() column fails above
# PostgreSQL's 1 MB tsvector limit, which counts every lexeme plus its 4-byte entry header and 2-byte positions. Short
# unique tokens (log or CSV IDs) expand roughly 2-3x, so ~600 KB of such text already overflows; 100 KB keeps even a
# worst-case chunk well under the limit.
PLAINTEXT_CHUNK_MAX_BYTES = 100_000


@workflow_activity
async def handle_file_if_plaintext(ctx: WorkflowActivityContext, activity_input) -> dict:
    """
    Activity to index a file's contents if it's plaintext and send a pub/sub message to Titus.

    Errors are caught and reported in the result instead of raised, so a file that can't be indexed still gets its
    Titus scan, and the rest of the workflow (alerts, document conversion) still runs.

    Returns:
        {"indexed": bool, "titus_submitted": bool, "errors": [str, ...]}
    """
    object_id = as_uuid(activity_input["object_id"])
    result: dict = {"indexed": False, "titus_submitted": False, "errors": []}

    logger.info("Executing activity: handle_file_if_plaintext", object_id=object_id)

    try:
        file_enriched = await get_file_enriched_async(object_id, global_vars.asyncpg_pool)
    except Exception as e:
        logger.exception(message="Could not load file metadata for plaintext handling", object_id=object_id)
        result["errors"].append(f"metadata: {e}")
        await _record_failure(ctx, "plaintext_index")
        return result

    # if the file is plaintext, make sure we index it
    if file_enriched.is_plaintext:
        try:
            with await global_vars.storage.download_async(object_id) as tmp_file:
                with open(tmp_file.name, "rb") as binary_file:
                    with create_text_reader(binary_file) as text_file:
                        await index_plaintext_content(object_id, text_file)
            result["indexed"] = True
        except Exception as e:
            logger.exception(message="Plaintext indexing failed; continuing with the Titus scan", object_id=object_id)
            result["errors"].append(f"index: {e}")
            await _record_failure(ctx, "plaintext_index")

    # Submit the file to Titus
    try:
        titus_input = TitusInput(
            object_id=object_id, workflow_id=ctx.workflow_id, original_path=file_enriched.path or ""
        )
        await global_vars.get_dapr_client().publish_event(
            pubsub_name=TITUS_PUBSUB,
            topic_name=TITUS_INPUT_TOPIC,
            data=json.dumps(titus_input.model_dump()),
            data_content_type="application/json",
        )
        result["titus_submitted"] = True
    except Exception as e:
        logger.exception(message="Failed to submit file to Titus", object_id=object_id)
        result["errors"].append(f"titus: {e}")
        await _record_failure(ctx, "titus_submit")

    return result


async def _record_failure(ctx: WorkflowActivityContext, name: str) -> None:
    """Best-effort: list the failed step on the workflow record so it shows in the UI."""
    try:
        if global_vars.tracking_service is not None:
            await global_vars.tracking_service.update_enrichment_results(ctx.workflow_id, failure_list=[name])
    except Exception:
        logger.warning("Could not record plaintext step failure", step=name, instance_id=ctx.workflow_id)


async def index_plaintext_content(
    object_id: UUID, file_obj: io.TextIOWrapper, max_chunk_bytes: int = PLAINTEXT_CHUNK_MAX_BYTES
):
    """Used to index plaintext content with byte-based chunking to avoid tsvector limits"""
    logger.debug(f"indexing plaintext for {object_id}")

    assert global_vars.asyncpg_pool is not None
    async with global_vars.asyncpg_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("DELETE FROM plaintext_content WHERE object_id = $1", object_id)

            chunk_number = 0
            insert_query = """
            INSERT INTO plaintext_content (object_id, chunk_number, content)
            VALUES ($1, $2, $3);
            """

            # Read file content
            file_content = file_obj.read()

            # Sanitize content: PostgreSQL text can't store null bytes or lone surrogates
            file_content = file_content.replace("\x00", "").encode("utf-8", errors="replace").decode("utf-8")

            # Process in chunks of at most max_chunk_bytes UTF-8 bytes, split on character boundaries
            i = 0
            while i < len(file_content):
                encoded = file_content[i : i + max_chunk_bytes].encode("utf-8")
                # Cutting the bytes can split the last character; "ignore" drops only that partial character.
                chunk_content = encoded[:max_chunk_bytes].decode("utf-8", errors="ignore")

                if not chunk_content:
                    break

                actual_bytes = len(chunk_content.encode("utf-8"))
                logger.debug(f"Inserting chunk {chunk_number} with {actual_bytes} bytes")
                await conn.execute(insert_query, object_id, chunk_number, chunk_content)
                chunk_number += 1

                # Continue right after what was stored, so trimmed characters are never skipped
                i += len(chunk_content)

            logger.debug("Indexed chunked content", object_id=object_id, num_chunks=chunk_number)

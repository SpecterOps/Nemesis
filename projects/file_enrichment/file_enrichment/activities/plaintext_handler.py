"""Plaintext file handling activity."""

import io
import json

from common.helpers import create_text_reader
from common.logger import get_logger
from common.models import NoseyParkerInput
from common.queues import NOSEYPARKER_INPUT_TOPIC, NOSEYPARKER_PUBSUB
from common.state_helpers import get_file_enriched_async
from common.workflows.setup import workflow_activity
from dapr.aio.clients import DaprClient
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext

from .. import global_vars

logger = get_logger(__name__)


@workflow_activity
async def handle_file_if_plaintext(ctx: WorkflowActivityContext, activity_input):
    """
    Activity to index a file's contents if it's plaintext and
    send a pub/sub message to NoseyParker
    """
    object_id = activity_input["object_id"]

    logger.info("Executing activity: handle_file_if_plaintext", object_id=object_id)

    file_enriched = await get_file_enriched_async(object_id, global_vars.asyncpg_pool)

    # if the file is plaintext, make sure we index it
    if file_enriched.is_plaintext:
        with global_vars.storage.download(object_id) as tmp_file:
            with open(tmp_file.name, "rb") as binary_file:
                with create_text_reader(binary_file) as text_file:
                    await index_plaintext_content(f"{object_id}", text_file)

    # Submit the file to NoseyParker
    nosey_parker_input = NoseyParkerInput(object_id=object_id, workflow_id=ctx.workflow_id)
    async with DaprClient() as client:
        await client.publish_event(
            pubsub_name=NOSEYPARKER_PUBSUB,
            topic_name=NOSEYPARKER_INPUT_TOPIC,
            data=json.dumps(nosey_parker_input.model_dump()),
            data_content_type="application/json",
        )


async def index_plaintext_content(object_id: str, file_obj: io.TextIOWrapper, max_chunk_bytes: int = 800000):
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

            # Sanitize content: remove null bytes which PostgreSQL text fields cannot store
            file_content = file_content.replace("\x00", "")

            # Process in chunks, ensuring we don't exceed byte limits
            i = 0
            while i < len(file_content):
                # Take a chunk that's guaranteed to be under the byte limit
                chunk_end = min(i + max_chunk_bytes // 4, len(file_content))  # Div by 4 for worst-case UTF-8
                chunk_content = file_content[i:chunk_end]

                # If chunk is still too big in bytes, trim it down
                while len(chunk_content.encode("utf-8")) > max_chunk_bytes and chunk_content:
                    chunk_content = chunk_content[:-100]  # Remove 100 chars at a time

                if chunk_content:  # Only insert non-empty chunks
                    actual_bytes = len(chunk_content.encode("utf-8"))
                    logger.debug(f"Inserting chunk {chunk_number} with {actual_bytes} bytes")
                    await conn.execute(insert_query, object_id, chunk_number, chunk_content)
                    chunk_number += 1

                # Move to next chunk
                i = chunk_end

            logger.debug("Indexed chunked content", object_id=object_id, num_chunks=chunk_number)

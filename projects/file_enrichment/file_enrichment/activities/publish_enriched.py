"""Publish enriched file activity."""

from common.logger import get_logger
from common.models import FileEnriched
from common.queues import (
    DOCUMENT_CONVERSION_INPUT_TOPIC,
    DOCUMENT_CONVERSION_PUBSUB,
    FILES_FILE_ENRICHED_TOPIC,
    FILES_PUBSUB,
)
from common.state_helpers import get_file_enriched_async
from common.workflows.setup import workflow_activity
from dapr.aio.clients import DaprClient
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext

from ..tracing import get_trace_injector

logger = get_logger(__name__)


@workflow_activity
async def publish_enriched_file(ctx: WorkflowActivityContext, object_id: str):
    """
    Activity to publish enriched file data to pubsub after retrieving from state store.
    """
    from .. import global_vars

    file_enriched = await get_file_enriched_async(object_id, global_vars.asyncpg_pool)
    logger.info("Executing activity: publish_enriched_file", object_id=object_id)

    try:
        async with DaprClient(headers_callback=get_trace_injector()) as client:
            json_data = file_enriched.model_dump_json(
                exclude_unset=True,
            )

            # Broadcast that a new file has been enriched
            await client.publish_event(
                pubsub_name=FILES_PUBSUB,
                topic_name=FILES_FILE_ENRICHED_TOPIC,
                data=json_data,
            )

            # Submit to document_conversion if applicable
            if should_convert_document(file_enriched):
                logger.debug("Sending enriched doc to document converter")
                await client.publish_event(
                    pubsub_name=DOCUMENT_CONVERSION_PUBSUB,
                    topic_name=DOCUMENT_CONVERSION_INPUT_TOPIC,
                    data=json_data,
                    data_content_type="application/json",
                )

            return True

    except Exception:
        logger.exception(message="Error publishing enriched file data", object_id=object_id)
        # Don't raise to ensure workflow can complete
        return False


def should_convert_document(enriched: FileEnriched):
    """
    Determine if the file should be processed based on its metadata.

    Specifically, check:
     1) if it's plaintext, don't submit
     2) if no originating_object_id (so is an original submission - not derived from anything else), submit it
     3) if it does does it have a nesting level, meaning it's derived from a container and NOT from
    some type of already processed transform (e.g., so we don't extract text from a PDF converted from an office doc).
    """

    if enriched.is_plaintext:
        return False

    # Original files (didn't originate from anything else)
    if not enriched.originating_object_id:
        return True

    # Don't want to submit transforms. e.g. a .doc converted to a .pdf (otherwise we'll double process)
    if enriched.is_transform():
        return False

    if enriched.is_extracted_from_archive():
        return True

    return True

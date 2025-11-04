"""Publish enriched file activity."""

import json

from common.logger import get_logger
from common.queues import FILES_FILE_ENRICHED_TOPIC, FILES_PUBSUB
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
            data = file_enriched.model_dump(
                exclude_unset=True,
                mode="json",
            )

            # Publish to pubsub
            await client.publish_event(
                pubsub_name=FILES_PUBSUB,
                topic_name=FILES_FILE_ENRICHED_TOPIC,
                data=json.dumps(data),
                data_content_type="application/json",
            )

            # Update workflow status to COMPLETED after successful publish
            instance_id = ctx.workflow_id
            await global_vars.workflow_manager.tracking_service.update_status(
                instance_id=instance_id, status="COMPLETED"
            )

            return True

    except Exception:
        logger.exception(message="Error publishing enriched file data", object_id=object_id)
        # Don't raise to ensure workflow can complete
        return False

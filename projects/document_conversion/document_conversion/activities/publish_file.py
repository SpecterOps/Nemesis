"""Storage and publishing activities."""

import document_conversion.global_vars as global_vars
from common.logger import get_logger
from common.models import File, Transform
from common.queues import FILES_NEW_FILE_TOPIC, FILES_PUBSUB
from common.state_helpers import get_file_enriched_async
from common.workflows.setup import workflow_activity
from dapr.aio.clients import DaprClient
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext

logger = get_logger(__name__)


@workflow_activity
async def publish_file_message(ctx: WorkflowActivityContext, activity_input: dict):
    """Publish a new file message for the transform as a Dapr activity."""
    try:
        object_id = activity_input["object_id"]
        transform = Transform.model_validate(activity_input["transform"])

        file_enriched = await get_file_enriched_async(object_id, global_vars.asyncpg_pool)

        assert transform.object_id is not None, "transform.object_id must not be None"
        assert transform.metadata is not None, "transform.metadata must not be None"

        new_file = File(
            object_id=transform.object_id,
            originating_object_id=file_enriched.object_id,
            agent_id=file_enriched.agent_id,
            source=file_enriched.source,
            project=file_enriched.project,
            timestamp=file_enriched.timestamp,
            expiration=file_enriched.expiration,
            path=f"{file_enriched.path}/{transform.metadata['file_name']}",
        )

        async with DaprClient() as client:
            await client.publish_event(
                pubsub_name=FILES_PUBSUB,
                topic_name=FILES_NEW_FILE_TOPIC,
                data=new_file.model_dump_json(),
                data_content_type="application/json",
            )

        logger.info(
            "Published new file message for transform",
            new_object_id=transform.object_id,
            originating_object_id=file_enriched.object_id,
        )
    except Exception:
        logger.exception(message="Error publishing file message")
        raise

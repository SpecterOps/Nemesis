import json
from datetime import datetime

from common.logger import get_logger
from common.queues import WORKFLOW_MONITOR_COMPLETED_TOPIC, WORKFLOW_MONITOR_PUBSUB
from dapr.aio.clients import DaprClient

from .tracing import get_trace_injector

logger = get_logger(__name__)


async def publish_workflow_completion(instance_id, completed=True):
    """
    Publish workflow completion event for container tracking.

    These events are consumed by the web_api so we can track the state of
    large container processing.

    Args:
        instance_id: The workflow instance ID
        completed: True if workflow completed successfully, False if failed
    """

    from . import global_vars

    assert global_vars.asyncpg_pool is not None
    try:
        async with global_vars.asyncpg_pool.acquire() as conn:
            # Get workflow data with a single optimized JOIN query
            row = await conn.fetchrow(
                """
                SELECT
                    w.object_id,
                    COALESCE(fe.originating_container_id, f.originating_container_id) as originating_container_id,
                    COALESCE(fe.size, 0) as file_size
                FROM workflows w
                LEFT JOIN files_enriched fe ON fe.object_id = w.object_id
                LEFT JOIN files f ON f.object_id = w.object_id
                WHERE w.wf_id = $1
                """,
                instance_id,
            )

            if not row or not row["object_id"]:
                object_id, originating_container_id, file_size = None, None, 0
            else:
                object_id = row["object_id"]
                originating_container_id = row["originating_container_id"]
                file_size = row["file_size"] or 0
        logger.debug(
            f"publish_workflow_completion - object_id: {object_id}, originating_container_id: {originating_container_id}, file_size: {file_size}",
        )

        # Only publish if we have a container ID to track
        if object_id and originating_container_id:
            async with DaprClient(headers_callback=get_trace_injector()) as client:
                completion_data = {
                    "object_id": str(object_id),
                    "originating_container_id": str(originating_container_id),
                    "workflow_id": instance_id,
                    "completed": completed,
                    "file_size": file_size,
                    "timestamp": datetime.now().isoformat(),
                }

                await client.publish_event(
                    pubsub_name=WORKFLOW_MONITOR_PUBSUB,
                    topic_name=WORKFLOW_MONITOR_COMPLETED_TOPIC,
                    data=json.dumps(completion_data),
                    data_content_type="application/json",
                )

                logger.debug(
                    "Published workflow completion event",
                    object_id=object_id,
                    container_id=originating_container_id,
                    completed=completed,
                    workflow_id=instance_id,
                )

    except Exception as e:
        logger.error("Error publishing workflow completion event", workflow_id=instance_id, error=str(e))

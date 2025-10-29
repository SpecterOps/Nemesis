"""Publish enriched file activity."""

import json

from common.logger import get_logger
from common.state_helpers import get_file_enriched_async
from common.workflows.setup import workflow_activity
from dapr.clients import DaprClient
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext

from ..tracing import get_trace_injector

logger = get_logger(__name__)


@workflow_activity
async def publish_enriched_file(ctx: WorkflowActivityContext, object_id: str):
    """
    Activity to publish enriched file data to pubsub after retrieving from state store.
    """

    file_enriched = await get_file_enriched_async(object_id)

    try:
        with DaprClient(headers_callback=get_trace_injector()) as client:
            data = file_enriched.model_dump(
                exclude_unset=True,
                mode="json",
            )

            # Publish to pubsub
            client.publish_event(
                pubsub_name="pubsub",
                topic_name="file_enriched",
                data=json.dumps(data),
                data_content_type="application/json",
            )

            return True

    except Exception:
        logger.exception(message="Error publishing enriched file data", object_id=object_id)
        # Don't raise to ensure workflow can complete
        return False

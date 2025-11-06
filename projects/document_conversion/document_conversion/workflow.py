"""Workflow definitions for document conversion."""

from datetime import timedelta

from common.logger import get_logger
from common.workflows.setup import wf_runtime
from dapr.ext.workflow import DaprWorkflowContext, RetryPolicy, when_all

from .activities.extract_strings import extract_strings
from .activities.extract_text import extract_text
from .activities.pdf_conversion import convert_to_pdf
from .activities.publish_file import publish_file_message
from .activities.store_transform import store_transform

logger = get_logger(__name__)


@wf_runtime.workflow
def document_conversion_workflow(ctx: DaprWorkflowContext, workflow_input: dict):
    """Main workflow for document conversion processing."""
    try:
        object_id = workflow_input["object_id"]

        if not ctx.is_replaying:
            logger.info("Document conversion workflow has started", object=object_id)

        # Define retry policy for extraction activities
        retry_policy = RetryPolicy(
            first_retry_interval=timedelta(seconds=10),
            max_retry_interval=timedelta(seconds=50),
            backoff_coefficient=2.0,
            max_number_of_attempts=3,
            retry_timeout=timedelta(minutes=10),
        )

        # Run all extraction methods in parallel
        enrichment_tasks = [
            ctx.call_activity(
                extract_text,
                input={"object_id": object_id},
                retry_policy=retry_policy,
            ),
            ctx.call_activity(
                extract_strings,
                input={"object_id": object_id},
                retry_policy=retry_policy,
            ),
            ctx.call_activity(
                convert_to_pdf,
                input={"object_id": object_id},
                retry_policy=retry_policy,
            ),
        ]

        # Wait for all extraction tasks to complete
        results = yield when_all(enrichment_tasks)

        valid_transforms = [result for result in results if result is not None]

        if valid_transforms:
            # For each transform, create parallel tasks for storing and publishing
            store_and_publish_tasks = []
            for transform in valid_transforms:
                store_and_publish_tasks.append(
                    ctx.call_activity(
                        store_transform,
                        input={"object_id": object_id, "transform": transform},
                        retry_policy=retry_policy,
                    )
                )

                store_and_publish_tasks.append(
                    ctx.call_activity(
                        publish_file_message,
                        input={"object_id": object_id, "transform": transform},
                        retry_policy=retry_policy,
                    )
                )

            # Wait for all store and publish tasks to complete
            yield when_all(store_and_publish_tasks)

        return {"status": "completed", "transforms_count": len(valid_transforms)}

    except Exception:
        logger.exception(message="Error in document conversion workflow")
        raise


def initialize_workflow_runtime():
    """Initialize and start the workflow runtime."""
    # Activities are auto-registered via @workflow_activity decorator
    # Workflow is auto-registered via @wf_runtime.workflow decorator
    wf_runtime.start()
    logger.info("Workflow runtime initialized and started")

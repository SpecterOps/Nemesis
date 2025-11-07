"""Workflow definitions for document conversion."""

from datetime import timedelta

from common.logger import get_logger
from common.workflows.setup import wf_runtime
from dapr.ext.workflow import DaprWorkflowContext, RetryPolicy, when_all

from .activities.extract_strings import extract_strings
from .activities.extract_text import extract_text
from .activities.finalize_workflow import (
    finalize_workflow_failure,
    finalize_workflow_success,
    update_workflow_status_to_running,
)
from .activities.pdf_conversion import convert_to_pdf
from .activities.publish_file import publish_file_message
from .activities.store_transform import store_transform

logger = get_logger(__name__)


@wf_runtime.workflow
def document_conversion_workflow(ctx: DaprWorkflowContext, workflow_input: dict):
    """Main workflow for document conversion processing."""
    start_time = ctx.current_utc_datetime

    try:
        object_id = workflow_input["object_id"]

        if not ctx.is_replaying:
            logger.info("Document conversion workflow has started", object=object_id)

        # Update workflow status to RUNNING
        yield ctx.call_activity(
            update_workflow_status_to_running,
            input={},
        )

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

        # Mark workflow as completed
        yield ctx.call_activity(
            finalize_workflow_success,
            input={"start_time": start_time.isoformat()},
        )

        return {"status": "completed", "transforms_count": len(valid_transforms)}

    except Exception as e:
        logger.exception(message="Error in document conversion workflow")

        # Mark workflow as failed
        try:
            yield ctx.call_activity(
                finalize_workflow_failure,
                input={
                    "error_message": str(e)[:200],
                    "start_time": start_time.isoformat(),
                },
            )
        except Exception:
            logger.error("Failed to finalize workflow failure status")

        raise

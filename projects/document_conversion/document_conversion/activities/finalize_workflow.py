"""Workflow finalization activity."""

import document_conversion.global_vars as global_vars
from common.logger import get_logger
from common.workflows.setup import workflow_activity
from common.workflows.tracking_service import WorkflowStatus
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext

logger = get_logger(__name__)


@workflow_activity
async def update_workflow_status_to_running(ctx: WorkflowActivityContext, activity_input: dict) -> None:
    """Mark workflow as running.

    Args:
        activity_input: Dict (currently unused, but kept for consistency)
    """
    instance_id = ctx.workflow_id

    logger.info(
        "Updating workflow status to RUNNING",
        instance_id=instance_id,
    )

    try:
        await global_vars.tracking_service.update_status(
            instance_id=instance_id,
            status=WorkflowStatus.RUNNING,
        )
    except Exception as e:
        logger.error(
            "Failed to update workflow status to RUNNING",
            instance_id=instance_id,
            error=str(e),
        )
        # Don't raise - we don't want to fail the workflow just because status update failed


@workflow_activity
async def finalize_workflow_success(ctx: WorkflowActivityContext, activity_input: dict) -> None:
    """Mark workflow as completed successfully.

    Calculates runtime from the database start_time.

    Args:
        activity_input: Dict (unused, kept for consistency)
    """
    instance_id = ctx.workflow_id

    try:
        logger.info(
            "Finalizing workflow as completed",
            instance_id=instance_id,
        )

        await global_vars.tracking_service.finalize_workflow(
            instance_id=instance_id,
        )
    except Exception as e:
        logger.error(
            "Failed to finalize workflow status",
            instance_id=instance_id,
            error=str(e),
        )
        # Don't raise - we don't want to fail the workflow just because status update failed


@workflow_activity
async def finalize_workflow_failure(ctx: WorkflowActivityContext, activity_input: dict) -> None:
    """Mark workflow as failed.

    Args:
        activity_input: Dict containing:
            - error_message: The error message
    """
    instance_id = ctx.workflow_id
    error_message = activity_input.get("error_message", "Unknown error")

    try:
        logger.error(
            "Finalizing workflow as failed",
            instance_id=instance_id,
            error_message=error_message,
        )

        await global_vars.tracking_service.update_status(
            instance_id=instance_id,
            status=WorkflowStatus.FAILED,
            error_message=error_message,
        )
    except Exception as e:
        logger.error(
            "Failed to finalize workflow failure status",
            instance_id=instance_id,
            error=str(e),
        )
        # Don't raise - we don't want to fail the workflow just because status update failed

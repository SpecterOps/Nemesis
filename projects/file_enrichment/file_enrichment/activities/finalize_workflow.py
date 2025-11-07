"""Workflow finalization activities."""

from datetime import datetime

import file_enrichment.global_vars as global_vars
from common.logger import get_logger
from common.workflows.setup import workflow_activity
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
        await global_vars.workflow_manager.tracking_service.update_status(
            instance_id=instance_id,
            status="RUNNING",
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

    Calculates runtime from the provided start_time.

    Args:
        activity_input: Dict containing:
            - start_time: Workflow start time (ISO format string)
    """
    instance_id = ctx.workflow_id
    start_time_str = activity_input.get("start_time")

    try:
        # Calculate runtime
        if start_time_str:
            start_time = datetime.fromisoformat(start_time_str)
            end_time = datetime.now()
            runtime_seconds = (end_time - start_time).total_seconds()
        else:
            logger.warning(
                "No start_time provided, setting runtime to None",
                instance_id=instance_id,
            )
            runtime_seconds = None

        logger.info(
            "Finalizing workflow as completed",
            instance_id=instance_id,
            runtime_seconds=runtime_seconds,
        )

        await global_vars.workflow_manager.tracking_service.update_status(
            instance_id=instance_id,
            status="COMPLETED",
            runtime_seconds=runtime_seconds,
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

    Calculates runtime from the provided start_time.

    Args:
        activity_input: Dict containing:
            - error_message: The error message
            - start_time: Workflow start time (ISO format string)
    """
    instance_id = ctx.workflow_id
    error_message = activity_input.get("error_message", "Unknown error")
    start_time_str = activity_input.get("start_time")

    try:
        # Calculate runtime
        if start_time_str:
            start_time = datetime.fromisoformat(start_time_str)
            end_time = datetime.now()
            runtime_seconds = (end_time - start_time).total_seconds()
        else:
            logger.warning(
                "No start_time provided, setting runtime to None",
                instance_id=instance_id,
            )
            runtime_seconds = None

        logger.error(
            "Finalizing workflow as failed",
            instance_id=instance_id,
            error_message=error_message,
            runtime_seconds=runtime_seconds,
        )

        await global_vars.workflow_manager.tracking_service.update_status(
            instance_id=instance_id,
            status="FAILED",
            runtime_seconds=runtime_seconds,
            error_message=error_message,
        )
    except Exception as e:
        logger.error(
            "Failed to finalize workflow failure status",
            instance_id=instance_id,
            error=str(e),
        )
        # Don't raise - we don't want to fail the workflow just because status update failed

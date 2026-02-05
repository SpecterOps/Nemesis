# src/workflow/workflow_manager.py
import asyncio
import os
from datetime import datetime

import asyncpg
from common.logger import get_logger
from common.models import File, SingleEnrichmentWorkflowInput
from common.workflows.tracking_service import WorkflowStatus
from dapr.ext.workflow.workflow_state import WorkflowStatus as DaprWorkflowStatus

from . import global_vars
from .tracing import get_tracer
from .workflow_completion import publish_workflow_completion

logger = get_logger(__name__)


class WorkflowManager:
    """WorkflowManager for workflow execution."""

    def __init__(self, pool: asyncpg.Pool, max_execution_time=300):
        """Initialize the workflow manager

        Args:
            pool: asyncpg connection pool (externally managed)
            max_execution_time: maximum time (in seconds) until a workflow is killed
        """
        self.max_execution_time = max_execution_time
        self.background_tasks = set()  # Track background tasks to prevent GC
        self.pool = pool

    async def __aenter__(self):
        """Async context manager entry - start background tasks"""

        # Start background cleanup task
        cleanup_task = asyncio.create_task(self._cleanup_loop())
        self.background_tasks.add(cleanup_task)
        cleanup_task.add_done_callback(self.background_tasks.discard)

        logger.info("WorkflowManager fully initialized")

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - cleanup background tasks (pool is externally managed)"""
        logger.info("Cleaning up WorkflowManager...")

        # Cancel all background tasks
        for task in self.background_tasks:
            if not task.done():
                task.cancel()

        # Wait for all tasks to complete/cancel
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)

        self.background_tasks.clear()
        logger.info("WorkflowManager cleanup completed")

        return False  # Don't suppress exceptions

    async def _cleanup_loop(self):
        """Run cleanup_stale_workflows every 60 seconds"""
        while True:
            await asyncio.sleep(60)
            try:
                await self.cleanup_stale_workflows()
            except Exception as e:
                logger.error(f"Background cleanup error: {e}")

    def _get_status_string(self, state_obj):
        """Convert workflow state to string"""
        if state_obj.runtime_status == DaprWorkflowStatus.FAILED:
            logger.warning(
                "Workflow failed",
                instance_id=state_obj.instance_id,
                error=state_obj.failure_details.message if state_obj.failure_details else "Unknown",
            )

        return state_obj.runtime_status.name

    async def cleanup_stale_workflows(self):
        """Clean up workflows that were left running from previous service instances"""
        try:
            async with self.pool.acquire() as conn:
                # Find workflows that have been running for longer than max execution time
                stale_workflows = await conn.fetch(
                    """
                    SELECT wf_id, object_id,
                        EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - start_time)) as runtime_seconds
                    FROM workflows
                    WHERE status = 'RUNNING'
                    AND EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - start_time)) > $1
                """,
                    self.max_execution_time,
                )

            if stale_workflows:
                logger.warning(f"Found {len(stale_workflows)} stale workflows, cleaning up...")

                for wf_id, _object_id, runtime_seconds in stale_workflows:
                    logger.info(f"Cleaning up stale workflow {wf_id}, runtime: {runtime_seconds:.2f}s")

                    # Try to terminate the workflow in Dapr
                    try:
                        await asyncio.to_thread(global_vars.workflow_client.terminate_workflow, wf_id)
                    except Exception as e:
                        logger.warning(f"Could not terminate workflow {wf_id}: {e}")

                    # Update database status using tracking service
                    assert global_vars.tracking_service is not None
                    await global_vars.tracking_service.update_status(
                        wf_id,
                        WorkflowStatus.TIMEOUT,
                        error_message="cleaned up by cleanup_stale_workflows",
                    )

                    # Publish completion event for large container processing
                    await publish_workflow_completion(wf_id, completed=False)

        except Exception as e:
            logger.error(f"Error during stale workflow cleanup: {e}")

    async def reset(self):
        """Reset the workflow manager's state."""
        try:
            async with self.pool.acquire() as conn:
                await conn.execute("DELETE FROM workflows")
        except Exception:
            logger.exception(message="Error resetting workflows in database")

        logger.info("WorkflowManager reset")

        return {
            "status": "success",
            "message": "Workflow manager reset successfully",
            "timestamp": datetime.now().isoformat(),
        }

    async def run_workflow(self, file: File):
        """Start a workflow"""
        from .workflow import enrichment_pipeline_workflow

        tracer = get_tracer()

        object_id = file.object_id
        base_filename = os.path.basename(file.path) if file.path else None

        with tracer.start_as_current_span("start_workflow") as current_span:
            current_span.set_attribute("workflow.type", "enrichment_workflow")
            current_span.set_attribute("workflow.object_id", object_id)

            try:
                # Start tracking workflow in database
                assert global_vars.tracking_service is not None
                instance_id = await global_vars.tracking_service.register_workflow(
                    object_id=object_id,
                    filename=base_filename,
                )

                logger.info(
                    "Scheduling workflow",
                    instance_id=instance_id,
                    object_id=object_id,
                )

                current_span.set_attribute("workflow.instance_id", instance_id)

                # Schedule the workflow in Dapr
                await asyncio.to_thread(
                    global_vars.workflow_client.schedule_new_workflow,
                    instance_id=instance_id,
                    workflow=enrichment_pipeline_workflow,
                    input=file.model_dump(exclude_unset=True),
                )

                # await asyncio.to_thread(global_vars.workflow_client.wait_for_workflow_completion, instance_id)

                return instance_id

            except Exception:
                logger.exception(message="Error starting workflow")
                raise

    async def run_single_enrichment_workflow(
        self, workflow_input: SingleEnrichmentWorkflowInput | dict[str, str]
    ) -> str:
        """Start a single enrichment workflow

        Args:
            workflow_input: Input for the single enrichment workflow containing
                enrichment_name and object_id

        Returns:
            The workflow instance ID (UUID string without hyphens)

        Raises:
            Exception: If workflow scheduling fails
        """
        tracer = get_tracer()

        try:
            # Normalize input to SingleEnrichmentWorkflowInput if dict
            if isinstance(workflow_input, dict):
                workflow_input = SingleEnrichmentWorkflowInput(**workflow_input)

            # Extract metadata for tracking
            object_id = workflow_input.object_id
            enrichment_name = workflow_input.enrichment_name
            filename = f"bulk:{enrichment_name} ({object_id})"

            with tracer.start_as_current_span("start_single_enrichment_workflow") as span:
                span.set_attribute("workflow.start", True)
                span.set_attribute("workflow.type", "single_enrichment_workflow")
                span.set_attribute("workflow.enrichment_name", enrichment_name)
                span.set_attribute("workflow.object_id", object_id)

                # Start tracking workflow in database
                assert global_vars.tracking_service is not None
                instance_id = await global_vars.tracking_service.register_workflow(
                    object_id=object_id,
                    filename=filename,
                )

                # Add workflow ID to trace for Jaeger queries
                span.set_attribute("workflow.instance_id", instance_id)

                logger.debug(
                    "Triggering single enrichment workflow",
                    instance_id=instance_id,
                    enrichment_name=enrichment_name,
                    object_id=object_id,
                )

                # Actually schedule the workflow
                # Import here to avoid circular import
                from .workflow import single_enrichment_workflow

                # Convert Pydantic model to dict for Dapr workflow
                workflow_input_dict = (
                    workflow_input.model_dump()
                    if isinstance(workflow_input, SingleEnrichmentWorkflowInput)
                    else workflow_input
                )

                # Use asyncio.to_thread() to prevent blocking the event loop
                await asyncio.to_thread(
                    global_vars.workflow_client.schedule_new_workflow,
                    instance_id=instance_id,
                    workflow=single_enrichment_workflow,
                    input=workflow_input_dict,
                )

                return instance_id

        except Exception:
            logger.exception(message="Error starting single enrichment workflow")
            raise

    async def cleanup(self):
        """Clean up background tasks during shutdown (pool is externally managed)"""
        logger.info("Cleaning up WorkflowManager background tasks")

        # Cancel all background tasks
        for task in self.background_tasks:
            if not task.done():
                task.cancel()

        # Wait for all tasks to complete/cancel
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)

        self.background_tasks.clear()

        # Note: Pool is externally managed and will be closed by the caller

        logger.info("WorkflowManager cleanup completed")

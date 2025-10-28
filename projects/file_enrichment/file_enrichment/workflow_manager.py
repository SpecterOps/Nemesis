# src/workflow/workflow_manager.py
import asyncio
import json
import os
import time
import uuid
from datetime import datetime

import asyncpg
from common.logger import get_logger
from common.models import SingleEnrichmentWorkflowInput
from dapr.clients import DaprClient
from dapr.ext.workflow.workflow_state import WorkflowStatus

from .global_vars import workflow_client
from .tracing import get_trace_injector, get_tracer
from .workflow import enrichment_workflow

logger = get_logger(__name__)


class WorkflowManager:
    """WorkflowManager for workflow execution."""

    def __init__(self, pool: asyncpg.Pool, max_execution_time=300):
        """Initialize the workflow manager

        Args:
            pool: asyncpg connection pool (externally managed)
            max_execution_time: maximum time (in seconds) until a workflow is killed
        """
        self.active_workflows = {}  # {instance_id: workflow_info}
        self.lock = asyncio.Lock()  # For synchronizing access to active_workflows
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
        if state_obj.runtime_status == WorkflowStatus.FAILED:
            logger.warning(
                "Workflow failed",
                instance_id=state_obj.instance_id,
                error=state_obj.failure_details.message if state_obj.failure_details else "Unknown",
                pid=os.getpid(),
            )

        return state_obj.runtime_status.name

    async def publish_workflow_completion(self, instance_id, completed=True):
        """
        Publish workflow completion event for container tracking.

        These events are consumed by the web_api so we can track the state of
        large container processing.

        TODO: any way to eliminate the database reads by using the internal state?

        Args:
            instance_id: The workflow instance ID
            completed: True if workflow completed successfully, False if failed
        """

        try:
            async with self.pool.acquire() as conn:
                # Get object_id from workflow
                row = await conn.fetchrow(
                    """
                    SELECT object_id FROM workflows WHERE wf_id = $1
                """,
                    instance_id,
                )

                if not row or not row["object_id"]:
                    object_id, originating_container_id, file_size = None, None, 0
                else:
                    object_id = row["object_id"]

                    # Get originating_container_id and file size from files table
                    file_row = await conn.fetchrow(
                        """
                        SELECT fe.originating_container_id, fe.size
                        FROM files_enriched fe
                        WHERE fe.object_id = $1
                    """,
                        object_id,
                    )

                    if file_row:
                        originating_container_id = file_row["originating_container_id"]
                        file_size = file_row["size"] or 0
                    else:
                        # Fallback to files table if not in files_enriched yet
                        fallback_row = await conn.fetchrow(
                            """
                            SELECT f.originating_container_id, 0 as size
                            FROM files f
                            WHERE f.object_id = $1
                        """,
                            object_id,
                        )

                        if fallback_row:
                            originating_container_id = fallback_row["originating_container_id"]
                            file_size = fallback_row["size"] or 0
                        else:
                            originating_container_id = None
                            file_size = 0
            logger.debug(
                f"publish_workflow_completion - object_id: {object_id}, originating_container_id: {originating_container_id}, file_size: {file_size}",
                pid=os.getpid(),
            )

            # Only publish if we have a container ID to track
            if object_id and originating_container_id:
                with DaprClient(headers_callback=get_trace_injector()) as client:
                    completion_data = {
                        "object_id": str(object_id),
                        "originating_container_id": str(originating_container_id),
                        "workflow_id": instance_id,
                        "completed": completed,
                        "file_size": file_size,
                        "timestamp": datetime.now().isoformat(),
                    }

                    client.publish_event(
                        pubsub_name="pubsub",
                        topic_name="workflow-completed",
                        data=json.dumps(completion_data),
                        data_content_type="application/json",
                    )

                    logger.debug(
                        "Published workflow completion event",
                        object_id=object_id,
                        container_id=originating_container_id,
                        completed=completed,
                        workflow_id=instance_id,
                        pid=os.getpid(),
                    )

        except Exception as e:
            logger.error("Error publishing workflow completion event", workflow_id=instance_id, error=str(e))

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
                        await asyncio.to_thread(workflow_client.terminate_workflow, wf_id)
                    except Exception as e:
                        logger.warning(f"Could not terminate workflow {wf_id}: {e}")

                    # Update database status
                    await self.update_workflow_status(
                        wf_id, "TIMEOUT", runtime_seconds, "cleaned up by cleanup_stale_workflows"
                    )

                    # Publish completion event
                    await self.publish_workflow_completion(wf_id, completed=False)

        except Exception as e:
            logger.error(f"Error during stale workflow cleanup: {e}")

    async def update_workflow_status(self, instance_id, status, runtime_seconds=None, error_message=None):
        """
        Generalized function to update workflow status in database.

        Args:
            instance_id: The workflow instance ID
            status: The status to set (COMPLETED, FAILED, ERROR, TIMEOUT, etc.)
            runtime_seconds: Runtime in seconds (optional)
            error_message: Error message to append to enrichments_failure (optional)
        """

        try:
            async with self.pool.acquire() as conn:
                if error_message:
                    # Update with error message appended to enrichments_failure
                    await conn.execute(
                        """
                        UPDATE workflows
                        SET status = $1,
                            runtime_seconds = COALESCE($2, runtime_seconds),
                            enrichments_failure = array_append(enrichments_failure, $3)
                        WHERE wf_id = $4
                        """,
                        status,
                        runtime_seconds,
                        error_message[:100],
                        instance_id,
                    )
                else:
                    # Update without modifying enrichments_failure
                    await conn.execute(
                        """
                        UPDATE workflows
                        SET status = $1,
                            runtime_seconds = COALESCE($2, runtime_seconds)
                        WHERE wf_id = $3
                        """,
                        status,
                        runtime_seconds,
                        instance_id,
                    )

            logger.debug(
                "Updated workflow status",
                instance_id=instance_id,
                status=status,
                runtime_seconds=runtime_seconds,
                has_error=bool(error_message),
                pid=os.getpid(),
            )
        except Exception as e:
            logger.error(
                "Failed to update workflow status in database",
                instance_id=instance_id,
                status=status,
                error=str(e),
                pid=os.getpid(),
            )

    async def reset(self):
        """Reset the workflow manager's state."""
        async with self.lock:
            # Clear active workflows
            self.active_workflows.clear()

            # Reset workflows in database
            try:
                async with self.pool.acquire() as conn:
                    # Clear existing workflows
                    #   TODO: should this only include running workflows?
                    await conn.execute("DELETE FROM workflows")
            except Exception:
                logger.exception(message="Error resetting workflows in database")

            logger.info("WorkflowManager reset", active_count=len(self.active_workflows))

            return {
                "status": "success",
                "message": "Workflow manager reset successfully",
                "timestamp": datetime.now().isoformat(),
            }

    async def start_workflow(self, workflow_input):
        """Start a workflow"""
        start_time = time.time()
        tracer = get_tracer()

        try:
            # Generate the workflow ID first so we can schedule the workflow after
            # initializing it in the database
            instance_id = str(uuid.uuid4()).replace("-", "")

            with tracer.start_as_current_span("start_workflow") as current_span:
                # Add workflow ID to trace for Jaeger queries
                current_span.set_attribute("workflow.instance_id", instance_id)
                current_span.set_attribute("workflow.type", "enrichment_workflow")

                if "file" in workflow_input and "object_id" in workflow_input["file"]:
                    current_span.set_attribute("workflow.object_id", workflow_input["file"]["object_id"])

                # Extract metadata for tracking
                base_filename = None
                object_id = None
                if "file" in workflow_input:
                    if "path" in workflow_input["file"]:
                        filepath = workflow_input["file"]["path"]
                        base_filename = os.path.basename(filepath)
                    if "object_id" in workflow_input["file"]:
                        object_id = workflow_input["file"].get("object_id")

                # Store workflow in database
                # async with self.pool.acquire() as conn:
                #     await conn.execute(
                #         """
                #         INSERT INTO workflows (wf_id, object_id, filename, status, start_time)
                #         VALUES ($1, $2, $3, $4, $5)
                #         """,
                #         instance_id,
                #         object_id,
                #         base_filename,
                #         "RUNNING",
                #         datetime.fromtimestamp(start_time),
                #     )

                # Add to active workflows tracking
                async with self.lock:
                    self.active_workflows[instance_id] = {
                        "object_id": object_id,
                        "start_time": start_time,
                        "filename": base_filename,
                    }

                logger.info(
                    "Scheduling workflow",
                    instance_id=instance_id,
                    object_id=object_id,
                    active_count=len(self.active_workflows),
                    pid=os.getpid(),
                )

                # Actually schedule the workflow
                await asyncio.to_thread(
                    workflow_client.schedule_new_workflow,
                    instance_id=instance_id,
                    workflow=enrichment_workflow,
                    input=workflow_input,
                )

                # TODO: Mnitor this workflow for completion/failure/timeout

                return instance_id

        except Exception:
            logger.exception(message="Error starting workflow")
            raise

    async def start_workflow_single_enrichment(
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
            start_time = time.time()

            # Generate the workflow ID
            instance_id = str(uuid.uuid4()).replace("-", "")

            # Normalize input to SingleEnrichmentWorkflowInput if dict
            if isinstance(workflow_input, dict):
                workflow_input = SingleEnrichmentWorkflowInput(**workflow_input)

            with tracer.start_as_current_span("start_single_enrichment_workflow") as span:
                # Add workflow ID to trace for Jaeger queries
                span.set_attribute("workflow.instance_id", instance_id)
                span.set_attribute("workflow.start", True)
                span.set_attribute("workflow.type", "single_enrichment_workflow")
                span.set_attribute("workflow.enrichment_name", workflow_input.enrichment_name)
                span.set_attribute("workflow.object_id", workflow_input.object_id)

                # Extract metadata for tracking
                enrichment_name = workflow_input.enrichment_name
                object_id = workflow_input.object_id

                # Store workflow in database (simplified - just for monitoring)
                # async with self.pool.acquire() as conn:
                #     await conn.execute(
                #         """
                #         INSERT INTO workflows (wf_id, object_id, filename, status, start_time)
                #         VALUES ($1, $2, $3, $4, $5)
                #         """,
                #         instance_id,
                #         object_id,
                #         f"bulk:{enrichment_name} ({object_id})",  # Use enrichment name as filename
                #         "RUNNING",
                #         datetime.fromtimestamp(start_time),
                #     )

                # Add to active workflows tracking
                async with self.lock:
                    self.active_workflows[instance_id] = {
                        "object_id": object_id,
                        "start_time": start_time,
                        "filename": f"bulk:{enrichment_name} ({object_id})",
                        "enrichment_name": enrichment_name,
                    }

                logger.debug(
                    "Triggering single enrichment workflow",
                    instance_id=instance_id,
                    enrichment_name=enrichment_name,
                    object_id=object_id,
                    active_count=len(self.active_workflows),
                    pid=os.getpid(),
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
                    workflow_client.schedule_new_workflow,
                    instance_id=instance_id,
                    workflow=single_enrichment_workflow,
                    input=workflow_input_dict,
                )

                # TODO: Start a task to monitor this workflow for completion/failure/timeout
                # monitor_task = asyncio.create_task(self._monitor_single_enrichment_workflow(instance_id, start_time))
                # self.background_tasks.add(monitor_task)
                # monitor_task.add_done_callback(self.background_tasks.discard)

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

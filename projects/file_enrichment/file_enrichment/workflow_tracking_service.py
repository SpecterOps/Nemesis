# src/workflow/workflow_tracking_service.py
import asyncio
import time
from datetime import datetime
from typing import Optional

import asyncpg
from common.logger import get_logger
from dapr.ext.workflow.workflow_state import WorkflowStatus

logger = get_logger(__name__)


class WorkflowTrackingService:
    """Service for tracking workflow lifecycle states in the database."""

    def __init__(self, pool: asyncpg.Pool, workflow_client, max_execution_time: int = 300):
        """Initialize the workflow tracking service.

        Args:
            pool: asyncpg connection pool for database operations
            workflow_client: Dapr workflow client for monitoring workflow states
            max_execution_time: Maximum time (in seconds) before a workflow is considered timed out
        """
        self.pool = pool
        self.workflow_client = workflow_client
        self.max_execution_time = max_execution_time
        self.monitoring_tasks = {}  # {instance_id: task}
        self.background_tasks = set()  # Track background tasks to prevent GC

    async def register_workflow(self, instance_id: str, object_id: str, filename: Optional[str] = None) -> None:
        """Create initial workflow record with SCHEDULED status.

        Args:
            instance_id: The workflow instance ID
            object_id: The object_id being processed
            filename: Optional filename for display purposes
        """
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO workflows (wf_id, object_id, filename, status, start_time)
                    VALUES ($1, $2, $3, $4, $5)
                    """,
                    instance_id,
                    object_id,
                    filename,
                    "SCHEDULED",
                    datetime.now(),
                )

            logger.debug(
                "Started tracking workflow",
                instance_id=instance_id,
                object_id=object_id,
                filename=filename,
                status="SCHEDULED",
            )
        except Exception as e:
            logger.error(
                "Failed to start tracking workflow",
                instance_id=instance_id,
                object_id=object_id,
                error=str(e),
            )
            raise

    async def update_status(
        self,
        instance_id: str,
        status: str,
        runtime_seconds: Optional[float] = None,
        error_message: Optional[str] = None,
    ) -> None:
        """Update workflow status and optionally runtime/error information.

        Args:
            instance_id: The workflow instance ID
            status: New status (RUNNING, COMPLETED, FAILED, TIMEOUT, TERMINATED)
            runtime_seconds: Optional runtime in seconds
            error_message: Optional error message (appended to enrichments_failure)
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
                        error_message[:100],  # Truncate long error messages
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
            )
        except Exception as e:
            logger.error(
                "Failed to update workflow status",
                instance_id=instance_id,
                status=status,
                error=str(e),
            )
            raise

    async def update_enrichment_results(
        self,
        instance_id: str,
        success_list: Optional[list[str]] = None,
        failure_list: Optional[list[str]] = None,
    ) -> None:
        """Update enrichment success/failure arrays.

        Args:
            instance_id: The workflow instance ID
            success_list: List of successful enrichment module names
            failure_list: List of failed enrichment module names
        """
        try:
            async with self.pool.acquire() as conn:
                if success_list is not None and failure_list is not None:
                    await conn.execute(
                        """
                        UPDATE workflows
                        SET enrichments_success = $1,
                            enrichments_failure = $2
                        WHERE wf_id = $3
                        """,
                        success_list,
                        failure_list,
                        instance_id,
                    )
                elif success_list is not None:
                    await conn.execute(
                        """
                        UPDATE workflows
                        SET enrichments_success = $1
                        WHERE wf_id = $2
                        """,
                        success_list,
                        instance_id,
                    )
                elif failure_list is not None:
                    await conn.execute(
                        """
                        UPDATE workflows
                        SET enrichments_failure = $1
                        WHERE wf_id = $2
                        """,
                        failure_list,
                        instance_id,
                    )

            logger.debug(
                "Updated enrichment results",
                instance_id=instance_id,
                success_count=len(success_list) if success_list else 0,
                failure_count=len(failure_list) if failure_list else 0,
            )
        except Exception as e:
            logger.error(
                "Failed to update enrichment results",
                instance_id=instance_id,
                error=str(e),
            )
            raise

    async def get_workflow_status(self, instance_id: str) -> Optional[dict]:
        """Query current workflow state from database.

        Args:
            instance_id: The workflow instance ID

        Returns:
            Dictionary with workflow information or None if not found
        """
        try:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT wf_id, object_id, filename, status, runtime_seconds,
                           enrichments_success, enrichments_failure, start_time
                    FROM workflows
                    WHERE wf_id = $1
                    """,
                    instance_id,
                )

                if row:
                    return {
                        "wf_id": row["wf_id"],
                        "object_id": row["object_id"],
                        "filename": row["filename"],
                        "status": row["status"],
                        "runtime_seconds": row["runtime_seconds"],
                        "enrichments_success": row["enrichments_success"],
                        "enrichments_failure": row["enrichments_failure"],
                        "start_time": row["start_time"],
                    }
                return None
        except Exception as e:
            logger.error(
                "Failed to get workflow status",
                instance_id=instance_id,
                error=str(e),
            )
            raise

    async def start_monitoring(self, instance_id: str, start_time: float, completion_callback=None) -> None:
        """Launch background task to monitor workflow via Dapr.

        Args:
            instance_id: The workflow instance ID
            start_time: Workflow start time (from time.time())
            completion_callback: Optional async callback function to call on completion/failure
                                 Should accept (instance_id, completed: bool) as arguments
        """
        # Create monitoring task
        task = asyncio.create_task(self._monitor_workflow(instance_id, start_time, completion_callback))
        self.monitoring_tasks[instance_id] = task
        self.background_tasks.add(task)
        task.add_done_callback(self.background_tasks.discard)
        task.add_done_callback(lambda t: self.monitoring_tasks.pop(instance_id, None))

        logger.debug(
            "Started monitoring workflow",
            instance_id=instance_id,
            monitoring_count=len(self.monitoring_tasks),
        )

    async def _monitor_workflow(self, instance_id: str, start_time: float, completion_callback=None) -> None:
        """Background task to monitor workflow state and update database.

        Args:
            instance_id: The workflow instance ID
            start_time: Workflow start time (from time.time())
            completion_callback: Optional async callback function
        """
        poll_interval = 5  # Poll every 5 seconds
        running_logged = False

        try:
            while True:
                await asyncio.sleep(poll_interval)

                # Check for timeout
                elapsed_time = time.time() - start_time
                if elapsed_time > self.max_execution_time:
                    logger.warning(
                        "Workflow exceeded max execution time",
                        instance_id=instance_id,
                        elapsed_time=elapsed_time,
                        max_time=self.max_execution_time,
                    )
                    await self.update_status(
                        instance_id,
                        "TIMEOUT",
                        runtime_seconds=elapsed_time,
                        error_message="Exceeded max execution time",
                    )

                    # Call completion callback with failure
                    if completion_callback:
                        try:
                            await completion_callback(instance_id, completed=False)
                        except Exception as e:
                            logger.error(
                                "Error in completion callback",
                                instance_id=instance_id,
                                error=str(e),
                            )
                    break

                # Query Dapr for workflow state
                try:
                    state = await asyncio.to_thread(self.workflow_client.get_workflow_state, instance_id)

                    if state.runtime_status == WorkflowStatus.RUNNING:
                        if not running_logged:
                            await self.update_status(instance_id, "RUNNING")
                            running_logged = True

                    elif state.runtime_status == WorkflowStatus.COMPLETED:
                        runtime = time.time() - start_time
                        await self.update_status(instance_id, "COMPLETED", runtime_seconds=runtime)
                        logger.info(
                            "Workflow completed successfully",
                            instance_id=instance_id,
                            runtime_seconds=runtime,
                        )

                        # Call completion callback with success
                        if completion_callback:
                            try:
                                await completion_callback(instance_id, completed=True)
                            except Exception as e:
                                logger.error(
                                    "Error in completion callback",
                                    instance_id=instance_id,
                                    error=str(e),
                                )
                        break

                    elif state.runtime_status == WorkflowStatus.FAILED:
                        runtime = time.time() - start_time
                        error_msg = state.failure_details.message if state.failure_details else "Unknown error"
                        await self.update_status(
                            instance_id,
                            "FAILED",
                            runtime_seconds=runtime,
                            error_message=error_msg,
                        )
                        logger.warning(
                            "Workflow failed",
                            instance_id=instance_id,
                            error=error_msg,
                            runtime_seconds=runtime,
                        )

                        # Call completion callback with failure
                        if completion_callback:
                            try:
                                await completion_callback(instance_id, completed=False)
                            except Exception as e:
                                logger.error(
                                    "Error in completion callback",
                                    instance_id=instance_id,
                                    error=str(e),
                                )
                        break

                    elif state.runtime_status == WorkflowStatus.TERMINATED:
                        runtime = time.time() - start_time
                        await self.update_status(
                            instance_id,
                            "TERMINATED",
                            runtime_seconds=runtime,
                            error_message="Workflow was terminated",
                        )
                        logger.warning(
                            "Workflow was terminated",
                            instance_id=instance_id,
                            runtime_seconds=runtime,
                        )

                        # Call completion callback with failure
                        if completion_callback:
                            try:
                                await completion_callback(instance_id, completed=False)
                            except Exception as e:
                                logger.error(
                                    "Error in completion callback",
                                    instance_id=instance_id,
                                    error=str(e),
                                )
                        break

                except Exception as e:
                    logger.error(
                        "Error querying workflow state from Dapr",
                        instance_id=instance_id,
                        error=str(e),
                    )
                    # Continue monitoring despite error

        except asyncio.CancelledError:
            logger.debug(
                "Workflow monitoring cancelled",
                instance_id=instance_id,
            )
            raise
        except Exception as e:
            logger.exception(
                "Unexpected error in workflow monitoring",
                instance_id=instance_id,
                error=str(e),
            )

    async def cleanup(self) -> None:
        """Clean up all monitoring tasks during shutdown."""
        logger.info("Cleaning up workflow tracking service", task_count=len(self.background_tasks))

        # Cancel all background tasks
        for task in self.background_tasks:
            if not task.done():
                task.cancel()

        # Wait for all tasks to complete/cancel
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)

        self.background_tasks.clear()
        self.monitoring_tasks.clear()

        logger.info("Workflow tracking service cleanup completed")

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - cleanup tasks."""
        await self.cleanup()
        return False  # Don't suppress exceptions

"""
Workflow purger module for cleaning up completed workflows from Dapr.

This module queries the database for completed workflows, verifies their state
with Dapr's workflow_client, and purges them to free up resources.
"""

import asyncio

import asyncpg
import dapr.ext.workflow as wf
import grpc
from common.logger import get_logger
from dapr.ext.workflow.workflow_state import WorkflowStatus as DaprWorkflowStatus

logger = get_logger(__name__)


class WorkflowPurger:
    """Service for purging completed workflows from Dapr state store."""

    def __init__(
        self,
        workflow_name: str,
        db_pool: asyncpg.Pool,
        workflow_client: wf.DaprWorkflowClient,
        *,
        max_execution_time: int = 300,
        batch_size=50,
        interval_seconds=5,
    ):
        """Initialize the workflow purger.

        Args:
            name: Workflow name prefix to filter workflows (e.g., 'FileEnrichment')
            db_pool: asyncpg connection pool for database operations
            workflow_client: Dapr workflow client for querying and purging workflows
            max_execution_time: Maximum time (in seconds) until a workflow is considered timed out (default: 300)
        """
        self._workflow_name = workflow_name
        self._db_pool = db_pool
        self._loop = None
        self._workflow_client = workflow_client
        self._max_execution_time = max_execution_time
        self._batch_size = batch_size
        self._interval_seconds = interval_seconds

    async def _handle_running_workflow(self, wf_id: str) -> tuple[bool, str | None]:
        """Check if a running workflow has timed out and terminate it if so.

        Args:
            wf_id: The workflow instance ID

        Returns:
            Tuple of (success: bool, purged_wf_id: str | None)
            - success: True if workflow was terminated due to timeout
            - purged_wf_id: The workflow ID if terminated, None otherwise
        """
        # Query database for workflow start_time to calculate runtime
        async with self._db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT start_time,
                    EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - start_time)) as runtime_seconds
                FROM workflows
                WHERE wf_id = $1
                """,
                wf_id,
            )

        if not row:
            logger.warning(
                "Running workflow not found in database, skipping",
                wf_id=wf_id,
            )
            return (False, None)

        runtime_seconds = row["runtime_seconds"]

        # Check if workflow has exceeded max execution time
        if runtime_seconds > self._max_execution_time:
            logger.warning(
                "Running workflow exceeded max execution time, terminating",
                wf_id=wf_id,
                runtime_seconds=runtime_seconds,
                max_execution_time=self._max_execution_time,
            )

            # Terminate the workflow in Dapr
            try:
                await asyncio.to_thread(self._workflow_client.terminate_workflow, wf_id)
            except Exception:
                logger.exception(
                    message="Error terminating timed-out workflow",
                    wf_id=wf_id,
                )

            # Update database status to TIMEOUT
            async with self._db_pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE workflows
                    SET status = 'TIMEOUT',
                        enrichments_failure = array_append(enrichments_failure, $2)
                    WHERE wf_id = $1
                    """,
                    wf_id,
                    f"Workflow exceeded max execution time ({runtime_seconds:.2f}s > {self._max_execution_time}s)",
                )

            logger.info(
                "Marked timed-out workflow as TIMEOUT in database",
                wf_id=wf_id,
            )

            # Return success to mark as purged (workflow is terminated)
            return (True, wf_id)
        else:
            logger.debug(
                "Running workflow has not exceeded max execution time, skipping",
                wf_id=wf_id,
                runtime_seconds=runtime_seconds,
                max_execution_time=self._max_execution_time,
            )
            return (False, None)

    async def _get_completed_workflows(self, limit: int = 200) -> list[str]:
        """Query database for workflows that may need purging.

        Retrieves workflows with status COMPLETED, FAILED, TERMINATED, or RUNNING
        that haven't been purged yet.

        Args:
            limit: Maximum number of workflows to retrieve per batch (default: 200)

        Returns:
            List of workflow IDs
        """
        try:
            async with self._db_pool.acquire() as conn:
                # Query for workflows that haven't been purged yet, filtered by workflow name
                # Include COMPLETED, FAILED, TERMINATED, and RUNNING workflows
                records = await conn.fetch(
                    """
                    SELECT wf_id
                    FROM workflows
                    WHERE status != 'SCHEDULED'
                    AND is_purged = false
                    AND wf_id LIKE $1
                    ORDER BY start_time ASC
                    LIMIT $2
                    """,
                    f"{self._workflow_name}.%",
                    limit,
                )

                workflow_ids = [record["wf_id"] for record in records]

                if workflow_ids:
                    logger.debug(
                        "Found scheduled workflows. Proceeding with purge checks...",
                        count=len(workflow_ids),
                    )

                return workflow_ids

        except Exception:
            logger.exception(message="Error querying workflows from database")
            return []

    async def _verify_and_purge_workflow(self, wf_id: str) -> tuple[bool, str | None]:
        """Verify workflow state with Dapr and purge if appropriate.

        Handles different workflow states:
        - COMPLETED: Purge from Dapr
        - FAILED: Log error details and purge from Dapr
        - TERMINATED: Purge from Dapr
        - RUNNING: Check if timed out, terminate and update DB if so
        - None (not found): Treat as already purged
        - Other states: Skip purging

        Args:
            wf_id: The workflow instance ID

        Returns:
            Tuple of (success: bool, purged_wf_id: str | None)
            - success: True if successfully purged from Dapr or handled
            - purged_wf_id: The workflow ID if purged/handled, None otherwise
        """
        try:
            # Get the current state from Dapr
            state = await asyncio.to_thread(self._workflow_client.get_workflow_state, wf_id, fetch_payloads=False)

            if state is None:
                logger.debug(
                    "Workflow not found in Dapr state - treating as already purged, will mark in DB",
                    wf_id=wf_id,
                )
                return (True, wf_id)

            # Handle COMPLETED workflows - purge them
            if state.runtime_status in [DaprWorkflowStatus.COMPLETED, DaprWorkflowStatus.TERMINATED]:
                await asyncio.to_thread(self._workflow_client.purge_workflow, wf_id, True)

                logger.debug(
                    "Purged workflow from Dapr state",
                    wf_id=wf_id,
                    workflow_state=state.runtime_status,
                )
                return (True, wf_id)

            # Handle FAILED workflows - log error and purge
            elif state.runtime_status == DaprWorkflowStatus.FAILED:
                logger.error(
                    "Workflow failed in Dapr, purging",
                    wf_id=wf_id,
                    failure_info=state.to_json(),
                )

                # Purge the failed workflow from Dapr state
                await asyncio.to_thread(self._workflow_client.purge_workflow, wf_id, True)

                logger.debug(
                    "Purged failed workflow from Dapr state",
                    wf_id=wf_id,
                )
                return (True, wf_id)

            # Handle RUNNING workflows - check if timed out
            elif state.runtime_status == DaprWorkflowStatus.RUNNING:
                return await self._handle_running_workflow(wf_id)

            # Handle other statuses (PENDING, SUSPENDED, UNKNOWN) - skip
            else:
                logger.debug(
                    "Workflow in non-purgeable state, skipping",
                    wf_id=wf_id,
                    dapr_status=state.runtime_status.name,
                )
                return (False, None)

        except grpc.RpcError as e:
            details = e.details()
            if details and "no such instance exists" in details:
                # Workflow doesn't exist anymore: another instance may have already purged it
                return (True, wf_id)

            return (True, wf_id)

        except Exception:
            logger.exception(
                message="Error verifying and purging workflow",
                wf_id=wf_id,
            )
            return (False, None)

    async def _run_purge_cycle(self) -> dict:
        """Run a single purge cycle.

        Uses a database cursor to process all non-purged workflows in batches
        without any artificial cap on the number of workflows processed.

        Args:
            batch_size: Number of workflows to process per batch (default: 50)

        Returns:
            Dictionary with purge statistics
        """
        logger.debug(
            "Starting workflow purge cycle",
            batch_size=self._batch_size,
        )

        # Track total statistics across all batches
        total_checked = 0
        total_purged = 0
        batches_processed = 0

        try:
            # Use a database connection with cursor to stream through all non-purged workflows
            async with self._db_pool.acquire() as conn:
                # Start a transaction for the cursor
                async with conn.transaction():
                    # Create a cursor for streaming results
                    cursor = await conn.cursor(
                        """
                        SELECT wf_id
                        FROM workflows
                        WHERE status != 'SCHEDULED'
                        AND is_purged = false
                        AND wf_id LIKE $1
                        ORDER BY start_time ASC
                        """,
                        f"{self._workflow_name}.%",
                    )

                    # Process workflows in batches using the cursor
                    while True:
                        # Fetch next batch of workflow IDs from cursor
                        workflow_ids = [record["wf_id"] for record in await cursor.fetch(self._batch_size)]

                        if not workflow_ids:
                            logger.debug(
                                "No more workflows found",
                                batches_processed=batches_processed,
                            )
                            break

                        batches_processed += 1
                        total_checked += len(workflow_ids)

                        # Purge workflows in parallel from Dapr
                        purge_results = await asyncio.gather(
                            *[self._verify_and_purge_workflow(wf_id) for wf_id in workflow_ids],
                            return_exceptions=True,
                        )

                        # Collect successfully purged workflow IDs
                        purged_wf_ids = []

                        for wf_id, result in zip(workflow_ids, purge_results):
                            if isinstance(result, Exception):
                                logger.error(
                                    "Purge operation failed with exception",
                                    wf_id=wf_id,
                                    error=str(result),
                                )
                                continue

                            if not isinstance(result, tuple):
                                logger.error(
                                    "Purge operation returned unexpected type",
                                    wf_id=wf_id,
                                    result_type=type(result).__name__,
                                )
                                continue

                            if result[0]:  # result is (success, purged_wf_id)
                                purged_wf_ids.append(result[1])

                        # Update all successfully purged workflows in a single transaction
                        if purged_wf_ids:
                            try:
                                # Use a separate connection for the update to avoid blocking the cursor
                                async with self._db_pool.acquire() as update_conn:
                                    await update_conn.execute(
                                        """
                                        UPDATE workflows
                                        SET is_purged = true
                                        WHERE wf_id = ANY($1)
                                        """,
                                        purged_wf_ids,
                                    )
                                total_purged += len(purged_wf_ids)
                                logger.info(
                                    "Marked workflows as purged in database",
                                    count=len(purged_wf_ids),
                                )
                            except Exception:
                                logger.exception(
                                    message="Error marking workflows as purged in database",
                                    count=len(purged_wf_ids),
                                )

                        logger.info(
                            "Batch processed",
                            batch_num=batches_processed,
                            checked=len(workflow_ids),
                            purged=len(purged_wf_ids),
                        )

            stats = {
                "total_checked": total_checked,
                "purged": total_purged,
                "batches_processed": batches_processed,
            }

            logger.info(
                "Workflow purge cycle completed",
                **stats,
            )

            return stats

        except Exception:
            logger.exception(message="Error during workflow purge cycle")
            return {
                "total_checked": total_checked,
                "purged": total_purged,
                "batches_processed": batches_processed,
                "error": True,
            }

    async def run(self):
        while True:
            logger.info("Running purge cycle")
            await self._run_purge_cycle()
            await asyncio.sleep(self._interval_seconds)

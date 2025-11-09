"""
Workflow purger module for cleaning up completed workflows from Dapr.

This module queries the database for completed workflows, verifies their state
with Dapr's workflow_client, and purges them to free up resources.
"""

import asyncio

import asyncpg
from common.logger import get_logger
from dapr.ext.workflow import DaprWorkflowClient
from dapr.ext.workflow.workflow_state import WorkflowStatus as DaprWorkflowStatus

logger = get_logger(__name__)


class WorkflowPurger:
    """Service for purging completed workflows from Dapr state store."""

    def __init__(self, name: str, db_pool: asyncpg.Pool, workflow_client: DaprWorkflowClient):
        """Initialize the workflow purger.

        Args:
            name: Workflow name prefix to filter workflows (e.g., 'FileEnrichment')
            db_pool: asyncpg connection pool for database operations
            workflow_client: Dapr workflow client for querying and purging workflows
        """
        self.name = name
        self.db_pool = db_pool
        self.workflow_client = workflow_client

    async def get_completed_workflows(self, limit: int = 200) -> list[str]:
        """Query database for workflows marked as completed but not yet purged.

        Args:
            limit: Maximum number of workflows to retrieve per batch (default: 200)

        Returns:
            List of workflow IDs
        """
        try:
            async with self.db_pool.acquire() as conn:
                # Query for completed workflows that haven't been purged yet, filtered by workflow name
                records = await conn.fetch(
                    """
                    SELECT wf_id
                    FROM workflows
                    WHERE status = 'COMPLETED' AND is_purged = false AND wf_id LIKE $1
                    ORDER BY start_time ASC
                    LIMIT $2
                    """,
                    f"{self.name}.%",
                    limit,
                )

                workflow_ids = [record["wf_id"] for record in records]

                if workflow_ids:
                    logger.info(
                        "Found completed workflows for verification",
                        count=len(workflow_ids),
                    )

                return workflow_ids

        except Exception:
            logger.exception(message="Error querying completed workflows from database")
            return []

    async def verify_and_purge_workflow(self, wf_id: str) -> tuple[bool, str | None]:
        """Verify workflow state with Dapr and purge if completed.

        Args:
            wf_id: The workflow instance ID

        Returns:
            Tuple of (success: bool, purged_wf_id: str | None)
            - success: True if successfully purged from Dapr
            - purged_wf_id: The workflow ID if purged, None otherwise
        """
        try:
            # Get the current state from Dapr (run sync call in thread)
            state = await asyncio.to_thread(self.workflow_client.get_workflow_state, wf_id, fetch_payloads=False)

            if state is None:
                logger.debug(
                    "Workflow not found in Dapr state - may already be purged",
                    wf_id=wf_id,
                )
                return (False, None)

            # Only purge if workflow is marked as COMPLETED in Dapr
            if state.runtime_status == DaprWorkflowStatus.COMPLETED:
                # Purge the workflow from Dapr state (run sync call in thread)
                await asyncio.to_thread(self.workflow_client.purge_workflow, wf_id, True)

                logger.debug(
                    "Purged completed workflow from Dapr state",
                    wf_id=wf_id,
                )
                return (True, wf_id)
            else:
                logger.debug(
                    "Workflow not completed in Dapr, skipping purge",
                    wf_id=wf_id,
                    db_status="COMPLETED",
                    dapr_status=state.runtime_status.name,
                    state=state,
                    runtime_status=state.runtime_status,
                )
                return (False, None)

        except Exception:
            logger.exception(
                message="Error verifying and purging workflow",
                wf_id=wf_id,
            )
            return (False, None)

    async def run_purge_cycle(self, batch_size: int = 50, max_batches: int = 1000) -> dict:
        """Run a single purge cycle.

        Processes workflows in batches until no more completed workflows are found
        or the maximum number of batches is reached.

        Args:
            batch_size: Maximum number of workflows to process per batch (default: 50)
            max_batches: Maximum number of batches to process per cycle (default: 1000)

        Returns:
            Dictionary with purge statistics
        """
        logger.info(
            "Starting workflow purge cycle",
            batch_size=batch_size,
            max_batches=max_batches,
        )

        # Track total statistics across all batches
        total_checked = 0
        total_purged = 0
        batches_processed = 0

        try:
            while batches_processed < max_batches:
                # Get completed workflows from database
                workflow_ids = await self.get_completed_workflows(limit=batch_size)

                if not workflow_ids:
                    logger.debug(
                        "No more completed workflows found",
                        batches_processed=batches_processed,
                    )
                    break

                batches_processed += 1
                total_checked += len(workflow_ids)

                # Purge workflows in parallel from Dapr
                purge_results = await asyncio.gather(
                    *[self.verify_and_purge_workflow(wf_id) for wf_id in workflow_ids],
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
                    elif result[0]:  # result is (success, purged_wf_id)
                        purged_wf_ids.append(result[1])

                # Update all successfully purged workflows in a single transaction
                if purged_wf_ids:
                    try:
                        async with self.db_pool.acquire() as conn:
                            await conn.execute(
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

                # If we got fewer workflows than the batch size, we're done
                if len(workflow_ids) < batch_size:
                    break

                # Add a small delay between batches to avoid overwhelming the system
                if batches_processed < max_batches:
                    await asyncio.sleep(0.1)

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

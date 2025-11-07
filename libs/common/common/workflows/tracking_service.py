# src/workflow/workflow_tracking_service.py
from datetime import datetime
from typing import Optional

import asyncpg
from common.logger import get_logger

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
        """Update enrichment success/failure arrays by appending to existing values.

        Args:
            instance_id: The workflow instance ID
            success_list: List of successful enrichment module names to append
            failure_list: List of failed enrichment module names to append
        """
        try:
            async with self.pool.acquire() as conn:
                if success_list is not None and failure_list is not None:
                    await conn.execute(
                        """
                        UPDATE workflows
                        SET enrichments_success = enrichments_success || $1,
                            enrichments_failure = enrichments_failure || $2
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
                        SET enrichments_success = enrichments_success || $1
                        WHERE wf_id = $2
                        """,
                        success_list,
                        instance_id,
                    )
                elif failure_list is not None:
                    await conn.execute(
                        """
                        UPDATE workflows
                        SET enrichments_failure = enrichments_failure || $1
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

    async def update_enrichment_results_by_object_id(
        self,
        object_id: str,
        success_list: Optional[list[str]] = None,
        failure_list: Optional[list[str]] = None,
    ) -> None:
        """Update enrichment success/failure arrays by object_id (for subscription handlers).

        Args:
            object_id: The object_id being processed
            success_list: List of successful enrichment module names to append
            failure_list: List of failed enrichment module names to append
        """
        try:
            async with self.pool.acquire() as conn:
                if success_list is not None and failure_list is not None:
                    await conn.execute(
                        """
                        UPDATE workflows
                        SET enrichments_success = enrichments_success || $1,
                            enrichments_failure = enrichments_failure || $2
                        WHERE object_id = $3
                        """,
                        success_list,
                        failure_list,
                        object_id,
                    )
                elif success_list is not None:
                    await conn.execute(
                        """
                        UPDATE workflows
                        SET enrichments_success = enrichments_success || $1
                        WHERE object_id = $2
                        """,
                        success_list,
                        object_id,
                    )
                elif failure_list is not None:
                    await conn.execute(
                        """
                        UPDATE workflows
                        SET enrichments_failure = enrichments_failure || $1
                        WHERE object_id = $2
                        """,
                        failure_list,
                        object_id,
                    )

            logger.debug(
                "Updated enrichment results by object_id",
                object_id=object_id,
                success_count=len(success_list) if success_list else 0,
                failure_count=len(failure_list) if failure_list else 0,
            )
        except Exception as e:
            logger.error(
                "Failed to update enrichment results by object_id",
                object_id=object_id,
                error=str(e),
            )
            raise

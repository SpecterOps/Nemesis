# src/workflow/workflow_tracking_service.py
from datetime import UTC, datetime
from enum import StrEnum
from typing import Optional
from uuid import uuid4

import asyncpg
from common.logger import get_logger

logger = get_logger(__name__)


class WorkflowStatus(StrEnum):
    """Workflow status enumeration."""

    SCHEDULED = "SCHEDULED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    TERMINATED = "TERMINATED"


class WorkflowTrackingService:
    """Service for tracking workflow lifecycle states in the database."""

    def __init__(self, name: str, pool: asyncpg.Pool, workflow_client):
        """Initialize the workflow tracking service.

        Args:
            name: Name prefix for workflow instance IDs
            pool: asyncpg connection pool for database operations
            workflow_client: Dapr workflow client for monitoring workflow states
        """
        self._name = name
        self.pool = pool
        self.workflow_client = workflow_client

    def _create_instance_id(self, object_id: str) -> str:
        """Create a workflow instance ID.

        Args:
            object_id: The object_id being processed

        Returns:
            Instance ID in format: <NAME>.<uuid>.<object_id>
        """
        instance_uuid = uuid4().hex
        return f"{self._name}.{instance_uuid}.{object_id}"

    async def register_workflow(self, object_id: str, filename: Optional[str] = None) -> str:
        """Create initial workflow record with SCHEDULED status.

        Args:
            object_id: The object_id being processed
            filename: Optional filename for display purposes

        Returns:
            The generated workflow instance ID
        """
        instance_id = self._create_instance_id(object_id)

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
                    WorkflowStatus.SCHEDULED,
                    datetime.now(UTC),
                )

            logger.debug(
                "Started tracking workflow",
                instance_id=instance_id,
                object_id=object_id,
                filename=filename,
                status="SCHEDULED",
            )

            return instance_id
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
        status: WorkflowStatus,
        error_message: Optional[str] = None,
    ) -> None:
        """Update workflow status and optionally error information.

        Args:
            instance_id: The workflow instance ID
            status: New status (WorkflowStatus enum)
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
                            enrichments_failure = array_append(enrichments_failure, $2)
                        WHERE wf_id = $3
                        """,
                        status,
                        error_message[:100],  # Truncate long error messages
                        instance_id,
                    )
                else:
                    # Update without modifying enrichments_failure
                    await conn.execute(
                        """
                        UPDATE workflows
                        SET status = $1
                        WHERE wf_id = $2
                        """,
                        status,
                        instance_id,
                    )

            logger.debug(
                "Updated workflow status",
                instance_id=instance_id,
                status=status,
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

    async def finalize_workflow(self, instance_id: str) -> None:
        """Finalize workflow by setting status to COMPLETED and calculating runtime.

        Queries the database for the workflow start_time, calculates the runtime,
        and updates the status to COMPLETED.

        Args:
            instance_id: The workflow instance ID
        """
        try:
            async with self.pool.acquire() as conn:
                # Get the start time
                row = await conn.fetchrow(
                    """
                    SELECT start_time
                    FROM workflows
                    WHERE wf_id = $1
                    """,
                    instance_id,
                )

                if not row:
                    logger.error(
                        "Cannot finalize workflow - workflow not found",
                        instance_id=instance_id,
                    )
                    return

                start_time = row["start_time"]
                end_time = datetime.now(UTC)
                runtime_seconds = (end_time - start_time).total_seconds()

                # Update status to COMPLETED and set runtime_seconds
                await conn.execute(
                    """
                    UPDATE workflows
                    SET status = $1,
                        runtime_seconds = $2
                    WHERE wf_id = $3
                    """,
                    WorkflowStatus.COMPLETED,
                    runtime_seconds,
                    instance_id,
                )

            logger.info(
                "Finalized workflow as completed",
                instance_id=instance_id,
                runtime_seconds=runtime_seconds,
            )
        except Exception as e:
            logger.error(
                "Failed to finalize workflow",
                instance_id=instance_id,
                error=str(e),
            )
            raise

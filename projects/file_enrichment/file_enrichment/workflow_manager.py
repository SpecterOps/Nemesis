# src/workflow/workflow_manager.py
import asyncio
import json
import os
import time
import uuid
from datetime import datetime

from common.db import get_postgres_connection_str
from common.logger import get_logger
from dapr.clients import DaprClient
from dapr.ext.workflow.workflow_state import WorkflowStatus
from psycopg_pool import ConnectionPool

from .tracing import get_tracer
from .workflow import enrichment_workflow, get_workflow_client

logger = get_logger(__name__)
monitoring_enabled = os.getenv("NEMESIS_MONITORING", "").lower() == "enabled"


class WorkflowManager:
    """WorkflowManager with Semaphore to control max concurrent workflow execution."""

    def __init__(self, max_concurrent=3, max_execution_time=300):
        """Initialize the workflow manager"""
        self.semaphore = asyncio.Semaphore(max_concurrent)  # Controls max concurrent workflows
        self.active_workflows = {}  # {instance_id: workflow_info}
        self.lock = asyncio.Lock()  # For synchronizing access to active_workflows
        self.max_execution_time = max_execution_time
        self.max_concurrent = max_concurrent
        self.background_tasks = set()  # Track background tasks to prevent GC
        self.pool = ConnectionPool(
            get_postgres_connection_str(),
            min_size=max_concurrent,
            max_size=(3 * max_concurrent),
            open=True,
        )

        # Start background cleanup task
        cleanup_task = asyncio.create_task(self._cleanup_loop())
        self.background_tasks.add(cleanup_task)
        cleanup_task.add_done_callback(self.background_tasks.discard)

        logger.info(
            "WorkflowManager initialized",
            max_concurrent=max_concurrent,
            max_execution_time=max_execution_time,
            pid=os.getpid(),
        )

    async def _cleanup_loop(self):
        """Run cleanup_stale_workflows every 60 seconds"""
        while True:
            await asyncio.sleep(60)
            try:
                await self.cleanup_stale_workflows()
            except Exception as e:
                logger.error(f"Background cleanup error: {e}", pid=os.getpid())

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

            def get_workflow_container_info():
                with self.pool.connection() as conn:
                    with conn.cursor() as cur:
                        # Get object_id from workflow
                        cur.execute(
                            """
                            SELECT object_id FROM workflows WHERE wf_id = %s
                        """,
                            (instance_id,),
                        )

                        row = cur.fetchone()
                        if not row or not row[0]:
                            return None, None, 0

                        object_id = row[0]

                        # Get originating_container_id and file size from files table
                        cur.execute(
                            """
                            SELECT fe.originating_container_id, fe.size
                            FROM files_enriched fe
                            WHERE fe.object_id = %s
                        """,
                            (object_id,),
                        )

                        file_row = cur.fetchone()
                        if file_row:
                            return object_id, file_row[0], file_row[1] or 0

                        # Fallback to files table if not in files_enriched yet
                        cur.execute(
                            """
                            SELECT f.originating_container_id, 0 as size
                            FROM files f
                            WHERE f.object_id = %s
                        """,
                            (object_id,),
                        )

                        fallback_row = cur.fetchone()
                        if fallback_row:
                            return object_id, fallback_row[0], fallback_row[1] or 0

                        return object_id, None, 0

            object_id, originating_container_id, file_size = await asyncio.to_thread(get_workflow_container_info)
            logger.debug(
                f"publish_workflow_completion - object_id: {object_id}, originating_container_id: {originating_container_id}, file_size: {file_size}",
                pid=os.getpid(),
            )

            # Only publish if we have a container ID to track
            if object_id and originating_container_id:
                with DaprClient() as client:
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
            logger.error(
                "Error publishing workflow completion event", workflow_id=instance_id, error=str(e), pid=os.getpid()
            )

    async def cleanup_stale_workflows(self):
        """Clean up workflows that were left running from previous service instances"""
        try:

            def get_stale_workflows():
                with self.pool.connection() as conn:
                    with conn.cursor() as cur:
                        # Find workflows that have been running for longer than max execution time
                        cur.execute(
                            """
                            SELECT wf_id, object_id,
                                EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - start_time)) as runtime_seconds
                            FROM workflows
                            WHERE status = 'RUNNING'
                            AND EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - start_time)) > %s
                        """,
                            (self.max_execution_time,),
                        )
                        return cur.fetchall()

            stale_workflows = await asyncio.to_thread(get_stale_workflows)

            if stale_workflows:
                logger.warning(f"Found {len(stale_workflows)} stale workflows, cleaning up...", pid=os.getpid())

                for wf_id, _object_id, runtime_seconds in stale_workflows:
                    logger.info(f"Cleaning up stale workflow {wf_id}, runtime: {runtime_seconds:.2f}s", pid=os.getpid())

                    # Try to terminate the workflow in Dapr
                    try:
                        client = get_workflow_client()
                        if client:
                            client.terminate_workflow(wf_id)
                    except Exception as e:
                        logger.warning(f"Could not terminate workflow {wf_id}: {e}", pid=os.getpid())

                    # Update database status
                    await self.update_workflow_status(
                        wf_id, "TIMEOUT", runtime_seconds, "cleaned up by cleanup_stale_workflows"
                    )

                    # Publish completion event
                    await self.publish_workflow_completion(wf_id, completed=False)

        except Exception as e:
            logger.error(f"Error during stale workflow cleanup: {e}", pid=os.getpid())

    async def update_workflow_status(self, instance_id, status, runtime_seconds=None, error_message=None):
        """
        Generalized function to update workflow status in database.

        Args:
            instance_id: The workflow instance ID
            status: The status to set (COMPLETED, FAILED, ERROR, TIMEOUT, etc.)
            runtime_seconds: Runtime in seconds (optional)
            error_message: Error message to append to enrichments_failure (optional)
        """

        def _update_workflow_in_db():
            with self.pool.connection() as conn:
                with conn.cursor() as cur:
                    if error_message:
                        # Update with error message appended to enrichments_failure
                        cur.execute(
                            """
                            UPDATE workflows
                            SET status = %s,
                                runtime_seconds = COALESCE(%s, runtime_seconds),
                                enrichments_failure = array_append(enrichments_failure, %s)
                            WHERE wf_id = %s
                            """,
                            (status, runtime_seconds, error_message[:100], instance_id),
                        )
                    else:
                        # Update without modifying enrichments_failure
                        cur.execute(
                            """
                            UPDATE workflows
                            SET status = %s,
                                runtime_seconds = COALESCE(%s, runtime_seconds)
                            WHERE wf_id = %s
                            """,
                            (status, runtime_seconds, instance_id),
                        )
                    conn.commit()

        try:
            await asyncio.to_thread(_update_workflow_in_db)
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

                def reset_db_workflows():
                    with self.pool.connection() as conn:
                        with conn.cursor() as cur:
                            # Clear existing workflows
                            #   TODO: should this only include running workflows?
                            cur.execute("DELETE FROM workflows")
                            conn.commit()

                await asyncio.to_thread(reset_db_workflows)
            except Exception as e:
                logger.exception(e, message="Error resetting workflows in database", pid=os.getpid())

            logger.info("WorkflowManager reset", active_count=len(self.active_workflows), pid=os.getpid())

            return {
                "status": "success",
                "message": "Workflow manager reset successfully",
                "timestamp": datetime.now().isoformat(),
            }

    async def start_workflow(self, workflow_input):
        """Start a workflow using semaphore for backpressure control"""
        # Acquire semaphore - this will block if we're at max capacity
        #   This provides natural backpressure to the Dapr pub/sub system
        start_time = time.time()
        tracer = get_tracer("workflow_manager", monitoring_enabled)
        client = get_workflow_client()
        if client is None:
            raise ValueError("Workflow client is None")

        await self.semaphore.acquire()

        try:
            # Generate the workflow ID first so we can schedule the workflow after
            #   initializing it in the database
            instance_id = str(uuid.uuid4()).replace("-", "")

            with tracer.start_as_current_span("start_workflow") as current_span:
                # Add workflow ID to trace for Jaeger queries
                current_span.set_attribute("workflow.instance_id", instance_id)
                current_span.set_attribute("workflow.start", True)
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
                def store_workflow():
                    with self.pool.connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                """
                                INSERT INTO workflows (wf_id, object_id, filename, status, start_time)
                                VALUES (%s, %s, %s, %s, %s)
                                """,
                                (
                                    instance_id,
                                    object_id,
                                    base_filename,
                                    "RUNNING",
                                    datetime.fromtimestamp(start_time),
                                ),
                            )
                            conn.commit()

                await asyncio.to_thread(store_workflow)

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
                client.schedule_new_workflow(
                    instance_id=instance_id,
                    workflow=enrichment_workflow,
                    input=workflow_input,
                )

                # Start a task to monitor this workflow for completion/failure/timeout
                monitor_task = asyncio.create_task(self._monitor_workflow(instance_id, start_time))
                self.background_tasks.add(monitor_task)
                monitor_task.add_done_callback(self.background_tasks.discard)

                return instance_id

        except Exception as e:
            # Release semaphore on error
            self.semaphore.release()
            logger.exception(e, message="Error starting workflow", pid=os.getpid())
            raise

    async def _monitor_workflow(self, instance_id, workflow_start_time: float):
        """Monitor a workflow until completion or timeout"""
        tracer = get_tracer("workflow_manager", monitoring_enabled)

        with tracer.start_as_current_span("monitor_workflow") as current_span:
            current_span.set_attribute("workflow.instance_id", instance_id)
            current_span.set_attribute("workflow.monitor", True)

            try:
                try:
                    # Use wait_for to implement a timeout
                    processing_time = time.time() - workflow_start_time
                    logger.debug(
                        "Monitoring for workflow completion",
                        processing_time=f"{processing_time:.4f}s",
                    )

                    final_status = await asyncio.wait_for(
                        self._wait_for_completion(instance_id, workflow_start_time),
                        timeout=self.max_execution_time,
                    )

                    processing_time = time.time() - workflow_start_time
                    logger.info(
                        "Updating workflow status",
                        processing_time=f"{processing_time:.4f}s",
                    )
                    await self.update_workflow_status(instance_id, final_status, processing_time)

                    logger.info(
                        f"Workflow finished: {'completed successfully' if final_status == 'COMPLETED' else 'completed with failure'}",
                        instance_id=instance_id,
                        processing_time=f"{processing_time:.4f}s",
                        final_status=final_status,
                        pid=os.getpid(),
                    )

                except TimeoutError:
                    processing_time = time.time() - workflow_start_time
                    logger.warning(
                        "Workflow timed out after exceeding maximum execution time",
                        instance_id=instance_id,
                        max_execution_time=f"{self.max_execution_time}s",
                        actual_time=f"{processing_time:.4f}s",
                        pid=os.getpid(),
                    )

                    try:
                        client = get_workflow_client()
                        if client:
                            client.terminate_workflow(
                                instance_id, recursive=True
                            )  # recursive == terminate all child workflows
                            logger.info("Workflow terminated due to timeout", instance_id=instance_id, pid=os.getpid())
                    except Exception as e:
                        logger.error("Failed to terminate timed-out workflow", instance_id=instance_id, error=str(e))

                    # Update workflow status for timeout
                    await self.update_workflow_status(instance_id, "TIMEOUT", processing_time, "timeout")

            except Exception as e:
                # Handle any other misc. failures
                processing_time = time.time() - workflow_start_time

                logger.exception(
                    "Workflow monitoring failed",
                    instance_id=instance_id,
                    processing_time=f"{processing_time:.4f}s",
                    error=str(e),
                    pid=os.getpid(),
                )

                # Update workflow status for error
                await self.update_workflow_status(instance_id, "ERROR", processing_time, str(e))

            finally:
                # Always clean up and release semaphore
                async with self.lock:
                    if instance_id in self.active_workflows:
                        del self.active_workflows[instance_id]

                # Release semaphore to allow next workflow
                self.semaphore.release()

    async def _wait_for_completion(self, instance_id, workflow_start_time: float):
        """Wait for workflow to complete and return the final status"""

        error_count = 0

        client = get_workflow_client()
        tracer = get_tracer("workflow_manager", monitoring_enabled)

        # Add trace attributes for workflow status monitoring
        with tracer.start_as_current_span("wait_for_completion") as current_span:
            current_span.set_attribute("workflow.instance_id", instance_id)
            current_span.set_attribute("workflow.wait_for_completion", True)

            while True:
                try:
                    state = await asyncio.to_thread(client.get_workflow_state, instance_id)
                    status = self._get_status_string(state)
                    error_count = 0  # Reset on successful check

                    if status in ["COMPLETED", "FAILED", "TERMINATED", "ERROR"]:
                        runtime_seconds = time.time() - workflow_start_time
                        logger.info(
                            "Workflow finished",
                            instance_id=instance_id,
                            final_status=status,
                            runtime=f"{runtime_seconds:.4f}s",
                            pid=os.getpid(),
                        )

                        # For failed workflows, capture the error message and update status
                        if status in ["FAILED", "TERMINATED", "ERROR"]:
                            error_msg = ""
                            if status == "FAILED" and state.failure_details:
                                error_msg = state.failure_details.message

                            logger.debug(
                                "Updating FAILED workflow status",
                                processing_time=f"{time.time() - workflow_start_time:.4f}s",
                            )
                            await self.update_workflow_status(
                                instance_id, status, runtime_seconds, error_msg[:100] if error_msg else status.lower()
                            )
                        else:
                            logger.debug(
                                "Updating SUCCESSFUL workflow status",
                                processing_time=f"{time.time() - workflow_start_time:.4f}s",
                            )
                            await self.update_workflow_status(instance_id, status, runtime_seconds, "")

                        logger.debug(
                            "Publishing workflow status",
                            processing_time=f"{time.time() - workflow_start_time:.4f}s",
                        )
                        # Publish workflow completion event for container tracking
                        await self.publish_workflow_completion(instance_id, status == "COMPLETED")

                        logger.debug(
                            "Done publishing workflow status",
                            processing_time=f"{time.time() - workflow_start_time:.4f}s",
                        )

                        # Return the actual status so _monitor_workflow knows what happened
                        return status

                    logger.debug(
                        "Waiting for workflow completion",
                        processing_time=f"{time.time() - workflow_start_time:.4f}s",
                    )
                    await asyncio.sleep(5)

                except Exception as e:
                    # specific case when we're standing the system down, so want to mark this as still running
                    #   [error    ] Unhandled RPC error while fetching workflow state: StatusCode.UNAVAILABLE - failed to connect to all addresses; last error: UNKNOWN: ipv4:127.0.0.1:50003: Failed to connect to remote host: connect: Connection refused (111) [DaprWorkflowClient]
                    if "StatusCode.UNAVAILABLE" in f"{e}":
                        return "RUNNING"

                    error_count += 1
                    logger.warning(
                        f"Error checking workflow status: {str(e)}",
                        instance_id=instance_id,
                        error_count=error_count,
                        pid=os.getpid(),
                    )

                    if error_count >= 3:  # Break after 3 consecutive errors
                        logger.error(
                            "Too many consecutive errors checking workflow status",
                            instance_id=instance_id,
                            error_count=error_count,
                            pid=os.getpid(),
                        )
                        # Return ERROR status so the monitoring can handle it appropriately
                        return "ERROR"

                    await asyncio.sleep(0.3)

    async def start_workflow_single_enrichment(self, workflow_input):
        """Start a single enrichment workflow using semaphore for backpressure control"""
        tracer = get_tracer("workflow_manager", monitoring_enabled)
        # Acquire semaphore - this will block if we're at max capacity
        #   This provides natural backpressure to the Dapr pub/sub system
        await self.semaphore.acquire()

        try:
            start_time = time.time()
            client = get_workflow_client()
            if client is None:
                raise ValueError("Workflow client is None")

            # Generate the workflow ID
            instance_id = str(uuid.uuid4()).replace("-", "")

            with tracer.start_as_current_span("start_single_enrichment_workflow") as span:
                # Add workflow ID to trace for Jaeger queries
                span.set_attribute("workflow.instance_id", instance_id)
                span.set_attribute("workflow.start", True)
                span.set_attribute("workflow.type", "single_enrichment_workflow")
                span.set_attribute("workflow.enrichment_name", workflow_input.get("enrichment_name"))

                if "object_id" in workflow_input:
                    span.set_attribute("workflow.object_id", workflow_input["object_id"])

                # Extract metadata for tracking
                enrichment_name = workflow_input.get("enrichment_name")
                object_id = workflow_input.get("object_id")

                # Store workflow in database (simplified - just for monitoring)
                def store_workflow():
                    with self.pool.connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                """
                                INSERT INTO workflows (wf_id, object_id, filename, status, start_time)
                                VALUES (%s, %s, %s, %s, %s)
                                """,
                                (
                                    instance_id,
                                    object_id,
                                    f"bulk:{enrichment_name} ({object_id})",  # Use enrichment name as filename
                                    "RUNNING",
                                    datetime.fromtimestamp(start_time),
                                ),
                            )
                            conn.commit()

                await asyncio.to_thread(store_workflow)

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

                client.schedule_new_workflow(
                    instance_id=instance_id,
                    workflow=single_enrichment_workflow,
                    input=workflow_input,
                )

                # Start a task to monitor this workflow for completion/failure/timeout
                monitor_task = asyncio.create_task(self._monitor_single_enrichment_workflow(instance_id, start_time))
                self.background_tasks.add(monitor_task)
                monitor_task.add_done_callback(self.background_tasks.discard)

                return instance_id

        except Exception as e:
            # Release semaphore on error
            self.semaphore.release()
            logger.exception(e, message="Error starting single enrichment workflow", pid=os.getpid())
            raise

    async def _monitor_single_enrichment_workflow(self, instance_id, workflow_start_time):
        """Monitor a single enrichment workflow until completion or timeout"""

        tracer = get_tracer("workflow_manager", monitoring_enabled)

        with tracer.start_as_current_span("monitor_single_enrichment_workflow") as current_span:
            current_span.set_attribute("workflow.instance_id", instance_id)
            current_span.set_attribute("workflow.monitor", True)

            try:
                try:
                    # Use wait_for to implement a timeout
                    final_status = await asyncio.wait_for(
                        self._wait_for_completion(instance_id, workflow_start_time),
                        timeout=self.max_execution_time,
                    )

                    processing_time = time.time() - workflow_start_time

                    await self.update_workflow_status(instance_id, final_status, processing_time)

                    logger.info(
                        "Single enrichment workflow completed",
                        instance_id=instance_id,
                        processing_time=f"{processing_time:.4f}s",
                        final_status=final_status,
                        pid=os.getpid(),
                    )

                except TimeoutError:
                    processing_time = time.time() - workflow_start_time

                    logger.warning(
                        "Single enrichment workflow timed out after exceeding maximum execution time",
                        instance_id=instance_id,
                        max_execution_time=f"{self.max_execution_time}s",
                        actual_time=f"{processing_time:.4f}s",
                        pid=os.getpid(),
                    )

                    try:
                        client = get_workflow_client()
                        if client:
                            client.terminate_workflow(instance_id, recursive=True)
                            logger.info(
                                "Single enrichment workflow terminated due to timeout",
                                instance_id=instance_id,
                                pid=os.getpid(),
                            )
                    except Exception as e:
                        logger.error(
                            "Failed to terminate timed-out single enrichment workflow",
                            instance_id=instance_id,
                            error=str(e),
                        )

                    # Update workflow status for timeout
                    await self.update_workflow_status(instance_id, "TIMEOUT", processing_time, "timeout")

            except Exception as e:
                # Handle any other misc. failures
                processing_time = time.time() - workflow_start_time

                logger.exception(
                    "Single enrichment workflow monitoring failed",
                    instance_id=instance_id,
                    processing_time=f"{processing_time:.4f}s",
                    error=str(e),
                    pid=os.getpid(),
                )

                # Update workflow status for error
                await self.update_workflow_status(instance_id, "ERROR", processing_time, str(e))

            finally:
                # Always clean up and release semaphore
                async with self.lock:
                    if instance_id in self.active_workflows:
                        del self.active_workflows[instance_id]

                # Release semaphore to allow next workflow
                self.semaphore.release()

    async def cleanup(self):
        """Clean up background tasks during shutdown"""
        logger.info("Cleaning up WorkflowManager background tasks")

        # Cancel all background tasks
        for task in self.background_tasks:
            if not task.done():
                task.cancel()

        # Wait for all tasks to complete/cancel
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)

        self.background_tasks.clear()
        logger.info("WorkflowManager cleanup completed")

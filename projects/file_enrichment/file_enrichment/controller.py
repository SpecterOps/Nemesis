# src/workflow/controller.py
import asyncio
import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

import common.helpers as helpers
from psycopg_pool import ConnectionPool
import structlog
from common.models import CloudEvent, File, NoseyParkerOutput
from dapr.clients import DaprClient
from dapr.ext.fastapi import DaprApp
from dapr.ext.workflow.workflow_state import WorkflowStatus
from fastapi import Body, FastAPI, HTTPException, Path
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.semconv.resource import ResourceAttributes
from pydantic import BaseModel

from file_enrichment.noseyparker import store_noseyparker_results

from .logging import configure_logging
from .workflow import (
    enrichment_workflow,
    get_workflow_client,
    initialize_workflow_runtime,
    shutdown_workflow_runtime,
    workflow_runtime,
    reload_yara_rules
)

configure_logging()
logger = structlog.get_logger(module=__name__)

resource = Resource.create(
    {
        ResourceAttributes.SERVICE_NAME: "workflow-controller",
        ResourceAttributes.SERVICE_VERSION: "1.0.0",
    }
)

otlp_exporter = OTLPSpanExporter(
    endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317"),
    headers=os.getenv("OTEL_EXPORTER_OTLP_HEADERS", ""),
    insecure=os.getenv("OTEL_EXPORTER_OTLP_SECURE", "false").lower() == "false",
)

trace_provider = TracerProvider(resource=resource)
span_processor = BatchSpanProcessor(otlp_exporter)
trace_provider.add_span_processor(span_processor)
trace.set_tracer_provider(trace_provider)
tracer = trace.get_tracer(__name__)

max_parallel_workflows = int(os.getenv("MAX_PARALLEL_WORKFLOWS", 3))  # maximum workflows that can run at a time
max_workflow_execution_time = int(
    os.getenv("MAX_WORKFLOW_EXECUTION_TIME", 300)
)  # maximum time (in seconds) until a workflow is killed
logger.info(f"max_parallel_workflows: {max_parallel_workflows}")
logger.info(f"max_workflow_execution_time: {max_workflow_execution_time}")

with DaprClient() as client:
    secret = client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_STRING")
    postgres_connection_string = secret.secret["POSTGRES_CONNECTION_STRING"]

pool = ConnectionPool(
    postgres_connection_string,
    min_size=max_parallel_workflows,
    max_size=(3 * max_parallel_workflows)
)

class EnrichmentRequest(BaseModel):
    object_id: str


class WorkflowManager:
    """Manages workflow execution with a simple queue system"""

    def __init__(self, max_concurrent=3, max_execution_time=300):
        """Initialize the workflow manager"""
        self.active_workflows = set()  # Set of active workflow IDs
        self.workflow_queue = asyncio.Queue()  # Queue for pending workflows
        self.max_concurrent = max_concurrent  # Maximum concurrent workflows
        self.lock = asyncio.Lock()  # For synchronizing access to shared state
        self.max_execution_time = max_execution_time  # max time (in seconds) until a workflow is killed

        logger.info("WorkflowManager initialized", max_concurrent=max_concurrent, max_execution_time=max_execution_time)

    def _get_status_string(self, state_obj):
        """Convert workflow state to string"""
        if state_obj.runtime_status == WorkflowStatus.FAILED:
            logger.warning(
                "Workflow failed",
                instance_id=state_obj.instance_id,
                error=state_obj.failure_details.message if state_obj.failure_details else "Unknown",
            )

        return state_obj.runtime_status.name

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
            with pool.connection() as conn:
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
                has_error=bool(error_message)
            )
        except Exception as e:
            logger.error(
                "Failed to update workflow status in database",
                instance_id=instance_id,
                status=status,
                error=str(e)
            )

    async def reset(self):
        """Reset the workflow manager's state."""
        async with self.lock:
            # Clear active workflows
            self.active_workflows.clear()

            # Clear the workflow queue
            while not self.workflow_queue.empty():
                try:
                    self.workflow_queue.get_nowait()
                    self.workflow_queue.task_done()
                except asyncio.QueueEmpty:
                    break

            # Reset workflows in database
            try:

                def reset_db_workflows():
                    with pool.connection() as conn:
                        with conn.cursor() as cur:
                            # Clear existing workflows
                            cur.execute("DELETE FROM workflows")
                            conn.commit()

                await asyncio.to_thread(reset_db_workflows)
            except Exception as e:
                logger.exception(e, message="Error resetting workflows in database")

            logger.warning(
                "WorkflowManager reset", active_count=len(self.active_workflows), queue_size=self.workflow_queue.qsize()
            )

            return {
                "status": "success",
                "message": "Workflow manager reset successfully",
                "timestamp": datetime.now().isoformat(),
            }

    async def start_workflow(self, workflow_input):
        """Start a workflow or queue it if at capacity"""
        async with self.lock:
            # Check if we're at capacity
            if len(self.active_workflows) >= self.max_concurrent:
                # Queue the workflow and return
                await self.workflow_queue.put(workflow_input)
                logger.info(
                    "Queued workflow - at capacity",
                    queue_size=self.workflow_queue.qsize(),
                    object_id=workflow_input["file"].get("object_id"),
                )
                return f"queued-{uuid.uuid4()}"

            # If not at capacity, then start the workflow immediately
            try:
                start_time = time.time()

                client = get_workflow_client()
                if client is None:
                    raise ValueError("Workflow client is None")

                # Start the workflow
                instance_id = client.schedule_new_workflow(workflow=enrichment_workflow, input=workflow_input)

                current_span = trace.get_current_span()
                if current_span:
                    # Add workflow ID to trace for Jaeger queries
                    current_span.set_attribute("workflow.instance_id", instance_id)
                    current_span.set_attribute("workflow.start", True)
                    current_span.set_attribute("workflow.type", "enrichment_workflow")
                    if "file" in workflow_input and "object_id" in workflow_input["file"]:
                        current_span.set_attribute("workflow.object_id", workflow_input["file"]["object_id"])

                # Extract and store metadata for tracking
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
                    with pool.connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                """
                                INSERT INTO workflows (wf_id, object_id, filename, status, start_time)
                                VALUES (%s, %s, %s, %s, %s)
                                """,
                                (instance_id, object_id, base_filename, "RUNNING", datetime.fromtimestamp(start_time)),
                            )
                            conn.commit()

                await asyncio.to_thread(store_workflow)

                # Add to active set
                self.active_workflows.add(instance_id)

                logger.info(
                    "Started workflow",
                    instance_id=instance_id,
                    object_id=object_id,
                    active_count=len(self.active_workflows),
                )

                # Start a task to monitor this workflow
                asyncio.create_task(self._monitor_workflow(instance_id, start_time))

                # Check queue for more work
                self._check_queue()

                return instance_id

            except Exception as e:
                logger.exception(e, message="Error starting workflow")
                raise

    def _check_queue(self):
        """Check if we can process more workflows from the queue"""
        # Schedule as a task so it doesn't block
        asyncio.create_task(self._process_queue())

    async def _process_queue(self) -> None:
        """Process pending workflows from the queue"""

        def store_workflow(
            instance_id: str,
            object_id: Optional[str],
            base_filename: Optional[str],
            start_time: float,
        ) -> None:
            with pool.connection() as conn:
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

        async with self.lock:
            # Process as many as we can from the queue
            while not self.workflow_queue.empty() and len(self.active_workflows) < self.max_concurrent:
                try:
                    # Get the next workflow input
                    workflow_input: dict = self.workflow_queue.get_nowait()

                    # Start the workflow
                    start_time: float = time.time()
                    client = get_workflow_client()

                    instance_id: str = client.schedule_new_workflow(workflow=enrichment_workflow, input=workflow_input)

                    # Add tracing for queued workflows
                    current_span = trace.get_current_span()
                    if current_span:
                        current_span.set_attribute("workflow.instance_id", instance_id)
                        current_span.set_attribute("workflow.start", True)
                        current_span.set_attribute("workflow.type", "enrichment_workflow")
                        current_span.set_attribute("workflow.queued", True)
                        if "file" in workflow_input and "object_id" in workflow_input["file"]:
                            current_span.set_attribute("workflow.object_id", workflow_input["file"]["object_id"])

                    # Extract and store metadata for tracking
                    base_filename: Optional[str] = None
                    object_id: Optional[str] = None
                    if "file" in workflow_input:
                        if "path" in workflow_input["file"]:
                            filepath: str = workflow_input["file"]["path"]
                            base_filename = os.path.basename(filepath)
                        if "object_id" in workflow_input["file"]:
                            object_id = workflow_input["file"].get("object_id")

                    # Store workflow in database
                    await asyncio.to_thread(store_workflow, instance_id, object_id, base_filename, start_time)

                    # Add to active set
                    self.active_workflows.add(instance_id)

                    logger.info(
                        "Started queued workflow",
                        instance_id=instance_id,
                        object_id=object_id,
                        queue_remaining=self.workflow_queue.qsize(),
                    )

                    # Create monitoring task
                    asyncio.create_task(self._monitor_workflow(instance_id, start_time))

                    # Mark as done
                    self.workflow_queue.task_done()

                except asyncio.QueueEmpty:
                    break
                except Exception as e:
                    logger.exception(e, message="Error starting queued workflow")
                    self.workflow_queue.task_done()  # Mark as done despite error

    async def _monitor_workflow(self, instance_id, start_time):
        """Monitor a workflow until completion or timeout"""
        try:
            current_span = trace.get_current_span()
            if current_span:
                current_span.set_attribute("workflow.instance_id", instance_id)
                current_span.set_attribute("workflow.monitor", True)

            # Wait for completion or timeout
            try:
                # Use wait_for to implement a timeout
                final_status = await asyncio.wait_for(self._wait_for_completion(instance_id), timeout=self.max_execution_time)

                processing_time = time.time() - start_time

                await self.update_workflow_status(instance_id, final_status, processing_time)

                # Remove from active set
                async with self.lock:
                    if instance_id in self.active_workflows:
                        self.active_workflows.remove(instance_id)

                    # Check if we can process more from queue
                    self._check_queue()

                logger.info("Workflow completed", instance_id=instance_id, processing_time=f"{processing_time:.2f}s", final_status=final_status)

            except TimeoutError:
                processing_time = time.time() - start_time

                logger.warning(
                    "Workflow timed out after exceeding maximum execution time",
                    instance_id=instance_id,
                    max_execution_time=f"{self.max_execution_time}s",
                    actual_time=f"{processing_time:.2f}s",
                )

                # Try to terminate the workflow
                try:
                    client = get_workflow_client()
                    if client:
                        client.terminate_workflow(instance_id)
                        logger.info("Workflow terminated due to timeout", instance_id=instance_id)
                except Exception as e:
                    logger.error("Failed to terminate timed-out workflow", instance_id=instance_id, error=str(e))

                # Update workflow status for timeout
                await self.update_workflow_status(instance_id, "TIMEOUT", processing_time, "timeout")

                # Remove from active set
                async with self.lock:
                    if instance_id in self.active_workflows:
                        self.active_workflows.remove(instance_id)

                    # Check if we can process more from queue
                    self._check_queue()

        except Exception as e:
            # Handle other failures
            processing_time = time.time() - start_time

            logger.exception(
                "Workflow monitoring failed",
                instance_id=instance_id,
                processing_time=f"{processing_time:.2f}s",
                error=str(e),
            )

            # Update workflow status for error
            await self.update_workflow_status(instance_id, "ERROR", processing_time, str(e))

            # Remove from active set and check queue
            async with self.lock:
                if instance_id in self.active_workflows:
                    self.active_workflows.remove(instance_id)

                # Check if we can process more from queue
                self._check_queue()

    async def _wait_for_completion(self, instance_id):
        """Wait for workflow to complete and return the final status"""
        start_time = datetime.now()
        error_count = 0

        client = get_workflow_client()

        # Add trace attributes for workflow status monitoring
        current_span = trace.get_current_span()
        if current_span:
            current_span.set_attribute("workflow.instance_id", instance_id)
            current_span.set_attribute("workflow.wait_for_completion", True)

        while True:
            try:
                state = await asyncio.to_thread(client.get_workflow_state, instance_id)
                status = self._get_status_string(state)
                error_count = 0  # Reset on successful check

                logger.debug(
                    "Workflow status check",
                    instance_id=instance_id,
                    status=status,
                    runtime=str(datetime.now() - start_time),
                )

                if status in ["COMPLETED", "FAILED", "TERMINATED", "ERROR"]:
                    runtime_seconds = (datetime.now() - start_time).total_seconds()
                    logger.info(
                        "Workflow finished",
                        instance_id=instance_id,
                        final_status=status,
                        runtime=str(datetime.now() - start_time),
                    )

                    # For failed workflows, capture the error message and update status
                    if status in ["FAILED", "TERMINATED", "ERROR"]:
                        error_msg = ""
                        if status == "FAILED" and state.failure_details:
                            error_msg = state.failure_details.message

                        await self.update_workflow_status(
                            instance_id,
                            status,
                            runtime_seconds,
                            error_msg[:100] if error_msg else status.lower()
                        )
                    else:
                        await self.update_workflow_status(
                            instance_id,
                            status,
                            runtime_seconds,
                            ""
                        )

                    # Return the actual status so _monitor_workflow knows what happened
                    return status

                await asyncio.sleep(0.1)

            except Exception as e:
                error_count += 1
                logger.warning(
                    f"Error checking workflow status: {str(e)}", instance_id=instance_id, error_count=error_count
                )

                if error_count >= 3:  # Break after 3 consecutive errors
                    logger.error(
                        "Too many consecutive errors checking workflow status",
                        instance_id=instance_id,
                        error_count=error_count,
                    )
                    # Return ERROR status so the monitoring can handle it appropriately
                    return "ERROR"

                await asyncio.sleep(0.5)

    async def get_status(self):
        """Get current status information with enhanced metrics from database"""
        try:
            async with self.lock:
                active_ids = list(self.active_workflows)
                current_queue_size = self.workflow_queue.qsize()

            logger.debug("Getting status", active_count=len(active_ids), queue_size=current_queue_size)

            # Get metrics and workflow information from database
            def get_db_metrics():
                with pool.connection() as conn:
                    with conn.cursor() as cur:
                        # Get metrics: counts and processing times
                        cur.execute("""
                            SELECT
                                COUNT(*) FILTER (WHERE status = 'COMPLETED') as completed_count,
                                COUNT(*) FILTER (WHERE status IN ('FAILED', 'TERMINATED', 'ERROR', 'TIMEOUT')) as failed_count,
                                AVG(runtime_seconds) as avg_time,
                                MIN(runtime_seconds) as min_time,
                                MAX(runtime_seconds) as max_time,
                                COUNT(runtime_seconds) as samples_count
                            FROM workflows
                            WHERE runtime_seconds IS NOT NULL
                        """)
                        metrics_row = cur.fetchone()
                        completed_count, failed_count, avg_time, min_time, max_time, samples_count = metrics_row

                        # Get active workflow details from database
                        cur.execute("""
                            SELECT
                                wf_id,
                                object_id,
                                status,
                                EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - start_time)) as runtime_seconds,
                                enrichments_success,
                                enrichments_failure,
                                filename
                            FROM workflows
                            WHERE status = 'RUNNING'
                        """)
                        active_workflows_db = []
                        for row in cur.fetchall():
                            wf_id, object_id, status, runtime_seconds, success_modules, failure_modules, filename = row

                            active_workflows_db.append(
                                {
                                    "id": wf_id,
                                    "status": status,
                                    "runtime_seconds": runtime_seconds,
                                    "filename": filename,
                                    "object_id": object_id,
                                    "success_modules": success_modules,
                                    "failure_modules": failure_modules,
                                }
                            )

                        # Get status counts
                        cur.execute("""
                            SELECT status, COUNT(*) FROM workflows GROUP BY status
                        """)
                        status_counts = {row[0]: row[1] for row in cur.fetchall()}

                        # Calculate percentiles
                        percentiles = {}
                        if samples_count >= 5:
                            cur.execute("""
                                SELECT
                                    percentile_cont(0.5) WITHIN GROUP (ORDER BY runtime_seconds) as p50,
                                    percentile_cont(0.9) WITHIN GROUP (ORDER BY runtime_seconds) as p90,
                                    percentile_cont(0.95) WITHIN GROUP (ORDER BY runtime_seconds) as p95,
                                    percentile_cont(0.99) WITHIN GROUP (ORDER BY runtime_seconds) as p99
                                FROM workflows
                                WHERE runtime_seconds IS NOT NULL
                            """)

                            result = cur.fetchone()
                            if result:
                                p50, p90, p95, p99 = result
                                percentiles = {
                                    "p50_seconds": round(float(p50), 2) if p50 is not None else None,
                                    "p90_seconds": round(float(p90), 2) if p90 is not None else None,
                                    "p95_seconds": round(float(p95), 2) if p95 is not None else None,
                                    "p99_seconds": round(float(p99), 2) if p99 is not None else None,
                                }

                        return {
                            "metrics": {
                                "completed_count": completed_count or 0,
                                "failed_count": failed_count or 0,
                                "total_processed": (completed_count or 0) + (failed_count or 0),
                                "success_rate": round(
                                    (completed_count or 0) / ((completed_count or 0) + (failed_count or 0)) * 100, 2
                                )
                                if ((completed_count or 0) + (failed_count or 0)) > 0
                                else None,
                                "processing_times": {
                                    "avg_seconds": round(avg_time, 2) if avg_time else None,
                                    "min_seconds": round(min_time, 2) if min_time else None,
                                    "max_seconds": round(max_time, 2) if max_time else None,
                                    "samples_count": samples_count or 0,
                                    **percentiles,
                                },
                            },
                            "status_counts": status_counts,
                            "active_workflows_db": active_workflows_db,
                        }

            # Get database metrics and status information
            db_info = await asyncio.to_thread(get_db_metrics)
            metrics = db_info["metrics"]
            status_counts = db_info["status_counts"]
            db_active_workflows = db_info["active_workflows_db"]

            # Get status for each active workflow from Dapr client as well (for comparison)
            active_statuses = []
            if active_ids:
                try:
                    client = get_workflow_client()
                    if client is None:
                        raise ValueError("Could not get workflow client")

                    for wf_id in active_ids:
                        try:
                            state = client.get_workflow_state(wf_id)
                            status = self._get_status_string(state)
                            # Get runtime for active workflows
                            if hasattr(state, "created_at") and state.created_at:
                                runtime = datetime.now() - state.created_at
                                runtime_seconds = runtime.total_seconds()
                            else:
                                runtime_seconds = None

                            # Find this workflow in our DB results
                            matching_db_workflow = next((w for w in db_active_workflows if w["id"] == wf_id), None)

                            # Combine information from both sources
                            workflow_info = {"id": wf_id, "status": status, "runtime_seconds": runtime_seconds}

                            if matching_db_workflow:
                                workflow_info["object_id"] = matching_db_workflow["object_id"]
                                workflow_info["filename"] = matching_db_workflow["filename"]
                                workflow_info["success_modules"] = matching_db_workflow["success_modules"]
                                workflow_info["failure_modules"] = matching_db_workflow["failure_modules"]

                            active_statuses.append(workflow_info)
                        except Exception as e:
                            logger.error("Error getting workflow state", workflow_id=wf_id, error=str(e))
                            active_statuses.append({"id": wf_id, "status": "ERROR", "error": str(e)})
                except Exception as e:
                    logger.error("Error getting workflow client", error=str(e))
                    # Use only database-based active workflows
                    active_statuses = db_active_workflows

            # If we have no active statuses from the client but do have from DB, use DB ones
            if not active_statuses and db_active_workflows:
                active_statuses = db_active_workflows

            status = {
                "queued_files": current_queue_size,
                "active_workflows": len(active_ids),
                "status_counts": status_counts,
                "active_details": active_statuses,
                "metrics": metrics,
                "timestamp": datetime.now().isoformat(),
            }

            logger.debug("Status response", status=status)
            return status

        except Exception as e:
            logger.exception(e, message="Error getting workflow status")
            # Try to get basic queue info even if other parts fail
            try:
                return {
                    "error": str(e),
                    "queued_files": self.workflow_queue.qsize(),
                    "active_workflows": len(self.active_workflows),
                    "active_details": [],
                    "metrics": {},
                    "timestamp": datetime.now().isoformat(),
                }
            except Exception as ee:
                return {
                    "error": f"Complete status failure: {ee}",
                    "queued_files": 0,
                    "active_workflows": 0,
                    "active_details": [],
                    "metrics": {},
                    "timestamp": datetime.now().isoformat(),
                }


module_execution_order = []
workflow_manager: WorkflowManager = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan manager for workflow runtime setup/teardown"""
    global module_execution_order, workflow_manager

    logger.info("Initializing workflow runtime...")

    try:
        # Initialize workflow runtime and modules
        module_execution_order = await initialize_workflow_runtime()
        # Wait for runtime to initialize
        await asyncio.sleep(5)

        # Test workflow client
        client = get_workflow_client()
        if client is None:
            raise ValueError("Workflow client not available after initialization")

        # Initialize workflow manager with our global ENV variables
        workflow_manager = WorkflowManager(
            max_concurrent=max_parallel_workflows, max_execution_time=max_workflow_execution_time
        )

        logger.info(
            "Workflow runtime initialized successfully",
            module_execution_order=module_execution_order,
            client_available=client is not None,
        )

    except Exception as e:
        logger.error("Failed to initialize workflow runtime", error=str(e))
        raise

    yield

    # Cleanup
    try:
        logger.info("Shutting down workflow runtime...")
        shutdown_workflow_runtime()
    except Exception as e:
        logger.error("Error during workflow runtime shutdown", error=str(e))


# Initialize FastAPI app with lifespan manager
app = FastAPI(lifespan=lifespan)
dapr_app = DaprApp(app)


@dapr_app.subscribe(pubsub="pubsub", topic="file")
async def process_file(event: CloudEvent[File]):
    """Handler for incoming file events"""

    try:
        file = event.data
        workflow_input = {
            "file": file.model_dump(exclude_unset=True, mode="json"),
            "execution_order": module_execution_order,
        }

        await workflow_manager.start_workflow(workflow_input)

    except Exception as e:
        logger.exception(e, message="Error processing file event", cloud_event=event)


@dapr_app.subscribe(pubsub="pubsub", topic="yara")
async def process_yara(event: CloudEvent):
    """Handler Yara events"""

    try:
        action = event.data['action']
        if action == 'reload':
            reload_yara_rules()
        else:
            logger.warning(f"Unsupported yara action: {action}")
    except Exception as e:
        logger.exception(e, message="Error processing Yara event", cloud_event=event)


@dapr_app.subscribe(pubsub="pubsub", topic="noseyparker-output")
async def process_nosey_parker_results(event: CloudEvent):
    """Handler for incoming Nosey Parker scan results"""
    try:
        # Extract the raw data
        raw_data = event.data
        logger.warning("Received NoseyParker output event")

        # Try to parse the event data into our NoseyParkerOutput model
        try:
            # If it's already a dict, use the from_dict factory method
            if isinstance(raw_data, dict):
                nosey_output = NoseyParkerOutput.from_dict(raw_data)
            # If it's a string, try to parse it as JSON
            elif isinstance(raw_data, str):
                import json

                parsed_data = json.loads(raw_data)
                nosey_output = NoseyParkerOutput.from_dict(parsed_data)
            else:
                logger.warning(f"Unexpected data type: {type(raw_data)}")
                return

            # Now process the properly parsed output
            object_id = nosey_output.object_id
            matches = nosey_output.scan_result.matches
            stats = nosey_output.scan_result.stats

            logger.debug(f"Found {len(matches)} matches for object {object_id}")

            # Store the findings in the database using our helper function
            await store_noseyparker_results(
                object_id=object_id,
                matches=matches,
                scan_stats=stats,
                postgres_connection_string=postgres_connection_string,
            )

        except Exception as parsing_error:
            # If parsing fails, fall back to direct dictionary access
            logger.warning(f"Error parsing NoseyParker output as model: {parsing_error}")

            if hasattr(raw_data, "get"):
                object_id = raw_data.get("object_id")
                scan_result = raw_data.get("scan_result", {})
                matches = scan_result.get("matches", [])
                stats = scan_result.get("stats", {})

                logger.debug(f"Using dict access: Found {len(matches)} matches for {object_id}")

                # Store the findings using direct dict access
                await store_noseyparker_results(
                    object_id=f"{object_id}",
                    matches=matches,
                    scan_stats=stats,
                    postgres_connection_string=postgres_connection_string,
                )

    except Exception as e:
        logger.exception(e, message="Error processing Nosey Parker output event")


@app.get("/status")
async def get_workflow_status():
    """Get current workflow system status."""
    try:
        status = await workflow_manager.get_status()
        return status
    except Exception as e:
        logger.exception(e, message="Error getting workflow status")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}") from e


@app.get("/llm_enrichments")
async def list_enabled_llm_enrichments():
    """List the enabled LLM enrichments based on environment variables."""
    try:
        if not workflow_runtime or not workflow_runtime.modules:
            raise HTTPException(status_code=503, detail="Workflow runtime or modules not initialized")

        llm_enrichments = []
        if os.getenv("RIGGING_GENERATOR_CREDENTIALS"):
            llm_enrichments.append("llm_credential_analysis")
        if os.getenv("RIGGING_GENERATOR_SUMMARY"):
            llm_enrichments.append("text_summarizer")
        if os.getenv("RIGGING_GENERATOR_TRIAGE"):
            llm_enrichments.append("finding_triage")

        return {"modules": llm_enrichments}

    except Exception as e:
        logger.exception(e, message="Error listing enabled LLM enrichment modules")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}") from e


@app.get("/enrichments")
async def list_enrichments():
    """List all available enrichment modules."""
    try:
        if not workflow_runtime or not workflow_runtime.modules:
            raise HTTPException(status_code=503, detail="Workflow runtime or modules not initialized")

        modules = list(workflow_runtime.modules.keys())
        return {"modules": modules}

    except Exception as e:
        logger.exception(e, message="Error listing enrichment modules")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}") from e


@app.post("/enrichments/{enrichment_name}")
async def run_enrichment(
    enrichment_name: str = Path(..., description="Name of the enrichment module to run"),
    request: EnrichmentRequest = Body(..., description="The enrichment request containing the object ID"),
):
    """Run a specific enrichment module directly."""

    try:
        # Check if module exists
        if not workflow_runtime or not workflow_runtime.modules:
            raise HTTPException(status_code=503, detail="Workflow runtime or modules not initialized")

        if enrichment_name not in workflow_runtime.modules:
            raise HTTPException(status_code=404, detail=f"Enrichment module '{enrichment_name}' not found")

        # Get the module
        module = workflow_runtime.modules[enrichment_name]

        # Check if we should process this file - run in thread since it might use sync operations
        should_process = await asyncio.to_thread(module.should_process, request.object_id)
        if not should_process:
            return {
                "status": "skipped",
                "message": f"Module {enrichment_name} decided to skip processing",
                "object_id": request.object_id,
                "instance_id": "",
            }

        # Process the file in a separate thread to avoid event loop conflicts
        result = await asyncio.to_thread(module.process, request.object_id)

        if result:
            # Store enrichment result in database
            def store_results():
                with pool.connection() as conn:
                    with conn.cursor() as cur:
                        # Store main enrichment result
                        results_escaped = json.dumps(helpers.sanitize_for_jsonb(result.model_dump(mode="json")))
                        cur.execute(
                            """
                            INSERT INTO enrichments (object_id, module_name, result_data)
                            VALUES (%s, %s, %s)
                            """,
                            (request.object_id, enrichment_name, results_escaped),
                        )

                        # Store any transforms
                        if result.transforms:
                            for transform in result.transforms:
                                cur.execute(
                                    """
                                    INSERT INTO transforms (object_id, type, transform_object_id, metadata)
                                    VALUES (%s, %s, %s, %s)
                                    """,
                                    (
                                        request.object_id,
                                        transform.type,
                                        transform.object_id,
                                        json.dumps(transform.metadata) if transform.metadata else None,
                                    ),
                                )

                        # Store any findings
                        if result.findings:
                            for finding in result.findings:
                                cur.execute(
                                    """
                                    INSERT INTO findings (
                                        finding_name, category, severity, object_id,
                                        origin_type, origin_name, raw_data, data
                                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                                    """,
                                    (
                                        finding.finding_name,
                                        finding.category,
                                        finding.severity,
                                        request.object_id,
                                        finding.origin_type,
                                        finding.origin_name,
                                        json.dumps(finding.raw_data),
                                        json.dumps([obj.model_dump() for obj in finding.data]),
                                    ),
                                )

                    conn.commit()

            # Run database operations in thread
            await asyncio.to_thread(store_results)

        return {
            "status": "success",
            "message": f"Completed enrichment with module '{enrichment_name}'",
            "object_id": request.object_id,
            "instance_id": str(uuid.uuid4()),  # Generate a unique instance ID
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(
            e, message="Error running enrichment module", enrichment_name=enrichment_name, object_id=request.object_id
        )
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}") from e


@app.get("/failed")
async def get_failed_workflows():
    """Get information about failed, error, and timed-out workflows from database."""
    try:
        # Query failed workflows from database
        def get_failed_workflows_from_db():
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT
                            wf_id as id,
                            object_id,
                            status,
                            runtime_seconds,
                            start_time,
                            enrichments_failure,
                            filename
                        FROM workflows
                        WHERE status IN ('FAILED', 'ERROR', 'TIMEOUT', 'TERMINATED')
                        ORDER BY start_time DESC
                        LIMIT 100
                    """)
                    columns = [desc[0] for desc in cur.description]
                    failed_workflows = []

                    for row in cur.fetchall():
                        workflow_dict = dict(zip(columns, row))

                        # Convert datetime to string
                        if "start_time" in workflow_dict:
                            workflow_dict["timestamp"] = workflow_dict["start_time"].isoformat()
                            del workflow_dict["start_time"]

                        # Add error from failure list if available
                        if workflow_dict.get("enrichments_failure") and len(workflow_dict["enrichments_failure"]) > 0:
                            workflow_dict["error"] = workflow_dict["enrichments_failure"][-1]  # Most recent failure

                        failed_workflows.append(workflow_dict)

                    return failed_workflows

        failed_workflows = await asyncio.to_thread(get_failed_workflows_from_db)

        return {
            "failed_count": len(failed_workflows),
            "workflows": failed_workflows,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        logger.exception(e, message="Error getting failed workflow information")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}") from e


@app.post("/reset")
async def reset_workflow_manager():
    """Reset the workflow manager's state."""
    try:
        if workflow_manager is None:
            raise HTTPException(status_code=503, detail="Workflow manager not initialized")

        result = await workflow_manager.reset()
        return result
    except Exception as e:
        logger.exception(e, message="Error resetting workflow manager")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}") from e


@app.api_route("/healthz", methods=["GET", "HEAD"])
async def healthcheck():
    """Health check endpoint for Docker healthcheck."""
    return {"status": "healthy"}


FastAPIInstrumentor.instrument_app(app, excluded_urls="healthz")

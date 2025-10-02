# src/workflow/controller.py
import asyncio
import json
import os
import random
from contextlib import asynccontextmanager

from common.logger import get_logger
from common.models import CloudEvent, File
from dapr.clients import DaprClient
from dapr.ext.fastapi import DaprApp
from fastapi import FastAPI
from file_enrichment.postgres_notifications import postgres_notify_listener
from nemesis_dpapi import DpapiManager as NemesisDpapiManager
from nemesis_dpapi.eventing import DaprDpapiEventPublisher
from psycopg_pool import ConnectionPool

from .routes.dpapi import dpapi_background_monitor, dpapi_router
from .routes.enrichments import router as enrichments_router
from .subscriptions.bulk_enrichment_handler import process_bulk_enrichment_event
from .subscriptions.dotnet_handler import process_dotnet_event
from .subscriptions.file_handler import process_file_event
from .subscriptions.noseyparker_handler import process_noseyparker_event
from .workflow import get_workflow_client, initialize_workflow_runtime, shutdown_workflow_runtime, workflow_runtime
from .workflow_manager import WorkflowManager

logger = get_logger(__name__)

max_parallel_workflows = int(os.getenv("MAX_PARALLEL_WORKFLOWS", 3))  # maximum workflows that can run at a time
max_workflow_execution_time = int(
    os.getenv("MAX_WORKFLOW_EXECUTION_TIME", 300)
)  # maximum time (in seconds) until a workflow is killed

logger.info(f"max_parallel_workflows: {max_parallel_workflows}", pid=os.getpid())
logger.info(f"max_workflow_execution_time: {max_workflow_execution_time}", pid=os.getpid())

with DaprClient() as client:
    secret = client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_STRING")
    postgres_connection_string = secret.secret["POSTGRES_CONNECTION_STRING"]

pool = ConnectionPool(
    postgres_connection_string, min_size=max_parallel_workflows, max_size=(3 * max_parallel_workflows)
)

module_execution_order = []
workflow_manager: WorkflowManager = None

# Global tracking for bulk enrichment processes
bulk_enrichment_tasks = {}  # {enrichment_name: task_info}
bulk_enrichment_lock = asyncio.Lock()

postgres_notify_listener_task = None
background_dpapi_task = None


async def recover_interrupted_workflows():
    """
    Recover workflows that were interrupted during system shutdown.

    NOTE/TODO:  if using multiple replicas or k8s, this process should be moved
                into a single instance and not replicated multiple times
    """
    try:
        # Tandom sleep delay to help with the worker overlap on recovery
        #   This, combined with the single atomic DELETE query, should
        #   ensure that only one worker will recover the workflows.
        delay = random.uniform(0, 10)
        logger.info(f"Workflow recovery starting in {delay:.1f} seconds...", pid=os.getpid())
        await asyncio.sleep(delay)

        logger.info("Starting workflow recovery process...", pid=os.getpid())

        def get_and_delete_running_workflows():
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    # Atomic DELETE with RETURNING - only one worker will get the interrupted workflows
                    cur.execute("""
                        DELETE FROM workflows
                        WHERE status = 'RUNNING'
                        RETURNING object_id
                    """)
                    running_ids = [row[0] for row in cur.fetchall()]
                    conn.commit()

                    if running_ids:
                        logger.info(f"Atomically claimed {len(running_ids)} interrupted workflows", pid=os.getpid())

                    return running_ids

        def get_file_data_and_cleanup(object_ids):
            recovered_files = []
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    for object_id in object_ids:
                        # Get file data for reconstruction
                        cur.execute(
                            """
                            SELECT object_id, agent_id, source, project, timestamp, expiration,
                                   path, originating_object_id, originating_container_id, nesting_level,
                                   file_creation_time, file_access_time, file_modification_time
                            FROM files WHERE object_id = %s
                        """,
                            (object_id,),
                        )

                        row = cur.fetchone()
                        if row:
                            # Convert database row to File-compatible dict
                            file_data = {
                                "object_id": str(row[0]),
                                "agent_id": row[1],
                                "source": row[2],
                                "project": row[3],
                                "timestamp": row[4],
                                "expiration": row[5],
                                "path": row[6],
                                "originating_object_id": str(row[7]) if row[7] else None,
                                "originating_container_id": str(row[8]) if row[8] else None,
                                "nesting_level": row[9],
                                "creation_time": row[10].isoformat() if row[10] else None,
                                "access_time": row[11].isoformat() if row[11] else None,
                                "modification_time": row[12].isoformat() if row[12] else None,
                            }
                            recovered_files.append(file_data)
                            logger.debug("Recovered file data for workflow", object_id=object_id, pid=os.getpid())
                        else:
                            logger.warning("No file data found for workflow", object_id=object_id, pid=os.getpid())

                    conn.commit()

            return recovered_files

        # Get interrupted workflows
        running_object_ids = await asyncio.to_thread(get_and_delete_running_workflows)

        if not running_object_ids:
            logger.info("No interrupted workflows found", pid=os.getpid())
            return

        logger.info(f"Found {len(running_object_ids)} interrupted workflows to recover", pid=os.getpid())

        # Get file data and clean up partial results
        recovered_files = await asyncio.to_thread(get_file_data_and_cleanup, running_object_ids)

        if not recovered_files:
            logger.warning("No file data found for interrupted workflows", pid=os.getpid())
            return

        # Republish recovered files with priority
        with DaprClient() as client:
            for file_data in recovered_files:
                try:
                    # Filter out None values for File object creation
                    clean_file_data = {k: v for k, v in file_data.items() if v is not None}

                    # Create File object from recovered data
                    file_obj = File(**clean_file_data)

                    # Publish with priority=3 for immediate processing
                    client.publish_event(
                        pubsub_name="pubsub",
                        topic_name="file",
                        data=json.dumps(file_obj.model_dump(exclude_unset=True, mode="json")),
                        data_content_type="application/json",
                        metadata=[("priority", "3")],
                    )

                    logger.info("Republished interrupted workflow", object_id=file_data["object_id"], pid=os.getpid())

                except Exception as e:
                    logger.exception(f"Failed to republish workflow {file_data['object_id']}: {e}")
                    logger.error("File data that caused error", file_data=file_data)

        logger.info(f"Successfully recovered {len(recovered_files)} interrupted workflows", pid=os.getpid())

    except Exception as e:
        logger.exception("Error during workflow recovery", error=str(e), pid=os.getpid())
        # Don't raise - we want the service to continue even if recovery fails


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan manager for workflow runtime setup/teardown"""
    global module_execution_order, workflow_manager, postgres_notify_listener_task, background_dpapi_task

    logger.info("Initializing workflow runtime...", pid=os.getpid())

    app.state.event_loop = asyncio.get_running_loop()

    # Initialize global DpapiManager for the application lifetime
    dapr_client = DaprClient()
    secret = dapr_client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_STRING")
    postgres_connection_string = secret.secret["POSTGRES_CONNECTION_STRING"]

    dpapi_manager = NemesisDpapiManager(
        storage_backend=postgres_connection_string,
        auto_decrypt=True,
        publisher=DaprDpapiEventPublisher(dapr_client, loop=app.state.event_loop),
    )
    await dpapi_manager.__aenter__()
    app.state.dpapi_manager = dpapi_manager

    try:
        # Initialize workflow runtime and modules
        module_execution_order = await initialize_workflow_runtime()

        # Wait a bit for runtime to initialize
        await asyncio.sleep(5)

        client = get_workflow_client()
        if client is None:
            raise ValueError("Workflow client not available after initialization")

        workflow_manager = WorkflowManager(
            max_concurrent=max_parallel_workflows, max_execution_time=max_workflow_execution_time
        )

        # Start PostgreSQL NOTIFY listener in background
        postgres_notify_listener_task = asyncio.create_task(
            postgres_notify_listener(postgres_connection_string, workflow_manager)
        )
        logger.info("Started PostgreSQL NOTIFY listener task", pid=os.getppid())

        # Start masterkey watcher in background
        background_dpapi_task = asyncio.create_task(dpapi_background_monitor(app.state.dpapi_manager))
        logger.info("Started masterkey watcher task", pid=os.getpid())

        # Recover any interrupted workflows before starting normal processing
        await recover_interrupted_workflows()

        logger.info(
            "Workflow runtime initialized successfully",
            module_execution_order=module_execution_order,
            client_available=client is not None,
            pid=os.getpid(),
        )

    except Exception as e:
        logger.error("Failed to initialize workflow runtime", error=str(e), pid=os.getpid())
        raise

    yield

    try:
        logger.info("Shutting down workflow runtime...", pid=os.getpid())

        # Cleanup DpapiManager
        if hasattr(app.state, "dpapi_manager") and app.state.dpapi_manager:
            logger.info("Closing DpapiManager...", pid=os.getpid())
            await app.state.dpapi_manager.__aexit__(None, None, None)

        # Cancel masterkey watcher task
        if background_dpapi_task and not background_dpapi_task.done():
            logger.info("Cancelling masterkey watcher task...", pid=os.getpid())
            background_dpapi_task.cancel()
            try:
                await background_dpapi_task
            except asyncio.CancelledError:
                logger.info("Masterkey watcher task cancelled", pid=os.getpid())

        # Cancel PostgreSQL NOTIFY listener
        if postgres_notify_listener_task and not postgres_notify_listener_task.done():
            logger.info("Cancelling PostgreSQL NOTIFY listener...", pid=os.getppid())
            postgres_notify_listener_task.cancel()
            try:
                await postgres_notify_listener_task
            except asyncio.CancelledError:
                logger.info("PostgreSQL NOTIFY listener cancelled", pid=os.getppid())

        # Clean up workflow manager background tasks
        if workflow_manager:
            await workflow_manager.cleanup()

        shutdown_workflow_runtime()

        dapr_client.close()
    except Exception as e:
        logger.error("Error during workflow runtime shutdown", error=str(e), pid=os.getpid())


# Initialize FastAPI app with lifespan manager
app = FastAPI(lifespan=lifespan)
dapr_app = DaprApp(app)

# region API Routers/Endpoints
app.include_router(dpapi_router)
app.include_router(enrichments_router)


@app.api_route("/healthz", methods=["GET", "HEAD"])
async def healthcheck():
    """Health check endpoint for Docker healthcheck."""
    return {"status": "healthy"}


# endregion


# region Dapr Subscriptions
@dapr_app.subscribe(pubsub="pubsub", topic="file")
async def process_file(event: CloudEvent[File]):
    """Handler for incoming file events"""
    global workflow_manager
    await process_file_event(event.data, workflow_manager, module_execution_order, pool)


@dapr_app.subscribe(pubsub="pubsub", topic="dotnet-output")
async def process_dotnet_results(event: CloudEvent):
    """Handler for incoming .NET processing results from the dotnet_service."""
    await process_dotnet_event(event.data, postgres_connection_string)


@dapr_app.subscribe(pubsub="pubsub", topic="noseyparker-output")
async def process_nosey_parker_results(event: CloudEvent):
    """Handler for incoming Nosey Parker scan results"""
    await process_noseyparker_event(event.data, postgres_connection_string)


@dapr_app.subscribe(pubsub="pubsub", topic="bulk-enrichment-task")
async def process_bulk_enrichment_task(event: CloudEvent):
    """Handler for individual bulk enrichment tasks"""
    global workflow_manager
    await process_bulk_enrichment_event(event.data, workflow_manager, workflow_runtime)

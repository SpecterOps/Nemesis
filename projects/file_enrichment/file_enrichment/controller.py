# src/workflow/controller.py
import asyncio
import json
import os
import random
from contextlib import asynccontextmanager
from datetime import datetime

import psycopg
from common.logger import get_logger
from common.models import CloudEvent, DotNetOutput, File, NoseyParkerOutput
from common.state_helpers import get_file_enriched
from dapr.clients import DaprClient
from dapr.ext.fastapi import DaprApp
from fastapi import FastAPI
from file_enrichment.dotnet import store_dotnet_results
from file_enrichment.noseyparker import store_noseyparker_results
from nemesis_dpapi import DpapiManager as NemesisDpapiManager
from nemesis_dpapi.eventing import DaprDpapiEventPublisher
from psycopg_pool import ConnectionPool

from .routes.dpapi import dpapi_background_monitor, dpapi_router
from .routes.enrichments import router as enrichments_router
from .workflow import (
    get_workflow_client,
    initialize_workflow_runtime,
    reload_yara_rules,
    shutdown_workflow_runtime,
    workflow_runtime,
)
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

# PostgreSQL LISTEN/NOTIFY client
notify_listener_task = None


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


async def postgres_notify_listener():
    """
    Listen for PostgreSQL NOTIFY events for yara reload and workflow reset.
    Runs in background task to handle notifications across all workers/replicas.
    """
    global workflow_manager

    logger.info("Starting PostgreSQL NOTIFY listener...", pid=os.getppid())

    retry_delay = 1  # Start with 1 second retry delay
    max_retry_delay = 60  # Max 60 seconds between retries

    while True:
        try:
            # Use async connection for LISTEN
            async with await psycopg.AsyncConnection.connect(postgres_connection_string, autocommit=True) as conn:
                logger.info("Connected to PostgreSQL for NOTIFY listening", pid=os.getppid())
                retry_delay = 1  # Reset retry delay on successful connection

                # Listen to our notification channels
                await conn.execute("LISTEN nemesis_yara_reload")
                await conn.execute("LISTEN nemesis_workflow_reset")

                logger.info(
                    "Listening for PostgreSQL notifications on nemesis_yara_reload and nemesis_workflow_reset",
                    pid=os.getppid(),
                )

                # Process notifications with timeout to prevent hanging
                try:
                    async for notify in conn.notifies():
                        try:
                            logger.info(
                                f"Received PostgreSQL notification: channel={notify.channel}, payload={notify.payload}, pid={os.getpid()}"
                            )

                            if notify.channel == "nemesis_yara_reload":
                                logger.info("Processing yara reload notification", pid=os.getppid())
                                reload_yara_rules()

                            elif notify.channel == "nemesis_workflow_reset":
                                logger.info("Processing workflow reset notification", pid=os.getppid())
                                if workflow_manager is not None:
                                    result = await workflow_manager.reset()
                                    logger.info("Workflow manager reset completed", result=result)
                                else:
                                    logger.warning("Workflow manager not initialized, skipping reset")

                        except Exception as e:
                            logger.exception(
                                "Error processing PostgreSQL notification",
                                channel=notify.channel,
                                payload=notify.payload,
                                error=str(e),
                                pid=os.getpid(),
                            )
                except asyncio.CancelledError:
                    logger.info("PostgreSQL NOTIFY listener cancelled", pid=os.getppid())
                    break
                except Exception as e:
                    logger.exception("Error in notification loop", error=str(e), pid=os.getpid())
                    raise

        except Exception as e:
            logger.exception("PostgreSQL NOTIFY listener connection error", error=str(e), pid=os.getppid())

            # Exponential backoff with jitter
            await asyncio.sleep(retry_delay + (retry_delay * 0.1))  # Add 10% jitter
            retry_delay = min(retry_delay * 2, max_retry_delay)

            logger.info(f"Retrying PostgreSQL NOTIFY listener in {retry_delay} seconds...", pid=os.getppid())


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan manager for workflow runtime setup/teardown"""
    global module_execution_order, workflow_manager, notify_listener_task, background_dpapi_task

    logger.info("Initializing workflow runtime...", pid=os.getpid())

    app.state.event_loop = asyncio.get_running_loop()

    # Initialize global DpapiManager for the application lifetime
    with DaprClient() as dapr_client:
        secret = dapr_client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_STRING")
        dpapi_postgres_connection_string = secret.secret["POSTGRES_CONNECTION_STRING"]

    dpapi_manager = NemesisDpapiManager(
        storage_backend=dpapi_postgres_connection_string,
        auto_decrypt=True,
        publisher=DaprDpapiEventPublisher(DaprClient(), loop=app.state.event_loop),
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
        notify_listener_task = asyncio.create_task(postgres_notify_listener())
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
        if hasattr(app.state, 'dpapi_manager') and app.state.dpapi_manager:
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
        if notify_listener_task and not notify_listener_task.done():
            logger.info("Cancelling PostgreSQL NOTIFY listener...", pid=os.getppid())
            notify_listener_task.cancel()
            try:
                await notify_listener_task
            except asyncio.CancelledError:
                logger.info("PostgreSQL NOTIFY listener cancelled", pid=os.getppid())

        # Clean up workflow manager background tasks
        if workflow_manager:
            await workflow_manager.cleanup()

        shutdown_workflow_runtime()
    except Exception as e:
        logger.error("Error during workflow runtime shutdown", error=str(e), pid=os.getpid())


# Initialize FastAPI app with lifespan manager
app = FastAPI(lifespan=lifespan)
dapr_app = DaprApp(app)

# Include routers
app.include_router(dpapi_router)
app.include_router(enrichments_router)

background_dpapi_task = None


async def save_file_message(file: File):
    """Save the file message to the database for recovery purposes"""
    try:
        # Only save files that are not nested (originating files)
        if file.nesting_level and file.nesting_level > 0:
            logger.debug(
                "nesting_level > 0, not saving file message",
                nesting_level=file.nesting_level,
                object_id=file.object_id,
                pid=os.getpid(),
            )
            return

        def save_to_db():
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    query = """
                    INSERT INTO files (
                        object_id, agent_id, source, project, timestamp, expiration,
                        path, originating_object_id, originating_container_id, nesting_level,
                        file_creation_time, file_access_time, file_modification_time
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    ) ON CONFLICT (object_id) DO UPDATE SET
                        agent_id = EXCLUDED.agent_id,
                        source = EXCLUDED.source,
                        project = EXCLUDED.project,
                        timestamp = EXCLUDED.timestamp,
                        expiration = EXCLUDED.expiration,
                        path = EXCLUDED.path,
                        originating_object_id = EXCLUDED.originating_object_id,
                        originating_container_id = EXCLUDED.originating_container_id,
                        nesting_level = EXCLUDED.nesting_level,
                        file_creation_time = EXCLUDED.file_creation_time,
                        file_access_time = EXCLUDED.file_access_time,
                        file_modification_time = EXCLUDED.file_modification_time,
                        updated_at = CURRENT_TIMESTAMP;
                    """

                    cur.execute(
                        query,
                        (
                            file.object_id,
                            file.agent_id,
                            file.source,
                            file.project,
                            file.timestamp,
                            file.expiration,
                            file.path,
                            file.originating_object_id,
                            getattr(file, "originating_container_id", None),
                            file.nesting_level,
                            datetime.fromisoformat(file.creation_time) if file.creation_time else None,
                            datetime.fromisoformat(file.access_time) if file.access_time else None,
                            datetime.fromisoformat(file.modification_time) if file.modification_time else None,
                        ),
                    )
                    conn.commit()

        await asyncio.to_thread(save_to_db)
        logger.debug("Successfully saved file message to database", object_id=file.object_id, pid=os.getpid())

    except Exception as e:
        logger.exception(e, message="Error saving file message to database", object_id=file.object_id, pid=os.getpid())
        raise


@dapr_app.subscribe(pubsub="pubsub", topic="file")
async def process_file(event: CloudEvent[File]):
    """Handler for incoming file events"""
    global workflow_manager
    try:
        file = event.data

        # Save the file message to database first for recovery purposes
        await save_file_message(file)

        workflow_input = {
            "file": file.model_dump(exclude_unset=True, mode="json"),
            "execution_order": module_execution_order,
        }

        # This will block if we're at max capacity, providing natural backpressure
        await workflow_manager.start_workflow(workflow_input)

    except Exception as e:
        logger.exception(e, message="Error processing file event", cloud_event=event, pid=os.getpid())


# Removed process_yara - replaced by PostgreSQL NOTIFY listener


@dapr_app.subscribe(pubsub="pubsub", topic="dotnet-output")
async def process_dotnet_results(event: CloudEvent):
    """Handler for incoming .NET processing results from the dotnet_service."""
    try:
        raw_data = event.data
        logger.debug(f"Received DotNet output event: {raw_data}", pid=os.getpid())

        # Try to parse the event data into our DotNetOutput model
        try:
            # If it's already a dict, use it directly
            if isinstance(raw_data, dict):
                dotnet_output = DotNetOutput(**raw_data)
            # If it's a string, try to parse it as JSON
            elif isinstance(raw_data, str):
                import json

                parsed_data = json.loads(raw_data)
                dotnet_output = DotNetOutput(**parsed_data)
            else:
                logger.warning(f"Unexpected data type: {type(raw_data)}", pid=os.getpid())
                return

            object_id = dotnet_output.object_id
            decompilation_object_id = dotnet_output.decompilation
            analysis = dotnet_output.get_parsed_analysis()

            logger.debug(f"Processing dotnet results for object {object_id}", pid=os.getpid())

            # Get the file enriched data for creating transforms
            file_enriched = None
            try:
                file_enriched = get_file_enriched(object_id)
            except Exception as e:
                logger.warning(f"Could not get file_enriched for {object_id}: {e}", pid=os.getpid())

            # Store the results in the database using our helper function
            await store_dotnet_results(
                object_id=object_id,
                decompilation_object_id=decompilation_object_id,
                analysis=analysis,
                postgres_connection_string=postgres_connection_string,
                file_enriched=file_enriched,
            )

        except Exception as parsing_error:
            # If parsing fails, log the error and try to extract what we can
            logger.warning(f"Error parsing DotNet output as model: {parsing_error}", pid=os.getpid())
            logger.debug(f"Raw data: {raw_data}", pid=os.getpid())

            # Try to extract object_id at minimum for logging
            object_id = None
            if hasattr(raw_data, "get"):
                object_id = raw_data.get("object_id")
            elif isinstance(raw_data, dict):
                object_id = raw_data.get("object_id")

            logger.error(f"Failed to process DotNet output for object_id: {object_id}", pid=os.getpid())

    except Exception as e:
        logger.exception(e, message="Error processing DotNet output event", pid=os.getpid())


@dapr_app.subscribe(pubsub="pubsub", topic="noseyparker-output")
async def process_nosey_parker_results(event: CloudEvent):
    """Handler for incoming Nosey Parker scan results"""
    try:
        # Extract the raw data
        raw_data = event.data
        # logger.debug(f"Received NoseyParker output event: {raw_data}", pid=os.getpid())

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
                logger.warning(f"Unexpected data type: {type(raw_data)}", pid=os.getpid())
                return

            # Now process the properly parsed output
            object_id = nosey_output.object_id
            matches = nosey_output.scan_result.matches
            stats = nosey_output.scan_result.stats

            logger.debug(f"Found {len(matches)} matches for object {object_id}", pid=os.getpid())

            # Store the findings in the database using our helper function
            await store_noseyparker_results(
                object_id=object_id,
                matches=matches,
                scan_stats=stats,
                postgres_connection_string=postgres_connection_string,
            )

        except Exception as parsing_error:
            # If parsing fails, fall back to direct dictionary access
            logger.warning(f"Error parsing NoseyParker output as model: {parsing_error}", pid=os.getpid())

            if hasattr(raw_data, "get"):
                object_id = raw_data.get("object_id")
                scan_result = raw_data.get("scan_result", {})
                matches = scan_result.get("matches", [])
                stats = scan_result.get("stats", {})

                logger.debug(f"Using dict access: Found {len(matches)} matches for {object_id}", pid=os.getpid())

                # Store the findings using direct dict access
                await store_noseyparker_results(
                    object_id=f"{object_id}",
                    matches=matches,
                    scan_stats=stats,
                    postgres_connection_string=postgres_connection_string,
                )

    except Exception as e:
        logger.exception(e, message="Error processing Nosey Parker output event", pid=os.getpid())


@dapr_app.subscribe(pubsub="pubsub", topic="bulk-enrichment-task")
async def process_bulk_enrichment_task(event: CloudEvent):
    """Handler for individual bulk enrichment tasks"""
    global workflow_manager
    try:
        data = event.data
        enrichment_name = data.get("enrichment_name")
        object_id = data.get("object_id")
        bulk_id = data.get("bulk_id")

        logger.debug(
            "Received bulk enrichment task", enrichment_name=enrichment_name, object_id=object_id, bulk_id=bulk_id
        )

        # Check if module exists
        if not workflow_runtime or not workflow_runtime.modules:
            logger.error("Workflow runtime or modules not initialized")
            return

        if enrichment_name not in workflow_runtime.modules:
            logger.error(f"Enrichment module '{enrichment_name}' not found")
            return

        # Prepare workflow input for single enrichment
        workflow_input = {"enrichment_name": enrichment_name, "object_id": object_id, "bulk_id": bulk_id}

        # This will block if we're at max capacity, providing natural backpressure
        await workflow_manager.start_workflow_single_enrichment(workflow_input)

    except Exception as e:
        logger.exception("Error processing bulk enrichment task", cloud_event=event, error=str(e))


@app.api_route("/healthz", methods=["GET", "HEAD"])
async def healthcheck():
    """Health check endpoint for Docker healthcheck."""
    return {"status": "healthy"}

import asyncio
import os
from contextlib import asynccontextmanager

import asyncpg
from common.db import get_postgres_connection_str
from common.logger import get_logger
from common.models import BulkEnrichmentEvent, CloudEvent, DotNetOutput, File, NoseyParkerOutput
from common.workflows.setup import set_fastapi_loop
from dapr.clients import DaprClient
from dapr.ext.fastapi import DaprApp
from fastapi import FastAPI
from file_enrichment.postgres_notifications import postgres_notify_listener
from file_enrichment.workflow_recovery import recover_interrupted_workflows
from file_linking import FileLinkingEngine
from nemesis_dpapi import DpapiManager as NemesisDpapiManager
from nemesis_dpapi.eventing import DaprDpapiEventPublisher

from . import global_vars
from .debug_utils import setup_debug_signals
from .routes.dpapi import dpapi_background_monitor, dpapi_router
from .routes.enrichments import router as enrichments_router
from .subscriptions.bulk_enrichment import process_bulk_enrichment_event
from .subscriptions.dotnet import process_dotnet_event
from .subscriptions.file import process_file_event
from .subscriptions.noseyparker import process_noseyparker_event
from .workflow import initialize_workflow_runtime, wf_runtime
from .workflow_manager import WorkflowManager

logger = get_logger(__name__)

max_workflow_execution_time = int(
    os.getenv("MAX_WORKFLOW_EXECUTION_TIME", 300)
)  # maximum time (in seconds) until a workflow is killed

logger.info(f"max_workflow_execution_time: {max_workflow_execution_time}", pid=os.getpid())

module_execution_order = []
workflow_manager: WorkflowManager = None

# Global tracking for bulk enrichment processes
bulk_enrichment_tasks = {}  # {enrichment_name: task_info}
bulk_enrichment_lock = asyncio.Lock()

postgres_notify_listener_task = None
background_dpapi_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan manager for workflow runtime setup/teardown"""
    global module_execution_order, workflow_manager, postgres_notify_listener_task, background_dpapi_task

    logger.info("Initializing workflow runtime...", pid=os.getpid())

    setup_debug_signals()

    app.state.event_loop = asyncio.get_running_loop()
    set_fastapi_loop(asyncio.get_event_loop())

    dapr_client = DaprClient()
    postgres_connection_string = get_postgres_connection_str(dapr_client)

    global_vars.asyncpg_pool = await asyncpg.create_pool(
        postgres_connection_string,
        min_size=5,
        max_size=100,
    )

    global_vars.file_linking_engine = FileLinkingEngine(global_vars.asyncpg_pool)

    dpapi_manager = NemesisDpapiManager(
        storage_backend=global_vars.asyncpg_pool,
        auto_decrypt=True,
        publisher=DaprDpapiEventPublisher(dapr_client, loop=app.state.event_loop),
    )
    await dpapi_manager.__aenter__()
    app.state.dpapi_manager = dpapi_manager

    # Initialize workflow runtime and modules
    module_execution_order = await initialize_workflow_runtime(dpapi_manager)

    # Wait a bit for runtime to initialize
    await asyncio.sleep(5)

    try:
        # Use async context manager for WorkflowManager
        async with WorkflowManager(
            pool=global_vars.asyncpg_pool, max_execution_time=max_workflow_execution_time
        ) as wf_manager:
            workflow_manager = wf_manager

            try:
                # Start PostgreSQL NOTIFY listener in background
                postgres_notify_listener_task = asyncio.create_task(
                    postgres_notify_listener(global_vars.asyncpg_pool, workflow_manager)
                )
                logger.info("Started PostgreSQL NOTIFY listener task")

                # Start masterkey watcher in background
                background_dpapi_task = asyncio.create_task(dpapi_background_monitor(app.state.dpapi_manager))
                logger.info("Started masterkey watcher task")

                # Recover any interrupted workflows before starting normal processing
                await recover_interrupted_workflows(global_vars.asyncpg_pool)

                logger.info(
                    "Workflow runtime initialized successfully",
                    module_execution_order=module_execution_order,
                    pid=os.getpid(),
                )

                yield

            finally:
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
                    logger.info("Cancelling PostgreSQL NOTIFY listener...")
                    postgres_notify_listener_task.cancel()
                    try:
                        await postgres_notify_listener_task
                    except asyncio.CancelledError:
                        logger.info("PostgreSQL NOTIFY listener cancelled")

                if wf_runtime:
                    wf_runtime.shutdown()

                dapr_client.close()

    finally:
        if global_vars.asyncpg_pool:
            await global_vars.asyncpg_pool.close()
            logger.info("AsyncPG pool closed", pid=os.getpid())


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
    await process_file_event(event.data, workflow_manager, module_execution_order)


@dapr_app.subscribe(pubsub="pubsub", topic="dotnet-output")
async def process_dotnet_results(event: CloudEvent[DotNetOutput]):
    """Handler for incoming .NET processing results from the dotnet_service."""
    await process_dotnet_event(event.data)


@dapr_app.subscribe(pubsub="pubsub", topic="noseyparker-output")
async def process_nosey_parker_results(event: CloudEvent[NoseyParkerOutput]):
    """Handler for incoming Nosey Parker scan results"""
    await process_noseyparker_event(event.data)


@dapr_app.subscribe(pubsub="pubsub", topic="bulk-enrichment-task")
async def process_bulk_enrichment_task(event: CloudEvent[BulkEnrichmentEvent]):
    """Handler for individual bulk enrichment tasks"""
    global workflow_manager
    import file_enrichment.global_vars as global_vars

    await process_bulk_enrichment_event(event.data, workflow_manager, global_vars.global_module_map)

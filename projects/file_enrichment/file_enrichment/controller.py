import asyncio
import os
from contextlib import asynccontextmanager

import asyncpg
from common.db import get_postgres_connection_str
from common.logger import get_logger
from common.models import CloudEvent, File
from common.workflows.setup import set_fastapi_loop
from dapr.clients import DaprClient
from dapr.ext.fastapi import DaprApp
from fastapi import FastAPI
from file_enrichment.postgres_notifications import postgres_notify_listener
from file_enrichment.workflow_recovery import recover_interrupted_workflows
from nemesis_dpapi import DpapiManager as NemesisDpapiManager
from nemesis_dpapi.eventing import DaprDpapiEventPublisher
from psycopg_pool import ConnectionPool

from .debug_utils import setup_debug_signals
from .routes.dpapi import dpapi_background_monitor, dpapi_router
from .routes.enrichments import router as enrichments_router
from .subscriptions.bulk_enrichment_handler import process_bulk_enrichment_event
from .subscriptions.dotnet_handler import process_dotnet_event
from .subscriptions.file_handler import process_file_event
from .subscriptions.noseyparker_handler import process_noseyparker_event
from .workflow import get_workflow_client, initialize_workflow_runtime, shutdown_workflow_runtime, wf_runtime
from .workflow_manager import WorkflowManager

logger = get_logger(__name__)

max_workflow_execution_time = int(
    os.getenv("MAX_WORKFLOW_EXECUTION_TIME", 300)
)  # maximum time (in seconds) until a workflow is killed

logger.info(f"max_workflow_execution_time: {max_workflow_execution_time}", pid=os.getpid())

postgres_connection_string = get_postgres_connection_str()

pool = ConnectionPool(postgres_connection_string, open=True)

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

    # Setup debug signal handlers for diagnosing blocking issues
    setup_debug_signals()

    app.state.event_loop = asyncio.get_running_loop()
    set_fastapi_loop(asyncio.get_event_loop())

    # Create asyncpg connection pool for WorkflowManager and workflow activities
    dapr_client = DaprClient()
    postgres_connection_string = get_postgres_connection_str(dapr_client)

    asyncpg_pool = await asyncpg.create_pool(
        postgres_connection_string,
        min_size=5,
        max_size=15,
    )
    logger.info("AsyncPG pool created", pid=os.getpid())

    # Initialize global DpapiManager for the application lifetime
    dpapi_manager = NemesisDpapiManager(
        storage_backend=asyncpg_pool,
        auto_decrypt=True,
        publisher=DaprDpapiEventPublisher(dapr_client, loop=app.state.event_loop),
    )
    await dpapi_manager.__aenter__()
    app.state.dpapi_manager = dpapi_manager

    # Initialize workflow runtime and modules
    module_execution_order = await initialize_workflow_runtime(dpapi_manager, asyncpg_pool)

    # Wait a bit for runtime to initialize
    await asyncio.sleep(5)

    client = get_workflow_client()
    if client is None:
        raise ValueError("Workflow client not available after initialization")

    try:
        # Use async context manager for WorkflowManager
        async with WorkflowManager(pool=asyncpg_pool, max_execution_time=max_workflow_execution_time) as wf_manager:
            workflow_manager = wf_manager

            try:
                # Start PostgreSQL NOTIFY listener in background
                postgres_notify_listener_task = asyncio.create_task(
                    postgres_notify_listener(postgres_connection_string, workflow_manager)
                )
                logger.info("Started PostgreSQL NOTIFY listener task", pid=os.getppid())

                # Start masterkey watcher in background
                background_dpapi_task = asyncio.create_task(dpapi_background_monitor(app.state.dpapi_manager))
                logger.info("Started masterkey watcher task", pid=os.getpid())

                # Recover any interrupted workflows before starting normal processing
                await recover_interrupted_workflows(pool)

                logger.info(
                    "Workflow runtime initialized successfully",
                    module_execution_order=module_execution_order,
                    client_available=client is not None,
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
                    logger.info("Cancelling PostgreSQL NOTIFY listener...", pid=os.getppid())
                    postgres_notify_listener_task.cancel()
                    try:
                        await postgres_notify_listener_task
                    except asyncio.CancelledError:
                        logger.info("PostgreSQL NOTIFY listener cancelled", pid=os.getppid())

                shutdown_workflow_runtime()

                dapr_client.close()

    finally:
        # Close asyncpg pool
        if asyncpg_pool:
            await asyncpg_pool.close()
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


@app.get("/debug/tasks")
async def debug_tasks():
    """Debug endpoint to check asyncio task status and identify blocking."""
    import sys
    import threading
    import traceback

    try:
        loop = asyncio.get_running_loop()
        all_tasks = asyncio.all_tasks(loop)

        task_info = []
        for task in all_tasks:
            info = {
                "name": task.get_name(),
                "done": task.done(),
                "cancelled": task.cancelled(),
            }

            # Try to get the coroutine info
            try:
                coro = task.get_coro()
                if coro.cr_frame:
                    info["coro_name"] = coro.__name__ if hasattr(coro, "__name__") else str(coro)
                    info["file"] = coro.cr_frame.f_code.co_filename
                    info["line"] = coro.cr_frame.f_lineno
                    info["function"] = coro.cr_frame.f_code.co_name
            except Exception:
                pass

            task_info.append(info)

        # Get thread info
        thread_info = []
        for thread in threading.enumerate():
            t_info = {
                "name": thread.name,
                "daemon": thread.daemon,
                "alive": thread.is_alive(),
            }

            # Check if thread is blocking
            if thread.ident:
                frame = sys._current_frames().get(thread.ident)
                if frame:
                    code = frame.f_code
                    t_info["current_file"] = code.co_filename
                    t_info["current_line"] = frame.f_lineno
                    t_info["current_function"] = code.co_name

                    # Flag potentially blocking calls
                    if any(keyword in code.co_name for keyword in ["wait", "lock", "result", "sleep"]):
                        t_info["potentially_blocking"] = True

            thread_info.append(t_info)

        return {
            "pid": os.getpid(),
            "total_tasks": len(all_tasks),
            "active_workflows": len(workflow_manager.active_workflows) if workflow_manager else 0,
            "background_tasks": len(workflow_manager.background_tasks) if workflow_manager else 0,
            "total_threads": len(threading.enumerate()),
            "tasks": task_info,
            "threads": thread_info,
        }
    except Exception as e:
        import traceback

        return {"error": str(e), "traceback": traceback.format_exc()}


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
    await process_bulk_enrichment_event(event.data, workflow_manager, wf_runtime)

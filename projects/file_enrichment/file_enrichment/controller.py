import asyncio
import os
from contextlib import asynccontextmanager

import file_enrichment.global_vars as global_vars
from common.db import create_connection_pool
from common.logger import get_logger
from common.queues import (
    DOTNET_OUTPUT_TOPIC,
    DOTNET_PUBSUB,
    FILES_BULK_ENRICHMENT_TASK_TOPIC,
    FILES_NEW_FILE_TOPIC,
    FILES_PUBSUB,
    NOSEYPARKER_OUTPUT_TOPIC,
    NOSEYPARKER_PUBSUB,
)
from common.workflows.setup import set_fastapi_loop
from dapr.aio.clients import DaprClient
from dapr.ext.fastapi import DaprApp
from fastapi import FastAPI
from file_enrichment.postgres_notifications import postgres_notify_listener
from file_enrichment.workflow_recovery import recover_interrupted_workflows
from file_linking import FileLinkingEngine
from nemesis_dpapi import DpapiManager as NemesisDpapiManager
from nemesis_dpapi.eventing import DaprDpapiEventPublisher

from .debug_utils import setup_debug_signals
from .routes.dpapi import dpapi_background_monitor, dpapi_router
from .routes.enrichments import router as enrichments_router
from .subscriptions.bulk_enrichment import bulk_enrichment_subscription_handler
from .subscriptions.dotnet import dotnet_subscription_handler
from .subscriptions.file import file_subscription_handler, start_workers, stop_workers
from .subscriptions.noseyparker import noseyparker_subscription_handler
from .workflow import initialize_workflow_runtime, wf_runtime
from .workflow_manager import WorkflowManager

logger = get_logger(__name__)

max_workflow_execution_time = int(
    os.getenv("MAX_WORKFLOW_EXECUTION_TIME", 300)
)  # maximum time (in seconds) until a workflow is killed

logger.info(f"max_workflow_execution_time: {max_workflow_execution_time}")


# Global tracking for bulk enrichment processes


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan manager for workflow runtime setup/teardown"""
    logger.info("Initializing workflow runtime...")

    setup_debug_signals()

    loop = asyncio.get_running_loop()
    set_fastapi_loop(loop)

    async with DaprClient() as dapr_client:
        global_vars.asyncpg_pool = await create_connection_pool(dapr_client)

        global_vars.file_linking_engine = FileLinkingEngine(global_vars.asyncpg_pool)

        dpapi_manager = NemesisDpapiManager(
            storage_backend=global_vars.asyncpg_pool,
            auto_decrypt=True,
            publisher=DaprDpapiEventPublisher(dapr_client, loop=loop),
        )
        await dpapi_manager.__aenter__()
        app.state.dpapi_manager = dpapi_manager

        # Initialize workflow runtime and modules
        global_vars.module_execution_order = await initialize_workflow_runtime(dpapi_manager)

        try:
            # Use async context manager for WorkflowManager
            async with WorkflowManager(
                pool=global_vars.asyncpg_pool, max_execution_time=max_workflow_execution_time
            ) as wf_manager:
                global_vars.workflow_manager = wf_manager

                try:
                    # Start PostgreSQL NOTIFY listener in background
                    global_vars.postgres_notify_listener_task = asyncio.create_task(
                        postgres_notify_listener(global_vars.asyncpg_pool, global_vars.workflow_manager)
                    )
                    logger.info("Started PostgreSQL NOTIFY listener task")

                    # Start masterkey watcher in background
                    global_vars.background_dpapi_task = asyncio.create_task(
                        dpapi_background_monitor(app.state.dpapi_manager)
                    )
                    logger.info("Started masterkey watcher task")

                    # Start file processing workers
                    start_workers()
                    logger.info("Started file processing workers")

                    # Recover any interrupted workflows before starting normal processing
                    await recover_interrupted_workflows(global_vars.asyncpg_pool)

                    logger.info(
                        "Workflow runtime initialized",
                        module_execution_order=global_vars.module_execution_order,
                        pid=os.getpid(),
                    )

                    yield

                finally:
                    logger.info("Shutting down workflow runtime...")

                    # Stop file processing workers
                    await stop_workers()
                    logger.info("Stopped file processing workers")

                    # Cleanup DpapiManager
                    if hasattr(app.state, "dpapi_manager") and app.state.dpapi_manager:
                        logger.info("Closing DpapiManager...")
                        await app.state.dpapi_manager.__aexit__(None, None, None)

                    # Cancel masterkey watcher task
                    if global_vars.background_dpapi_task and not global_vars.background_dpapi_task.done():
                        logger.info("Cancelling masterkey watcher task...")
                        global_vars.background_dpapi_task.cancel()
                        try:
                            await global_vars.background_dpapi_task
                        except asyncio.CancelledError:
                            logger.info("Masterkey watcher task cancelled")

                    # Cancel PostgreSQL NOTIFY listener
                    if (
                        global_vars.postgres_notify_listener_task
                        and not global_vars.postgres_notify_listener_task.done()
                    ):
                        logger.info("Cancelling PostgreSQL NOTIFY listener...")
                        global_vars.postgres_notify_listener_task.cancel()
                        try:
                            await global_vars.postgres_notify_listener_task
                        except asyncio.CancelledError:
                            logger.info("PostgreSQL NOTIFY listener cancelled")

                    if wf_runtime:
                        wf_runtime.shutdown()

        finally:
            if global_vars.asyncpg_pool:
                await global_vars.asyncpg_pool.close()
                logger.info("AsyncPG pool closed")


# Initialize FastAPI app with lifespan manager
app = FastAPI(lifespan=lifespan)
dapr_app = DaprApp(app)

# Register subscriptions
dapr_app.subscribe(pubsub=FILES_PUBSUB, topic=FILES_NEW_FILE_TOPIC)(file_subscription_handler)
dapr_app.subscribe(pubsub=FILES_PUBSUB, topic=FILES_BULK_ENRICHMENT_TASK_TOPIC)(bulk_enrichment_subscription_handler)
dapr_app.subscribe(pubsub=NOSEYPARKER_PUBSUB, topic=NOSEYPARKER_OUTPUT_TOPIC)(noseyparker_subscription_handler)
dapr_app.subscribe(pubsub=DOTNET_PUBSUB, topic=DOTNET_OUTPUT_TOPIC)(dotnet_subscription_handler)

# region API Routers/Endpoints
app.include_router(dpapi_router)
app.include_router(enrichments_router)


@app.api_route("/healthz", methods=["GET", "HEAD"])
async def healthcheck():
    """Health check endpoint for Docker healthcheck."""
    return {"status": "healthy"}


# endregion

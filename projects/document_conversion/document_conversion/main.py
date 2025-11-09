"""Main controller for document_conversion service."""

import asyncio
import os
from contextlib import asynccontextmanager

import asyncpg
import document_conversion.global_vars as global_vars
import jpype
from common.db import get_postgres_connection_str
from common.logger import WORKFLOW_CLIENT_LOG_LEVEL, get_logger
from common.queues import DOCUMENT_CONVERSION_INPUT_TOPIC, DOCUMENT_CONVERSION_PUBSUB
from common.workflows.setup import set_fastapi_loop, wf_runtime
from common.workflows.workflow_purger import WorkflowPurger
from dapr.ext.fastapi import DaprApp
from dapr.ext.workflow import DaprWorkflowClient
from dapr.ext.workflow.logger.options import LoggerOptions
from fastapi import FastAPI

from .activities.extract_text import init_tika
from .routes.health import router as health_router
from .subscriptions.file_enriched import file_enriched_subscription_handler
from .workflow_manager import max_parallel_workflows, max_workflow_execution_time

logger = get_logger(__name__)

# Configuration
dapr_port = os.getenv("DAPR_HTTP_PORT", 3500)

logger.info(f"max_parallel_workflows: {max_parallel_workflows}")
logger.info(f"max_workflow_execution_time: {max_workflow_execution_time}")

postgres_connection_string = get_postgres_connection_str()

# Workflow purge interval in seconds
workflow_purge_interval = int(os.getenv("WORKFLOW_PURGE_INTERVAL_SECONDS", "30"))


async def workflow_purger_loop(workflow_purger: WorkflowPurger, interval_seconds: int):
    """Background task that periodically purges completed workflows.

    Args:
        workflow_purger: WorkflowPurger instance
        interval_seconds: Interval between purge cycles in seconds
    """
    logger.info(
        "Starting workflow purger background task",
        interval_seconds=interval_seconds,
    )

    while True:
        try:
            await asyncio.sleep(interval_seconds)
            stats = await workflow_purger.run_purge_cycle()
            logger.debug("Workflow purge cycle completed", **stats)
        except asyncio.CancelledError:
            logger.info("Workflow purger task cancelled")
            raise
        except Exception:
            logger.exception(message="Error in workflow purger loop")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan manager for FastAPI - handles startup and shutdown events."""
    logger.info("Initializing application")
    try:
        # Set the FastAPI event loop for async workflow activities
        loop = asyncio.get_running_loop()
        set_fastapi_loop(loop)

        init_tika()

        # Set Gotenberg URL
        global_vars.gotenberg_url = (
            f"http://localhost:{dapr_port}/v1.0/invoke/gotenberg/method/forms/libreoffice/convert"
        )

        # Initialize database pool
        global_vars.asyncpg_pool = await asyncpg.create_pool(
            postgres_connection_string,
            min_size=max_parallel_workflows,
            max_size=(3 * max_parallel_workflows),
        )

        wf_runtime.start()

        global_vars.workflow_client = DaprWorkflowClient(
            logger_options=LoggerOptions(log_level=WORKFLOW_CLIENT_LOG_LEVEL),
        )

        # Initialize tracking service
        from common.workflows.tracking_service import WorkflowTrackingService

        global_vars.tracking_service = WorkflowTrackingService(
            name="document_conversion",
            pool=global_vars.asyncpg_pool,
            workflow_client=global_vars.workflow_client,
        )

        # Initialize workflow purger
        workflow_purger = WorkflowPurger(
            name="document_conversion",
            db_pool=global_vars.asyncpg_pool,
            workflow_client=global_vars.workflow_client,
        )
        logger.info("Workflow purger initialized")

        # Start workflow purger in background
        global_vars.workflow_purger_task = asyncio.create_task(
            workflow_purger_loop(workflow_purger, workflow_purge_interval)
        )
        logger.info(
            "Started workflow purger task",
            interval_seconds=workflow_purge_interval,
        )

        logger.info("Document conversion service initialized successfully")

    except Exception:
        logger.exception(message="Error initializing service")
        raise

    yield

    # Cleanup
    # Cancel workflow purger task
    if hasattr(global_vars, "workflow_purger_task") and global_vars.workflow_purger_task:
        if not global_vars.workflow_purger_task.done():
            logger.info("Cancelling workflow purger task...")
            global_vars.workflow_purger_task.cancel()
            try:
                await global_vars.workflow_purger_task
            except asyncio.CancelledError:
                logger.info("Workflow purger task cancelled")

    if global_vars.asyncpg_pool:
        await global_vars.asyncpg_pool.close()
        logger.info("Database pool closed")
    if wf_runtime:
        wf_runtime.shutdown()
    if jpype.isJVMStarted():
        jpype.shutdownJVM()


app = FastAPI(lifespan=lifespan)
dapr_app = DaprApp(app)

app.include_router(health_router)
dapr_app.subscribe(pubsub=DOCUMENT_CONVERSION_PUBSUB, topic=DOCUMENT_CONVERSION_INPUT_TOPIC)(
    file_enriched_subscription_handler
)

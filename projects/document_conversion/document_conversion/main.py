"""Main controller for document_conversion service."""

import asyncio
import os
from contextlib import AsyncExitStack, asynccontextmanager

import asyncpg
import document_conversion.global_vars as global_vars
import jpype
from common.db import get_postgres_connection_str
from common.logger import WORKFLOW_CLIENT_LOG_LEVEL, get_logger
from common.queues import DOCUMENT_CONVERSION_INPUT_TOPIC, DOCUMENT_CONVERSION_PUBSUB
from common.workflows.setup import set_workflow_runtime_loop, wf_runtime
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


async def cancel_task(task: asyncio.Task | None, task_name: str) -> None:
    """Cancel an asyncio task gracefully.

    Args:
        task: The asyncio task to cancel
        task_name: Human-readable name for logging purposes
    """
    if task and not task.done():
        logger.info(f"Cancelling {task_name}...")
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            logger.info(f"{task_name} cancelled")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan manager for FastAPI - handles startup and shutdown events."""
    logger.info("Initializing application")

    # Set the FastAPI event loop for async workflow activities
    loop = asyncio.get_running_loop()
    set_workflow_runtime_loop(loop)

    # Set Gotenberg URL
    global_vars.gotenberg_url = f"http://localhost:{dapr_port}/v1.0/invoke/gotenberg/method/forms/libreoffice/convert"

    async with AsyncExitStack() as stack:
        init_tika()
        stack.callback(jpype.shutdownJVM)

        # Initialize database pool
        global_vars.asyncpg_pool = await asyncpg.create_pool(
            postgres_connection_string,
            min_size=max_parallel_workflows,
            max_size=(3 * max_parallel_workflows),
        )
        stack.push_async_callback(global_vars.asyncpg_pool.close)

        wf_runtime.start()
        stack.push_async_callback(wf_runtime.shutdown)

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

        try:
            # Initialize and start workflow purger as background task
            purger = WorkflowPurger(
                "document_conversion",
                global_vars.asyncpg_pool,
                global_vars.workflow_client,
                max_execution_time=max_workflow_execution_time,
                batch_size=50,
                interval_seconds=workflow_purge_interval,
            )
            cleanup_dapr_workflow_state_task = asyncio.create_task(purger.run())
            logger.info("Workflow purger initialized")

            logger.info("Document conversion service initialized successfully")

            yield

        finally:
            logger.info("FastAPI lifespan is shutting down...")

            # Cancel background tasks
            await cancel_task(cleanup_dapr_workflow_state_task, "Dapr workflow state purger")


app = FastAPI(lifespan=lifespan)
dapr_app = DaprApp(app)

app.include_router(health_router)
dapr_app.subscribe(pubsub=DOCUMENT_CONVERSION_PUBSUB, topic=DOCUMENT_CONVERSION_INPUT_TOPIC)(
    file_enriched_subscription_handler
)

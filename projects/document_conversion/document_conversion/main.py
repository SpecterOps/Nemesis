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
from dapr.ext.fastapi import DaprApp
from dapr.ext.workflow import DaprWorkflowClient
from dapr.ext.workflow.logger.options import LoggerOptions
from fastapi import FastAPI

from .routes.health import router as health_router
from .subscriptions.file_enriched import file_enriched_subscription_handler
from .tika_init import init_tika
from .workflow import initialize_workflow_runtime
from .workflow_manager import max_parallel_workflows, max_workflow_execution_time

logger = get_logger(__name__)

# Configuration
dapr_port = os.getenv("DAPR_HTTP_PORT", 3500)

logger.info(f"max_parallel_workflows: {max_parallel_workflows}")
logger.info(f"max_workflow_execution_time: {max_workflow_execution_time}")

postgres_connection_string = get_postgres_connection_str()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan manager for FastAPI - handles startup and shutdown events."""
    logger.info("Initializing application")
    try:
        # Set the FastAPI event loop for async workflow activities
        loop = asyncio.get_running_loop()
        set_fastapi_loop(loop)

        # Initialize Tika
        global_vars.tika, global_vars.JavaFile = init_tika()

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

        initialize_workflow_runtime()
        global_vars.workflow_client = DaprWorkflowClient(
            logger_options=LoggerOptions(log_level=WORKFLOW_CLIENT_LOG_LEVEL),
        )

        logger.info("Document conversion service initialized successfully")

    except Exception:
        logger.exception(message="Error initializing service")
        raise

    yield

    # Cleanup
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

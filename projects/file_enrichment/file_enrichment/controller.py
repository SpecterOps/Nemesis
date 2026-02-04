import asyncio
import os
from contextlib import AsyncExitStack, asynccontextmanager

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
from common.workflows.setup import set_workflow_runtime_loop, wf_runtime
from common.workflows.tracking_service import WorkflowTrackingService
from common.workflows.workflow_purger import WorkflowPurger
from dapr.aio.clients import DaprClient
from dapr.ext.fastapi import DaprApp
from fastapi import FastAPI
from file_enrichment.postgres_notifications import postgres_notify_listener
from file_linking import FileLinkingEngine
from grpc import RpcError
from nemesis_dpapi import DpapiManager as NemesisDpapiManager
from nemesis_dpapi.eventing import DaprDpapiEventPublisher

from .debug_utils import setup_debug_signals
from .routes.dpapi import dpapi_background_monitor, dpapi_router
from .routes.enrichments import router as enrichments_router
from .routes.health import router as health_router
from .subscriptions.bulk_enrichment import bulk_enrichment_subscription_handler
from .subscriptions.dotnet import dotnet_subscription_handler
from .subscriptions.file import file_subscription_handler, start_workers, stop_workers
from .subscriptions.noseyparker import noseyparker_subscription_handler
from .workflow import initialize_enrichment_modules
from .workflow_manager import WorkflowManager

logger = get_logger(__name__)
wf_runtime.start()

max_workflow_execution_time = int(
    os.getenv("MAX_WORKFLOW_EXECUTION_TIME", 300)
)  # maximum time (in seconds) until a workflow is killed

logger.info(f"max_workflow_execution_time: {max_workflow_execution_time}")

# Workflow purge interval in seconds
workflow_purge_interval = int(os.getenv("WORKFLOW_PURGE_INTERVAL_SECONDS", "5"))


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


def terminate_workflow_safe(workflow_id: str, workflow_name: str) -> None:
    """Terminate a workflow gracefully, ignoring 'no such instance' errors.

    Args:
        workflow_id: The workflow instance ID to terminate
        workflow_name: Human-readable name for logging purposes
    """
    try:
        global_vars.workflow_client.terminate_workflow(workflow_id)
        logger.info(f"Terminated {workflow_name}")
    except RpcError as e:
        details = e.details()
        if details and "no such instance exists" in details:
            pass  # Workflow doesn't exist, nothing to terminate
        else:
            logger.exception(f"Error terminating {workflow_name}")


# Initialize FastAPI app with lifespan manager
g_loop = asyncio.get_event_loop()
set_workflow_runtime_loop(g_loop)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan manager for workflow runtime setup/teardown"""
    logger.info("Initializing workflow runtime...")

    setup_debug_signals()

    loop = asyncio.get_running_loop()
    set_workflow_runtime_loop(loop)

    async with AsyncExitStack() as stack:
        dapr_client = await stack.enter_async_context(DaprClient())

        global_vars.asyncpg_pool = await create_connection_pool(dapr_client)
        global_vars.file_linking_engine = FileLinkingEngine(global_vars.asyncpg_pool)

        stack.push_async_callback(global_vars.asyncpg_pool.close)

        dpapi_manager = await stack.enter_async_context(
            NemesisDpapiManager(
                storage_backend=global_vars.asyncpg_pool,
                auto_decrypt=True,
                publisher=DaprDpapiEventPublisher(dapr_client),
            )
        )
        app.state.dpapi_manager = dpapi_manager

        # Initialize workflow runtime and modules
        global_vars.module_execution_order = await initialize_enrichment_modules(dpapi_manager)

        # Initialize workflow tracking service as a global variable
        global_vars.tracking_service = WorkflowTrackingService(
            name="file_enrichment",
            pool=global_vars.asyncpg_pool,
            workflow_client=global_vars.workflow_client,
        )

        logger.info("Workflow purger initialized")

        # Use async context manager for WorkflowManager
        wf_manager = await stack.enter_async_context(
            WorkflowManager(
                pool=global_vars.asyncpg_pool,
                max_execution_time=max_workflow_execution_time,
            )
        )
        global_vars.workflow_manager = wf_manager

        try:
            postgres_notify_listener_task = asyncio.create_task(
                postgres_notify_listener(global_vars.asyncpg_pool, global_vars.workflow_manager)
            )

            background_dpapi_task = asyncio.create_task(dpapi_background_monitor(app.state.dpapi_manager))

            purger = WorkflowPurger(
                "file_enrichment",
                global_vars.asyncpg_pool,
                global_vars.workflow_client,
                max_execution_time=max_workflow_execution_time,
                batch_size=50,
                interval_seconds=5,
            )
            cleanup_dapr_workflow_state_task = asyncio.create_task(purger.run())

            # Start file processing workers
            start_workers()
            logger.info("Started file processing workers")

            logger.info(
                "Workflow runtime initialized",
                module_execution_order=global_vars.module_execution_order,
            )

            # Ensure workflow runtime is setup first before importing!
            # await setup_workflow_purger(workflow_purger_monitor)

            yield

        finally:
            logger.info("FastAPI lifespan is shutting down...")

            # Stop file processing workers
            logger.info("Stopping file processing workers")
            await stop_workers()

            # Cancel background tasks
            await cancel_task(background_dpapi_task, "masterkey watcher task")
            await cancel_task(postgres_notify_listener_task, "PostgreSQL NOTIFY listener")
            await cancel_task(cleanup_dapr_workflow_state_task, "Dapr workflow state purger")

            # Terminate the workflow purger monitor
            # terminate_workflow_safe("workflow-purger-monitor", "workflow purger monitor")


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
app.include_router(health_router)


def setup_workflow_purger(purger_workflow):
    logger.info("Setting up the dapr state purge workflow...")

    workflow_instance_id = "workflow-purger-monitor"

    # Check if the workflow is already running
    try:
        logger.info("Getting workflow purge state...")
        _instance_id = global_vars.workflow_client.schedule_new_workflow(  # noqa: F841
            workflow=purger_workflow,
            input=workflow_purge_interval,
            instance_id=workflow_instance_id,
        )
        # state = global_vars.workflow_client.get_workflow_state(workflow_instance_id)
        logger.info("Got workflow purge state...")
    #     if state and state.runtime_status.name in ["RUNNING", "PENDING"]:
    #         logger.info(
    #             "Workflow purger monitor already running",
    #             instance_id=workflow_instance_id,
    #             status=state.runtime_status.name,
    #         )
    #     else:
    #         # Start new workflow instance
    #         instance_id = global_vars.workflow_client.schedule_new_workflow(
    #             workflow=purger_workflow,
    #             input=workflow_purge_interval,
    #             instance_id=workflow_instance_id,
    #         )
    #         logger.info(
    #             "Started workflow purger monitor",
    #             instance_id=instance_id,
    #             interval_seconds=workflow_purge_interval,
    #         )
    except Exception:
        # Workflow doesn't exist, start it
        logger.info("Dapr purge state workflow does not exist. Scheduling it")
        # instance_id = global_vars.workflow_client.schedule_new_workflow(
        #     workflow=purger_workflow,
        #     input=workflow_purge_interval,
        #     instance_id=workflow_instance_id,
        # )
        # logger.info(
        #     "Started workflow purger monitor",
        #     instance_id=instance_id,
        #     interval_seconds=workflow_purge_interval,
        # )

    logger.warn("Purger setup done!!!!!!!!!!!!!!!!")


# setup_workflow_purger(workflow_purger_monitor)


# endregion

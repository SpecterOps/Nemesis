"""Global variables for document_conversion service."""

import asyncpg
from common.workflows.tracking_service import WorkflowTrackingService
from dapr.ext.workflow import DaprWorkflowClient
from dapr.ext.workflow.aio import DaprWorkflowClient as AsyncDaprWorkflowClient

# Global variables that will be initialized during startup
asyncpg_pool: asyncpg.Pool | None = None
gotenberg_url: str | None = None
workflow_client: DaprWorkflowClient | None = None
# Async client (bound to the FastAPI loop) for scheduling workflows and waiting on them
async_workflow_client: AsyncDaprWorkflowClient | None = None
tracking_service: WorkflowTrackingService | None = None

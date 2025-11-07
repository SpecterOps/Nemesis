"""Global variables for document_conversion service."""

import asyncpg
from common.workflows.tracking_service import WorkflowTrackingService
from dapr.ext.workflow import DaprWorkflowClient

# Global variables that will be initialized during startup
asyncpg_pool: asyncpg.Pool = None
gotenberg_url: str = None
workflow_client: DaprWorkflowClient = None
tracking_service: WorkflowTrackingService = None

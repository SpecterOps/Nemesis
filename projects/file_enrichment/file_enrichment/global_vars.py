import os

import asyncpg
import dapr.ext.workflow as wf
from common.logger import WORKFLOW_CLIENT_LOG_LEVEL
from common.storage import StorageMinio
from common.workflows.tracking_service import WorkflowTrackingService
from dapr.ext.workflow.logger.options import LoggerOptions
from file_enrichment_modules.module_loader import EnrichmentModule
from file_linking import FileLinkingEngine

from .workflow_manager import WorkflowManager

workflow_client = wf.DaprWorkflowClient(
    logger_options=LoggerOptions(
        log_level=WORKFLOW_CLIENT_LOG_LEVEL,
    ),
)

activity_functions = {}
storage = StorageMinio()
global_module_map: dict[str, EnrichmentModule] = {}  # Enrichment modules loaded at initialization

_dapr_port = os.getenv("DAPR_HTTP_PORT", 3500)
gotenberg_url = f"http://localhost:{_dapr_port}/v1.0/invoke/gotenberg/method/forms/libreoffice/convert"

nemesis_url = os.getenv("NEMESIS_URL", "http://localhost/")
nemesis_url = f"{nemesis_url}/" if not nemesis_url.endswith("/") else nemesis_url

asyncpg_pool: asyncpg.Pool = None  # Connection pool for database operations

# Note: file_linking_engine is initialized after asyncpg_pool is created
# See initialization code that sets this up with the pool
file_linking_engine: FileLinkingEngine = None

module_execution_order: list[str] = []
workflow_manager: WorkflowManager = None
tracking_service: WorkflowTrackingService = None  # Workflow tracking service for monitoring workflow state

max_workflow_execution_time = int(os.getenv("MAX_WORKFLOW_EXECUTION_TIME", 300))

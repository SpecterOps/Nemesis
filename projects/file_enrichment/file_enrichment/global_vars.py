# src/workflow/workflow.py
import asyncio
import os

import asyncpg
import dapr.ext.workflow as wf
from common.db import get_postgres_connection_str
from common.logger import WORKFLOW_CLIENT_LOG_LEVEL
from common.storage import StorageMinio
from dapr.ext.workflow.logger.options import LoggerOptions
from file_enrichment_modules.module_loader import EnrichmentModule
from file_linking import FileLinkingEngine

workflow_client = wf.DaprWorkflowClient(
    logger_options=LoggerOptions(
        log_level=WORKFLOW_CLIENT_LOG_LEVEL,
    )
)
activity_functions = {}
storage = StorageMinio()
global_module_map: dict[str, EnrichmentModule] = {}  # Enrichment modules loaded at initialization

_dapr_port = os.getenv("DAPR_HTTP_PORT", 3500)
gotenberg_url = f"http://localhost:{_dapr_port}/v1.0/invoke/gotenberg/method/forms/libreoffice/convert"

nemesis_url = os.getenv("NEMESIS_URL", "http://localhost/")
nemesis_url = f"{nemesis_url}/" if not nemesis_url.endswith("/") else nemesis_url

asyncpg_pool: asyncpg.Pool = None  # Connection pool for database operations

file_linking_engine = FileLinkingEngine(get_postgres_connection_str())
asyncio_loop: asyncio.AbstractEventLoop = None

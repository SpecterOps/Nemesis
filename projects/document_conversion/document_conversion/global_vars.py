"""Global variables for document_conversion service."""

import asyncpg
import jpype
from dapr.ext.workflow import DaprWorkflowClient

# Global variables that will be initialized during startup
asyncpg_pool: asyncpg.Pool = None
tika: jpype.JClass = None
JavaFile: jpype.JClass = None
gotenberg_url: str = None
workflow_client: DaprWorkflowClient = None

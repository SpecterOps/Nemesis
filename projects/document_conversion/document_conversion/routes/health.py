"""Health check routes."""

import document_conversion.global_vars as global_vars
import jpype
from common.logger import get_logger
from common.workflows.setup import wf_runtime
from fastapi import APIRouter

logger = get_logger(__name__)

router = APIRouter(tags=["health"])


@router.api_route("/healthz", methods=["GET", "HEAD"])
async def health_check():
    """Health check endpoint for Docker healthcheck."""
    try:
        if not global_vars.asyncpg_pool:
            return {"status": "unhealthy", "error": "Database pool not initialized"}

        async with global_vars.asyncpg_pool.acquire() as connection:
            await connection.fetchval("SELECT 1")

        if not jpype.isJVMStarted():
            return {"status": "unhealthy", "error": "JVM not started"}

        if not wf_runtime or not global_vars.workflow_client:
            return {"status": "unhealthy", "error": "Workflow runtime not initialized"}

        return {"status": "healthy"}

    except Exception as e:
        logger.exception(message="Health check failed")
        return {"status": "unhealthy", "error": str(e)}

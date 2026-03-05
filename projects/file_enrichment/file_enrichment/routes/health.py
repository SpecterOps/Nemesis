import file_enrichment.global_vars as global_vars
from common.db import get_pool_stats, update_pool_gauges
from fastapi import APIRouter
from fastapi.responses import PlainTextResponse
from prometheus_client import generate_latest

router = APIRouter()


@router.api_route("/healthz", methods=["GET", "HEAD"])
async def healthcheck():
    """Health check endpoint for Docker healthcheck."""
    return {"status": "healthy"}


@router.get("/system/pool-stats")
async def pool_stats():
    """Return asyncpg connection pool utilization stats."""
    if global_vars.asyncpg_pool is None:
        return {"error": "pool not initialized"}
    return get_pool_stats(global_vars.asyncpg_pool)


@router.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint. Updates pool gauges on each scrape."""
    if global_vars.asyncpg_pool is not None:
        update_pool_gauges(global_vars.asyncpg_pool)
    return PlainTextResponse(generate_latest(), media_type="text/plain; version=0.0.4; charset=utf-8")

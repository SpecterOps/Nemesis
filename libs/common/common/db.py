import asyncio
import os
import time
from contextlib import asynccontextmanager
from functools import lru_cache
from urllib.parse import quote_plus

import asyncpg
from dapr.aio.clients import DaprClient as AsyncDaprClient
from dapr.clients import DaprClient
from prometheus_client import Gauge, Histogram

_DAPR__DAPR_SECRET_STORE_NAME = "nemesis-secret-store"

# Prometheus metrics for connection pool monitoring
DB_POOL_SIZE = Gauge("nemesis_db_pool_size", "Current number of connections in the pool")
DB_POOL_IDLE = Gauge("nemesis_db_pool_idle", "Number of idle (available) connections in the pool")
DB_POOL_IN_USE = Gauge("nemesis_db_pool_in_use", "Number of connections currently in use")
DB_POOL_MAX = Gauge("nemesis_db_pool_max", "Maximum pool size")
DB_POOL_EXHAUSTED = Gauge("nemesis_db_pool_exhausted", "1 if pool is exhausted (no idle, at max), 0 otherwise")
DB_POOL_ACQUIRE_SECONDS = Histogram(
    "nemesis_db_pool_acquire_seconds",
    "Time spent waiting to acquire a connection from the pool",
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)


@lru_cache(maxsize=1)
def get_postgres_connection_str(dapr_client: DaprClient | None = None) -> str:
    """Get PostgreSQL connection string from Dapr secrets by building it from individual parameters."""

    def fetch_secrets(client: DaprClient) -> dict:
        """Fetch all required PostgreSQL secrets."""
        secrets = {}
        secret_keys = [
            "POSTGRES_USER",
            "POSTGRES_PASSWORD",
            "POSTGRES_HOST",
            "POSTGRES_PORT",
            "POSTGRES_DB",
            "POSTGRES_PARAMETERS",
        ]

        for key in secret_keys:
            try:
                secret = client.get_secret(store_name=_DAPR__DAPR_SECRET_STORE_NAME, key=key)
                secrets[key] = secret.secret[key]
            except Exception as e:
                raise ValueError(f"Failed to fetch {key} from Dapr secret store: {e}") from e

        return secrets

    if dapr_client:
        secrets = fetch_secrets(dapr_client)
    else:
        with DaprClient() as client:
            secrets = fetch_secrets(client)

    # Build the connection string from individual parameters
    # URL-encode user and password to handle special characters like @, :, /, etc.
    user = quote_plus(secrets["POSTGRES_USER"])
    password = quote_plus(secrets["POSTGRES_PASSWORD"])
    host = secrets["POSTGRES_HOST"]
    port = secrets["POSTGRES_PORT"]
    db = secrets["POSTGRES_DB"]
    parameters = secrets["POSTGRES_PARAMETERS"]

    output = f"postgresql://{user}:{password}@{host}:{port}/{db}?{parameters}"

    if not output.startswith("postgresql://"):
        raise ValueError("Constructed POSTGRES connection string must start with 'postgresql://'")

    return output


async def create_connection_pool(dapr_client: AsyncDaprClient):
    _DAPR_SECRET_STORE_NAME = "nemesis-secret-store"
    postgres_user = (await dapr_client.get_secret(store_name=_DAPR_SECRET_STORE_NAME, key="POSTGRES_USER")).secret[
        "POSTGRES_USER"
    ]
    postgres_password = (
        await dapr_client.get_secret(store_name=_DAPR_SECRET_STORE_NAME, key="POSTGRES_PASSWORD")
    ).secret["POSTGRES_PASSWORD"]
    postgres_host = (await dapr_client.get_secret(store_name=_DAPR_SECRET_STORE_NAME, key="POSTGRES_HOST")).secret[
        "POSTGRES_HOST"
    ]
    postgres_port = (await dapr_client.get_secret(store_name=_DAPR_SECRET_STORE_NAME, key="POSTGRES_PORT")).secret[
        "POSTGRES_PORT"
    ]
    postgres_db = (await dapr_client.get_secret(store_name=_DAPR_SECRET_STORE_NAME, key="POSTGRES_DB")).secret[
        "POSTGRES_DB"
    ]

    max_size = int(os.environ.get("DB_POOL_MAX_SIZE", "20"))
    min_size = int(os.environ.get("DB_POOL_MIN_SIZE", "2"))

    return await asyncpg.create_pool(
        host=postgres_host,
        port=int(postgres_port),
        user=postgres_user,
        password=postgres_password,
        database=postgres_db,
        min_size=min_size,
        max_size=max_size,
    )


def get_pool_stats(pool: asyncpg.Pool) -> dict:
    """Return connection pool utilization stats."""
    size = pool.get_size()
    idle = pool.get_idle_size()
    max_size = pool.get_max_size()
    in_use = size - idle
    return {
        "pool_size": size,
        "pool_idle": idle,
        "pool_in_use": in_use,
        "pool_max": max_size,
        "pool_exhausted": idle == 0 and size >= max_size,
    }


@asynccontextmanager
async def acquire_with_timing(pool: asyncpg.Pool, logger=None):
    """Acquire a connection from the pool, logging a warning if wait exceeds 1s."""
    start = time.monotonic()
    async with pool.acquire() as conn:
        elapsed = time.monotonic() - start
        DB_POOL_ACQUIRE_SECONDS.observe(elapsed)
        if elapsed > 1.0 and logger:
            stats = get_pool_stats(pool)
            logger.warning(
                f"Slow pool acquire: {elapsed:.2f}s — in_use={stats['pool_in_use']}/{stats['pool_max']}"
            )
        yield conn


def update_pool_gauges(pool: asyncpg.Pool):
    """Update Prometheus gauges from the current pool state."""
    stats = get_pool_stats(pool)
    DB_POOL_SIZE.set(stats["pool_size"])
    DB_POOL_IDLE.set(stats["pool_idle"])
    DB_POOL_IN_USE.set(stats["pool_in_use"])
    DB_POOL_MAX.set(stats["pool_max"])
    DB_POOL_EXHAUSTED.set(1 if stats["pool_exhausted"] else 0)


async def pool_stats_logger(pool: asyncpg.Pool, logger, interval: int = 30):
    """Background task that periodically logs pool stats when utilization is high and updates Prometheus gauges."""
    while True:
        await asyncio.sleep(interval)
        stats = get_pool_stats(pool)
        update_pool_gauges(pool)
        if stats["pool_exhausted"]:
            logger.warning(f"DB pool exhausted — all {stats['pool_max']} connections in use, requests will wait")
        elif stats["pool_idle"] <= 2 and stats["pool_size"] >= stats["pool_max"]:
            logger.warning(
                f"DB pool near capacity — in_use={stats['pool_in_use']}/{stats['pool_max']}, idle={stats['pool_idle']}"
            )

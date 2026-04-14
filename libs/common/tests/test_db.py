"""Tests for common.db module - connection pool configuration and monitoring."""

import asyncio
import os
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from common.db import (
    DB_POOL_ACQUIRE_SECONDS,
    DB_POOL_EXHAUSTED,
    DB_POOL_IDLE,
    DB_POOL_IN_USE,
    DB_POOL_MAX,
    DB_POOL_SIZE,
    acquire_with_timing,
    get_pool_stats,
    pool_stats_logger,
    update_pool_gauges,
)


@pytest.fixture
def mock_dapr_client():
    """Create a mock async Dapr client that returns postgres secrets."""
    client = AsyncMock()

    async def mock_get_secret(store_name, key):
        secrets = {
            "POSTGRES_USER": MagicMock(secret={"POSTGRES_USER": "testuser"}),
            "POSTGRES_PASSWORD": MagicMock(secret={"POSTGRES_PASSWORD": "testpass"}),
            "POSTGRES_HOST": MagicMock(secret={"POSTGRES_HOST": "localhost"}),
            "POSTGRES_PORT": MagicMock(secret={"POSTGRES_PORT": "5432"}),
            "POSTGRES_DB": MagicMock(secret={"POSTGRES_DB": "testdb"}),
        }
        return secrets[key]

    client.get_secret = mock_get_secret
    return client


@pytest.fixture
def mock_pool():
    """Create a mock asyncpg pool with configurable stats."""
    pool = MagicMock()
    pool.get_size.return_value = 10
    pool.get_idle_size.return_value = 5
    pool.get_max_size.return_value = 20
    pool.get_min_size.return_value = 2

    conn = AsyncMock()
    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=conn)
    cm.__aexit__ = AsyncMock(return_value=False)
    pool.acquire.return_value = cm
    return pool


# ---- create_connection_pool tests ----


@pytest.mark.asyncio
@patch("common.db.asyncpg.create_pool", new_callable=AsyncMock)
async def test_default_pool_size(mock_create_pool, mock_dapr_client):
    """Pool uses default max_size=20, min_size=2 when env vars are unset."""
    env = {k: v for k, v in os.environ.items() if k not in ("DB_POOL_MAX_SIZE", "DB_POOL_MIN_SIZE")}
    with patch.dict(os.environ, env, clear=True):
        from common.db import create_connection_pool

        await create_connection_pool(mock_dapr_client)

    mock_create_pool.assert_called_once()
    call_kwargs = mock_create_pool.call_args[1]
    assert call_kwargs["min_size"] == 2
    assert call_kwargs["max_size"] == 20


@pytest.mark.asyncio
@patch("common.db.asyncpg.create_pool", new_callable=AsyncMock)
async def test_custom_pool_size_from_env(mock_create_pool, mock_dapr_client):
    """Pool respects DB_POOL_MAX_SIZE and DB_POOL_MIN_SIZE env vars."""
    with patch.dict(os.environ, {"DB_POOL_MAX_SIZE": "50", "DB_POOL_MIN_SIZE": "5"}):
        from common.db import create_connection_pool

        await create_connection_pool(mock_dapr_client)

    mock_create_pool.assert_called_once()
    call_kwargs = mock_create_pool.call_args[1]
    assert call_kwargs["min_size"] == 5
    assert call_kwargs["max_size"] == 50


@pytest.mark.asyncio
@patch("common.db.asyncpg.create_pool", new_callable=AsyncMock)
async def test_pool_passes_correct_credentials(mock_create_pool, mock_dapr_client):
    """Pool passes correct host, port, user, password, database from Dapr secrets."""
    from common.db import create_connection_pool

    await create_connection_pool(mock_dapr_client)

    mock_create_pool.assert_called_once()
    call_kwargs = mock_create_pool.call_args[1]
    assert call_kwargs["host"] == "localhost"
    assert call_kwargs["port"] == 5432
    assert call_kwargs["user"] == "testuser"
    assert call_kwargs["password"] == "testpass"
    assert call_kwargs["database"] == "testdb"


@pytest.mark.asyncio
@patch("common.db.asyncpg.create_pool", new_callable=AsyncMock)
async def test_invalid_pool_size_env_raises(mock_create_pool, mock_dapr_client):
    """Non-integer env var values raise ValueError."""
    with patch.dict(os.environ, {"DB_POOL_MAX_SIZE": "not_a_number"}):
        from common.db import create_connection_pool

        with pytest.raises(ValueError):
            await create_connection_pool(mock_dapr_client)


# ---- get_pool_stats tests ----


def test_pool_stats_normal(mock_pool):
    """get_pool_stats returns correct values when pool has idle connections."""
    stats = get_pool_stats(mock_pool)
    assert stats["pool_size"] == 10
    assert stats["pool_idle"] == 5
    assert stats["pool_in_use"] == 5
    assert stats["pool_max"] == 20
    assert stats["pool_exhausted"] is False


def test_pool_stats_exhausted(mock_pool):
    """get_pool_stats reports exhausted when no idle and at max."""
    mock_pool.get_size.return_value = 20
    mock_pool.get_idle_size.return_value = 0
    mock_pool.get_max_size.return_value = 20
    stats = get_pool_stats(mock_pool)
    assert stats["pool_in_use"] == 20
    assert stats["pool_exhausted"] is True


def test_pool_stats_not_exhausted_with_idle(mock_pool):
    """Pool at max size but with idle connections is not exhausted."""
    mock_pool.get_size.return_value = 20
    mock_pool.get_idle_size.return_value = 3
    mock_pool.get_max_size.return_value = 20
    stats = get_pool_stats(mock_pool)
    assert stats["pool_exhausted"] is False


def test_pool_stats_not_exhausted_below_max(mock_pool):
    """Pool with 0 idle but below max is not exhausted (can still grow)."""
    mock_pool.get_size.return_value = 10
    mock_pool.get_idle_size.return_value = 0
    mock_pool.get_max_size.return_value = 20
    stats = get_pool_stats(mock_pool)
    assert stats["pool_exhausted"] is False


# ---- acquire_with_timing tests ----


@pytest.mark.asyncio
async def test_acquire_with_timing_fast(mock_pool):
    """Fast acquire does not log a warning."""
    logger = MagicMock()
    async with acquire_with_timing(mock_pool, logger=logger) as conn:
        assert conn is not None
    logger.warning.assert_not_called()


@pytest.mark.asyncio
async def test_acquire_with_timing_slow():
    """Slow acquire (>1s) logs a warning with pool stats."""
    logger = MagicMock()
    conn = AsyncMock()

    pool = MagicMock()
    pool.get_size.return_value = 20
    pool.get_idle_size.return_value = 0
    pool.get_max_size.return_value = 20

    # Build a real async context manager that sleeps before returning
    @asynccontextmanager
    async def slow_acquire():
        await asyncio.sleep(1.1)
        yield conn

    pool.acquire = slow_acquire

    async with acquire_with_timing(pool, logger=logger) as c:
        assert c is conn
    logger.warning.assert_called_once()
    assert "Slow pool acquire" in logger.warning.call_args[0][0]


@pytest.mark.asyncio
async def test_acquire_with_timing_no_logger(mock_pool):
    """acquire_with_timing works without a logger (no crash)."""
    async with acquire_with_timing(mock_pool) as conn:
        assert conn is not None


# ---- pool_stats_logger tests ----


@pytest.mark.asyncio
async def test_pool_stats_logger_warns_on_exhaustion(mock_pool):
    """pool_stats_logger warns when pool is exhausted."""
    mock_pool.get_size.return_value = 20
    mock_pool.get_idle_size.return_value = 0
    mock_pool.get_max_size.return_value = 20
    logger = MagicMock()

    task = asyncio.create_task(pool_stats_logger(mock_pool, logger, interval=0))
    await asyncio.sleep(0.05)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    logger.warning.assert_called()
    assert "exhausted" in logger.warning.call_args[0][0]


@pytest.mark.asyncio
async def test_pool_stats_logger_warns_near_capacity(mock_pool):
    """pool_stats_logger warns when pool is near capacity (idle <= 2)."""
    mock_pool.get_size.return_value = 20
    mock_pool.get_idle_size.return_value = 1
    mock_pool.get_max_size.return_value = 20
    logger = MagicMock()

    task = asyncio.create_task(pool_stats_logger(mock_pool, logger, interval=0))
    await asyncio.sleep(0.05)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    logger.warning.assert_called()
    assert "near capacity" in logger.warning.call_args[0][0]


@pytest.mark.asyncio
async def test_pool_stats_logger_silent_when_healthy(mock_pool):
    """pool_stats_logger does not warn when pool has plenty of idle connections."""
    mock_pool.get_size.return_value = 10
    mock_pool.get_idle_size.return_value = 8
    mock_pool.get_max_size.return_value = 20
    logger = MagicMock()

    task = asyncio.create_task(pool_stats_logger(mock_pool, logger, interval=0))
    await asyncio.sleep(0.05)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    logger.warning.assert_not_called()


# ---- Prometheus metrics tests ----


def test_update_pool_gauges(mock_pool):
    """update_pool_gauges sets Prometheus gauges from pool state."""
    mock_pool.get_size.return_value = 15
    mock_pool.get_idle_size.return_value = 3
    mock_pool.get_max_size.return_value = 20

    update_pool_gauges(mock_pool)

    assert DB_POOL_SIZE._value.get() == 15
    assert DB_POOL_IDLE._value.get() == 3
    assert DB_POOL_IN_USE._value.get() == 12
    assert DB_POOL_MAX._value.get() == 20
    assert DB_POOL_EXHAUSTED._value.get() == 0


def test_update_pool_gauges_exhausted(mock_pool):
    """update_pool_gauges sets exhausted=1 when pool is at max with no idle."""
    mock_pool.get_size.return_value = 20
    mock_pool.get_idle_size.return_value = 0
    mock_pool.get_max_size.return_value = 20

    update_pool_gauges(mock_pool)

    assert DB_POOL_EXHAUSTED._value.get() == 1
    assert DB_POOL_IN_USE._value.get() == 20


@pytest.mark.asyncio
async def test_acquire_with_timing_records_histogram(mock_pool):
    """acquire_with_timing records acquire latency in the Prometheus histogram."""
    sample_count_before = DB_POOL_ACQUIRE_SECONDS.collect()[0].samples[2].value  # _count sample

    async with acquire_with_timing(mock_pool) as conn:
        assert conn is not None

    sample_count_after = DB_POOL_ACQUIRE_SECONDS.collect()[0].samples[2].value
    assert sample_count_after == sample_count_before + 1


@pytest.mark.asyncio
async def test_pool_stats_logger_updates_gauges(mock_pool):
    """pool_stats_logger updates Prometheus gauges each interval."""
    mock_pool.get_size.return_value = 8
    mock_pool.get_idle_size.return_value = 6
    mock_pool.get_max_size.return_value = 20
    logger = MagicMock()

    task = asyncio.create_task(pool_stats_logger(mock_pool, logger, interval=0))
    await asyncio.sleep(0.05)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert DB_POOL_SIZE._value.get() == 8
    assert DB_POOL_IDLE._value.get() == 6
    assert DB_POOL_IN_USE._value.get() == 2

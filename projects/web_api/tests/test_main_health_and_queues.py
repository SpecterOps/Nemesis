"""Tests for /system/health dependency checks (#172) and the cached RabbitMQ secret in queue_monitor (#165)."""

import asyncio
import time
from unittest.mock import MagicMock

import pytest
import web_api.main as main
import web_api.queue_monitor as queue_monitor


@pytest.fixture(autouse=True)
def reset_health_cache(monkeypatch):
    monkeypatch.setattr(main, "_health_cache", None)


@pytest.fixture
def checks(monkeypatch):
    db = MagicMock()
    s3 = MagicMock()
    monkeypatch.setattr(main, "_check_database", db)
    monkeypatch.setattr(main, "_check_storage", s3)
    return db, s3


class TestSystemHealth:
    def test_healthy_when_dependencies_reachable(self, client, checks):
        response = client.get("/system/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy", "checks": {"database": "ok", "storage": "ok"}}

    def test_degraded_when_database_down(self, client, checks):
        checks[0].side_effect = RuntimeError("connection refused")
        response = client.get("/system/health")
        assert response.status_code == 200
        assert response.json() == {"status": "degraded", "checks": {"database": "error", "storage": "ok"}}

    def test_degraded_on_storage_timeout(self, client, monkeypatch, checks):
        monkeypatch.setattr(main, "HEALTH_CHECK_TIMEOUT", 0.05)
        checks[1].side_effect = lambda: time.sleep(0.3)
        start = time.monotonic()
        response = client.get("/system/health")
        assert time.monotonic() - start < 0.3
        assert response.json()["checks"]["storage"] == "timeout"
        assert response.json()["status"] == "degraded"

    def test_result_is_cached_briefly(self, client, checks):
        client.get("/system/health")
        client.get("/system/health")
        assert checks[0].call_count == 1

    def test_healthz_liveness_does_not_touch_dependencies(self, client, checks):
        response = client.head("/healthz")
        assert response.status_code == 200
        checks[0].assert_not_called()
        checks[1].assert_not_called()

    def test_storage_check_missing_bucket_raises(self, mock_storage):
        mock_storage.minio_client.bucket_exists.return_value = False
        with pytest.raises(RuntimeError):
            main._check_storage()

    def test_database_check_uses_pool_timeout(self, monkeypatch):
        pool = MagicMock()
        monkeypatch.setattr(main, "get_db_pool", lambda: pool)
        main._check_database()
        pool.connection.assert_called_once_with(timeout=main.HEALTH_CHECK_TIMEOUT)
        pool.connection.return_value.__enter__.return_value.execute.assert_called_once_with("SELECT 1")


def _secret(store_name, key):
    resp = MagicMock()
    resp.secret = {key: "user" if key == "RABBITMQ_USER" else "pass"}
    return resp


@pytest.fixture
def dapr(monkeypatch):
    queue_monitor.clear_rabbitmq_auth_cache()
    client = MagicMock()
    client.__enter__.return_value = client
    client.get_secret.side_effect = _secret
    factory = MagicMock(return_value=client)
    monkeypatch.setattr(queue_monitor, "DaprClient", factory)
    yield client
    queue_monitor.clear_rabbitmq_auth_cache()


async def _enter_twice():
    headers = []
    for _ in range(2):
        async with queue_monitor.WorkflowQueueMonitor() as monitor:
            headers.append(monitor.auth_header)
    return headers


class TestQueueMonitorSecretCache:
    def test_constructor_makes_no_dapr_call(self, dapr):
        queue_monitor.WorkflowQueueMonitor()
        dapr.get_secret.assert_not_called()

    def test_secret_fetched_once_and_reused(self, dapr):
        headers = asyncio.run(_enter_twice())
        assert headers[0] == headers[1] == "Basic dXNlcjpwYXNz"  # base64("user:pass")
        assert dapr.get_secret.call_count == 2  # user + password, once per process

    def test_failed_fetch_is_not_cached(self, dapr):
        dapr.get_secret.side_effect = RuntimeError("secret store down")
        with pytest.raises(RuntimeError):
            asyncio.run(_enter_twice())
        dapr.get_secret.side_effect = _secret
        assert asyncio.run(_enter_twice())[0] == "Basic dXNlcjpwYXNz"

    def test_queue_route_returns_500_when_secret_unavailable(self, client, dapr):
        dapr.get_secret.side_effect = RuntimeError("secret store down")
        assert client.get("/queues").status_code == 500

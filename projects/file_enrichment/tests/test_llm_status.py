"""Tests for the cached LLM (agents service) availability check in publish_findings."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

with patch("common.storage.StorageS3", MagicMock()):
    import file_enrichment.activities.publish_findings as publish_findings

_LlmStatus = publish_findings._LlmStatus


class FakeProbe:
    """Stands in for check_llm_enabled: returns queued results and counts calls."""

    def __init__(self, *results: bool, delay: float = 0.0, error: Exception | None = None):
        self.results = list(results)
        self.delay = delay
        self.error = error
        self.calls = 0

    async def __call__(self) -> bool:
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error:
            raise self.error
        return self.results.pop(0) if len(self.results) > 1 else self.results[0]


@pytest.fixture
def probe(monkeypatch):
    def install(*results, **kwargs):
        fake = FakeProbe(*results, **kwargs)
        monkeypatch.setattr(publish_findings, "check_llm_enabled", fake)
        return fake

    return install


@pytest.fixture
def clock():
    return {"t": 1000.0}


def make_status(clock) -> _LlmStatus:
    return _LlmStatus(clock=lambda: clock["t"])


@pytest.mark.asyncio
async def test_first_call_waits_for_one_probe(probe, clock):
    fake = probe(True)
    status = make_status(clock)
    assert await status.get() is True
    assert fake.calls == 1


@pytest.mark.asyncio
async def test_disabled_result_is_cached_within_ttl(probe, clock):
    fake = probe(False)
    status = make_status(clock)
    assert await status.get() is False
    clock["t"] += publish_findings.LLM_STATUS_TTL_SECONDS - 1
    assert await status.get() is False
    assert fake.calls == 1


@pytest.mark.asyncio
async def test_concurrent_first_callers_share_one_probe(probe, clock):
    fake = probe(False, delay=0.05)
    status = make_status(clock)
    results = await asyncio.gather(*(status.get() for _ in range(10)))
    assert results == [False] * 10
    assert fake.calls == 1


@pytest.mark.asyncio
async def test_stale_value_is_served_immediately_and_refreshed_in_background(probe, clock):
    """An agents service that starts after file-enrichment is picked up without any caller waiting."""
    fake = probe(False, True, delay=0.05)
    status = make_status(clock)
    assert await status.get() is False

    clock["t"] += publish_findings.LLM_STATUS_TTL_SECONDS
    # Returns the cached value at once, even though the refresh probe takes 50ms
    assert await asyncio.wait_for(status.get(), timeout=0.01) is False
    await status._probe
    assert await status.get() is True
    assert fake.calls == 2


@pytest.mark.asyncio
async def test_agents_going_away_is_detected(probe, clock):
    probe(True, False)
    status = make_status(clock)
    assert await status.get() is True
    clock["t"] += publish_findings.LLM_STATUS_TTL_SECONDS
    await status.get()
    await status._probe
    assert await status.get() is False


@pytest.mark.asyncio
async def test_only_one_background_refresh_at_a_time(probe, clock):
    fake = probe(False, delay=0.05)
    status = make_status(clock)
    await status.get()
    clock["t"] += publish_findings.LLM_STATUS_TTL_SECONDS
    await asyncio.gather(*(status.get() for _ in range(5)))
    await status._probe
    assert fake.calls == 2


@pytest.mark.asyncio
async def test_cancelled_first_caller_does_not_cancel_the_shared_probe(probe, clock):
    fake = probe(True, delay=0.05)
    status = make_status(clock)
    first = asyncio.create_task(status.get())
    await asyncio.sleep(0)
    first.cancel()
    assert await status.get() is True
    assert fake.calls == 1


@pytest.mark.asyncio
async def test_check_reports_disabled_when_agents_unreachable(monkeypatch):
    monkeypatch.setenv("DAPR_HTTP_PORT", "1")  # nothing listens on port 1
    assert await publish_findings.check_llm_enabled() is False


@pytest.mark.asyncio
async def test_check_reports_status_of_health_endpoint(monkeypatch):
    class Response:
        def __init__(self, status):
            self.status = status

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    class Session:
        status = 200

        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        def get(self, url, timeout):
            assert url.endswith("/v1.0/invoke/agents/method/healthz")
            return Response(Session.status)

    monkeypatch.setattr(publish_findings.aiohttp, "ClientSession", Session)
    assert await publish_findings.check_llm_enabled() is True
    Session.status = 500
    assert await publish_findings.check_llm_enabled() is False

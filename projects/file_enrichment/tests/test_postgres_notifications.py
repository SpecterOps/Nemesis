"""The NOTIFY listener must UNLISTEN before returning its connection: the pool no longer resets released connections
with UNLISTEN * (common.db.skip_session_reset), so the next user would keep receiving the notifications."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

with patch("common.storage.StorageS3", MagicMock()):
    import file_enrichment.postgres_notifications as notifications


_real_sleep = asyncio.sleep


async def _no_backoff(seconds):
    """Skip the listener's retry backoff but still yield to the event loop."""
    await _real_sleep(0)


class _Conn:
    def __init__(self, listen_error: Exception | None = None):
        self.listen_error = listen_error
        self.calls: list[str] = []

    async def add_listener(self, channel, callback):
        if self.listen_error:
            raise self.listen_error
        self.calls.append(f"listen {channel}")

    async def remove_listener(self, channel, callback):
        self.calls.append(f"remove {channel}")

    async def execute(self, query):
        self.calls.append(query)


class _Pool:
    """Hands out the given connections in turn; once they run out, acquire blocks until cancelled."""

    def __init__(self, *conns):
        self.conns = list(conns)
        self.released: list[_Conn] = []

    async def acquire(self):
        if self.conns:
            return self.conns.pop(0)
        await asyncio.Event().wait()

    async def release(self, conn):
        conn.calls.append("release")
        self.released.append(conn)


@pytest.mark.asyncio
async def test_connection_error_unlistens_before_release(monkeypatch):
    monkeypatch.setattr(notifications.asyncio, "sleep", _no_backoff)
    broken = _Conn(listen_error=OSError("connection lost"))
    pool = _Pool(broken)

    task = asyncio.create_task(notifications.postgres_notify_listener(pool, MagicMock()))
    for _ in range(20):
        await _real_sleep(0)
        if pool.released:
            break
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)

    assert broken.calls == ["UNLISTEN *", "release"]


@pytest.mark.asyncio
async def test_cancelled_listener_unlistens_before_release():
    conn = _Conn()
    pool = _Pool(conn)

    task = asyncio.create_task(notifications.postgres_notify_listener(pool, MagicMock()))
    for _ in range(20):
        await _real_sleep(0)
        if "listen nemesis_workflow_reset" in conn.calls:
            break
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)

    assert conn.calls[-2:] == ["UNLISTEN *", "release"]
    assert "remove nemesis_yara_reload" in conn.calls


@pytest.mark.asyncio
async def test_unlisten_failure_still_releases(monkeypatch):
    monkeypatch.setattr(notifications.asyncio, "sleep", _no_backoff)
    conn = _Conn(listen_error=OSError("connection lost"))

    async def failing_execute(query):
        raise OSError("connection closed")

    conn.execute = failing_execute
    pool = _Pool(conn)

    task = asyncio.create_task(notifications.postgres_notify_listener(pool, MagicMock()))
    for _ in range(20):
        await _real_sleep(0)
        if pool.released:
            break
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)

    assert pool.released == [conn]

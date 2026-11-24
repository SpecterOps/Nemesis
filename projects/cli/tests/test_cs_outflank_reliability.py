"""Retry, dedupe, timeout, size-limit and metadata behaviour of the Cobalt Strike and Outflank connectors."""

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import aiohttp
import pytest
from cli.c2_download_state import (
    RETRY_DELAYS_SEC,
    FileTooLargeError,
    PermanentDownloadError,
    TransientDownloadError,
    classify_download_error,
    classify_upload_error,
    download_timeout,
    remote_file_path,
    retry_delay,
    stream_response_to_file,
)
from cli.c2_metadata import join_remote_path
from cli.cobaltstrike_connector.cache import ImplantCache as BeaconCache
from cli.cobaltstrike_connector.cobaltstrike_client import CobaltStrikeClient
from cli.cobaltstrike_connector.cobaltstrike_client import Download as CSDownload
from cli.cobaltstrike_connector.download_monitor import CobaltStrikeDownloadMonitor
from cli.cobaltstrike_connector.download_processor import CobaltStrikeDownloadProcessor
from cli.stage1_connector.cache import ImplantCache
from cli.stage1_connector.download_monitor import OutflankDownloadMonitor
from cli.stage1_connector.download_processor import OutflankDownloadProcessor
from cli.stage1_connector.outflankc2_client import Download as OutflankDownload
from cli.stage1_connector.outflankc2_client import OutflankC2Client
from common.models2.api import ErrorResponse, FileWithMetadataResponse

COLLECTED = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)


def accepted():
    return FileWithMetadataResponse(object_id=uuid4(), submission_id=uuid4())


def cs_download(download_id="dl1", size=4, path="C:\\Users\\bob", name="a.txt"):
    return CSDownload(id=download_id, bid="b1", name=name, path=path, size=size, timestamp=COLLECTED)


def of_download(uid="dl1", size=4, progress=100.0, path="C:\\Users\\bob\\a.txt"):
    return OutflankDownload(
        uid=uid,
        timestamp=COLLECTED.replace(tzinfo=None),
        path=path,
        name="a.txt",
        size=size,
        progress=progress,
        task_uid="t1",
        implant_uid="i1",
        implant_username="bob",
        implant_hostname="ws01",
    )


def writer(data=b"data"):
    """A fake C2 download_file that writes ``data`` and records the destination."""
    seen = {}

    async def download_file(_id, dest, **kwargs):
        seen["dest"] = dest
        seen["kwargs"] = kwargs
        Path(dest).write_bytes(data)
        return True

    return AsyncMock(side_effect=download_file), seen


class Harness:
    """One processor of either kind, with a mocked C2 client and Nemesis client."""

    def __init__(self, kind, tmp_path, *, max_file_size=None, expiration_days=100):
        self.kind = kind
        self.nemesis = MagicMock()
        self.nemesis.post_file = AsyncMock(return_value=accepted())
        self.c2 = MagicMock()
        self.c2.download_file, self.seen = writer()
        if kind == "cobaltstrike":
            self.processor = CobaltStrikeDownloadProcessor(
                tmp_path / "db",
                self.nemesis,
                "proj",
                cobalt_strike=self.c2,
                max_file_size=max_file_size,
                expiration_days=expiration_days,
            )
            self.owner = SimpleNamespace(computer="ws01", bid="b1")
        else:
            self.processor = OutflankDownloadProcessor(
                tmp_path / "db",
                self.nemesis,
                "proj",
                outflank=self.c2,
                max_file_size=max_file_size,
                expiration_days=expiration_days,
            )
            self.owner = SimpleNamespace(hostname="ws01", uid="i1")

    def download(self, **kwargs):
        return cs_download(**kwargs) if self.kind == "cobaltstrike" else of_download(**kwargs)

    async def process(self, download, owner=...):
        owner = self.owner if owner is ... else owner
        if self.kind == "cobaltstrike":
            await self.processor.process_cobaltstrike_download(download, owner)
        else:
            await self.processor.process_outflank_download(download, owner)

    def record(self, download):
        import json

        key = download.id if self.kind == "cobaltstrike" else download.uid
        raw = self.processor.db.get(f"download:{key}".encode())
        return json.loads(raw) if raw else None

    def retry(self, download):
        key = download.id if self.kind == "cobaltstrike" else download.uid
        return self.processor.state.retry_state(key)


@pytest.fixture(params=["cobaltstrike", "outflank"])
def harness(request, tmp_path):
    h = Harness(request.param, tmp_path)
    try:
        yield h
    finally:
        h.processor.close()


def make_harness(tmp_path, kind, **kwargs):
    return Harness(kind, tmp_path, **kwargs)


# --- retry state and backoff ---


def test_retry_delays_back_off_and_cap():
    assert [retry_delay(n) for n in range(1, 10)] == [5, 10, 20, 40, 80, 160, 300, 300, 300]
    assert RETRY_DELAYS_SEC[-1] == 300


@pytest.mark.asyncio
async def test_transient_upload_failure_is_retried_then_succeeds(harness):
    download = harness.download()
    harness.nemesis.post_file = AsyncMock(
        side_effect=[ErrorResponse(detail="Error uploading file to Nemesis: 503"), accepted()]
    )

    await harness.process(download)
    assert not harness.processor.is_processed(download)
    assert harness.retry(download)["attempts"] == 1
    assert "503" in harness.retry(download)["last_error"]

    harness.processor.state.clock = lambda: 10**12  # the retry delay has passed
    assert harness.processor.is_due(download)
    await harness.process(download)

    assert harness.processor.is_processed(download)
    assert harness.record(download)["success"] is True
    assert harness.retry(download) is None  # retry state cleared with the finished record
    assert harness.nemesis.post_file.await_count == 2


@pytest.mark.asyncio
async def test_backoff_is_respected(harness):
    now = [1000.0]
    harness.processor.state.clock = lambda: now[0]
    download = harness.download()
    harness.c2.download_file = AsyncMock(side_effect=aiohttp.ServerDisconnectedError())

    await harness.process(download)
    assert harness.retry(download)["next_at"] == 1005.0
    assert not harness.processor.is_due(download)
    now[0] = 1005.0
    assert harness.processor.is_due(download)

    await harness.process(download)
    assert harness.retry(download) == {
        "attempts": 2,
        "next_at": 1015.0,
        "last_error": harness.retry(download)["last_error"],
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [404, 410])
async def test_c2_not_found_is_permanent(harness, status):
    download = harness.download()
    harness.c2.download_file = AsyncMock(
        side_effect=aiohttp.ClientResponseError(MagicMock(), (), status=status, message="gone")
    )
    await harness.process(download)
    assert harness.processor.is_processed(download)
    assert harness.record(download)["success"] is False
    assert not harness.processor.is_due(download)
    harness.nemesis.post_file.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [500, 502, 503])
async def test_c2_server_error_is_transient(harness, status):
    download = harness.download()
    harness.c2.download_file = AsyncMock(
        side_effect=aiohttp.ClientResponseError(MagicMock(), (), status=status, message="boom")
    )
    await harness.process(download)
    assert not harness.processor.is_processed(download)
    assert harness.retry(download)["attempts"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(("status", "permanent"), [(400, True), (413, True), (422, True), (429, False), (500, False)])
async def test_nemesis_status_classification(harness, status, permanent):
    download = harness.download()
    harness.nemesis.post_file = AsyncMock(
        return_value=ErrorResponse(detail=f"Error uploading file to Nemesis: {status}")
    )
    await harness.process(download)
    assert harness.processor.is_processed(download) is permanent
    assert (harness.retry(download) is None) is permanent


@pytest.mark.asyncio
async def test_nemesis_connection_error_is_transient(harness):
    download = harness.download()
    harness.nemesis.post_file = AsyncMock(return_value=ErrorResponse(detail="Upload failed: ConnectError"))
    await harness.process(download)
    assert not harness.processor.is_processed(download)
    assert harness.retry(download)["attempts"] == 1


def test_classifiers():
    assert classify_upload_error("Upload failed: Error uploading file to Nemesis: 404") is PermanentDownloadError
    assert classify_upload_error("Upload failed: Error uploading file to Nemesis: 401") is TransientDownloadError
    assert classify_upload_error(None) is TransientDownloadError
    assert classify_download_error(FileTooLargeError("x")) is PermanentDownloadError
    assert classify_download_error(TimeoutError()) is TransientDownloadError
    assert classify_download_error(OSError("disk")) is TransientDownloadError


# --- temp files ---


@pytest.mark.asyncio
@pytest.mark.parametrize("make_error", [aiohttp.ServerDisconnectedError, asyncio.TimeoutError, RuntimeError])
async def test_temp_file_removed_when_download_raises(harness, make_error):
    seen = {}

    async def partial(_id, dest, **_kwargs):
        seen["dest"] = dest
        Path(dest).write_bytes(b"partial")
        raise make_error()

    harness.c2.download_file = AsyncMock(side_effect=partial)
    await harness.process(harness.download())
    assert not Path(seen["dest"]).exists()


@pytest.mark.asyncio
async def test_temp_file_removed_when_download_returns_false(harness):
    seen = {}

    async def failed(_id, dest, **_kwargs):
        seen["dest"] = dest
        return False

    harness.c2.download_file = AsyncMock(side_effect=failed)
    download = harness.download()
    await harness.process(download)
    assert not Path(seen["dest"]).exists()
    assert harness.retry(download)["attempts"] == 1


@pytest.mark.asyncio
async def test_temp_file_removed_after_failed_upload(harness):
    harness.nemesis.post_file = AsyncMock(return_value=ErrorResponse(detail="Error uploading file to Nemesis: 503"))
    await harness.process(harness.download())
    assert not Path(harness.seen["dest"]).exists()


# --- size limits ---


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["cobaltstrike", "outflank"])
async def test_oversize_download_skipped_before_download(tmp_path, kind):
    h = make_harness(tmp_path, kind, max_file_size=3)
    try:
        download = h.download(size=4)
        await h.process(download)
        h.c2.download_file.assert_not_awaited()
        h.nemesis.post_file.assert_not_awaited()
        assert h.processor.is_processed(download)
        assert h.record(download)["error"] == "file exceeds max_file_size"
    finally:
        h.processor.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["cobaltstrike", "outflank"])
async def test_stream_limit_is_passed_and_enforced(tmp_path, kind):
    h = make_harness(tmp_path, kind, max_file_size=10)
    try:
        h.c2.download_file = AsyncMock(side_effect=FileTooLargeError("too big"))
        download = h.download(size=5)  # the C2 under-reported the size
        await h.process(download)
        assert h.c2.download_file.await_args.kwargs == {"max_bytes": 10}
        assert h.processor.is_processed(download)
        assert h.record(download)["success"] is False
        h.nemesis.post_file.assert_not_awaited()
    finally:
        h.processor.close()


class FakeContent:
    def __init__(self, chunks):
        self.chunks = chunks

    async def iter_chunked(self, _size):
        for chunk in self.chunks:
            yield chunk


@pytest.mark.asyncio
async def test_stream_aborts_once_limit_exceeded(tmp_path):
    response = SimpleNamespace(content_length=None, content=FakeContent([b"aaaa", b"bbbb", b"cccc"]))
    with pytest.raises(FileTooLargeError):
        await stream_response_to_file(response, str(tmp_path / "out"), max_bytes=6)


@pytest.mark.asyncio
async def test_stream_rejects_content_length_before_reading(tmp_path):
    content = MagicMock()
    content.iter_chunked = MagicMock(side_effect=AssertionError("must not read"))
    response = SimpleNamespace(content_length=100, content=content)
    with pytest.raises(FileTooLargeError):
        await stream_response_to_file(response, str(tmp_path / "out"), max_bytes=10)
    assert not (tmp_path / "out").exists()


@pytest.mark.asyncio
async def test_stream_writes_within_limit(tmp_path):
    response = SimpleNamespace(content_length=8, content=FakeContent([b"aaaa", b"bbbb"]))
    assert await stream_response_to_file(response, str(tmp_path / "out"), max_bytes=8) == 8
    assert (tmp_path / "out").read_bytes() == b"aaaabbbb"


@pytest.mark.asyncio
async def test_short_file_is_retried_not_uploaded(harness):
    download = harness.download(size=100)  # the fake writes 4 bytes
    await harness.process(download)
    harness.nemesis.post_file.assert_not_awaited()
    assert "incomplete" in harness.retry(download)["last_error"]


# --- timeouts ---


@pytest.mark.parametrize("client_cls", [CobaltStrikeClient, OutflankC2Client])
def test_download_timeout_has_no_total_limit(client_cls):
    client = client_cls("https://c2.local", connect_timeout=7)
    assert client.download_timeout.total is None
    assert client.download_timeout.connect == 7
    assert client.download_timeout.sock_read == 300


def test_download_timeout_helper():
    timeout = download_timeout(5, read_timeout=60)
    assert (timeout.total, timeout.connect, timeout.sock_connect, timeout.sock_read) == (None, 5, 5, 60)


class FakeGet:
    """Async context manager standing in for session.get(); records its kwargs."""

    def __init__(self, response, calls, **kwargs):
        calls.append(kwargs)
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, *_exc):
        return False


@pytest.mark.asyncio
@pytest.mark.parametrize("client_cls", [CobaltStrikeClient, OutflankC2Client])
async def test_download_request_uses_download_timeout(tmp_path, client_cls):
    client = client_cls("https://c2.local", connect_timeout=3)
    calls = []
    response = SimpleNamespace(status=200, content_length=4, content=FakeContent([b"data"]))
    client._session = MagicMock()
    client._session.get = lambda _url, **kwargs: FakeGet(response, calls, **kwargs)

    assert await client.download_file("abc", str(tmp_path / "out"), max_bytes=10)
    assert calls == [{"timeout": client.download_timeout}]
    assert (tmp_path / "out").read_bytes() == b"data"


@pytest.mark.asyncio
@pytest.mark.parametrize("client_cls", [CobaltStrikeClient, OutflankC2Client])
async def test_client_download_enforces_max_bytes(tmp_path, client_cls):
    client = client_cls("https://c2.local")
    response = SimpleNamespace(status=200, content_length=None, content=FakeContent([b"aaaa", b"bbbb"]))
    client._session = MagicMock()
    client._session.get = lambda _url, **kwargs: FakeGet(response, [], **kwargs)
    with pytest.raises(FileTooLargeError):
        await client.download_file("abc", str(tmp_path / "out"), max_bytes=5)


# --- metadata ---


@pytest.mark.asyncio
async def test_metadata_uses_collection_time_and_expiration_days(tmp_path):
    for kind in ("cobaltstrike", "outflank"):
        (tmp_path / kind).mkdir()
        h = make_harness(tmp_path / kind, kind, expiration_days=30)
        try:
            await h.process(h.download())
            metadata = h.nemesis.post_file.await_args.args[1]
            assert metadata.timestamp == COLLECTED
            assert metadata.expiration - datetime.now(UTC) > timedelta(days=29)
            assert metadata.expiration - datetime.now(UTC) <= timedelta(days=30)
            assert metadata.path == "C:\\Users\\bob\\a.txt"
            assert metadata.source == "host://ws01"
        finally:
            h.processor.close()


@pytest.mark.parametrize(
    ("directory", "name", "expected"),
    [
        ("C:\\Users\\bob", "a.txt", "C:\\Users\\bob\\a.txt"),
        ("C:\\Users\\bob\\a.txt", "a.txt", "C:\\Users\\bob\\a.txt"),
        ("/home/bob/a.txt", "a.txt", "/home/bob/a.txt"),
        ("/home/bob", "a.txt", "/home/bob/a.txt"),
        ("a.txt", "a.txt", "a.txt"),
        ("/home/xa.txt", "a.txt", "/home/xa.txt/a.txt"),
    ],
)
def test_remote_file_path(directory, name, expected):
    assert remote_file_path(directory, name, join_remote_path) == expected


# --- missing beacon / implant ---


@pytest.mark.asyncio
async def test_missing_owner_still_uploads(harness):
    download = harness.download()
    await harness.process(download, None)
    metadata = harness.nemesis.post_file.await_args.args[1]
    # Outflank downloads carry the implant hostname themselves; Cobalt Strike downloads do not.
    assert metadata.source == ("host://ws01" if harness.kind == "outflank" else None)
    assert harness.processor.is_processed(download)


# --- monitors ---


def cs_monitor(downloads, processor, beacons=()):
    client = MagicMock()
    client.get_downloads = AsyncMock(return_value=downloads)
    client.get_beacons = AsyncMock(return_value=list(beacons))
    return CobaltStrikeDownloadMonitor(client, BeaconCache(client), processor, polling_interval=0)


def of_monitor(downloads, processor, implants=()):
    client = MagicMock()
    client.get_downloads = AsyncMock(return_value=downloads)
    client.get_implants = AsyncMock(return_value=list(implants))
    return OutflankDownloadMonitor(client, ImplantCache(client), processor, polling_interval=0)


def fake_processor(due=True, processed=False):
    processor = MagicMock()
    processor.is_due = MagicMock(return_value=due)
    processor.is_processed = MagicMock(return_value=processed)
    return processor


@pytest.mark.asyncio
async def test_in_flight_download_is_not_queued_twice():
    monitor = cs_monitor([cs_download()], fake_processor())
    await monitor.poll_once()
    await monitor.poll_once()
    assert monitor.queue.qsize() == 1
    assert monitor.in_flight == {"dl1"}


@pytest.mark.asyncio
async def test_not_due_download_is_not_queued():
    monitor = of_monitor([of_download()], fake_processor(due=False))
    await monitor.poll_once()
    assert monitor.queue.empty()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("progress", "queued"), [(0.5, False), (50.0, False), (99.9, False), (1.0, True), (100.0, True)]
)
async def test_outflank_in_progress_download_not_queued(progress, queued):
    processor = fake_processor()
    monitor = of_monitor([of_download(progress=progress)], processor)
    await monitor.poll_once()
    assert (monitor.queue.qsize() == 1) is queued
    processor.record_retry.assert_not_called()  # in-progress is not a failure


@pytest.mark.asyncio
async def test_missing_beacon_queued_with_one_refresh_and_one_warning(caplog):
    caplog.set_level(logging.WARNING)
    downloads = [cs_download("d1"), cs_download("d2")]
    monitor = cs_monitor(downloads, fake_processor())
    await monitor.poll_once()

    assert monitor.queue.qsize() == 2
    assert monitor.queue.get_nowait()[1] is None
    # Two unknown beacons in one poll refresh the beacon list once, not once per download.
    assert monitor.cobalt_strike_client.get_beacons.await_count == 1

    monitor.in_flight.clear()
    await monitor.poll_once()
    assert monitor.cobalt_strike_client.get_beacons.await_count == 2  # one refresh per poll
    warnings = [r for r in caplog.records if "Could not find beacon" in r.getMessage()]
    assert len(warnings) == 2  # once per download, not once per poll


@pytest.mark.asyncio
async def test_worker_marks_task_done_and_clears_in_flight_on_exception():
    processor = fake_processor()
    processor.process_cobaltstrike_download = AsyncMock(side_effect=RuntimeError("boom"))
    monitor = cs_monitor([cs_download()], processor)
    monitor.is_running = True
    await monitor.poll_once()
    worker = asyncio.create_task(monitor.process_queue())
    try:
        await asyncio.wait_for(monitor.queue.join(), timeout=2)
    finally:
        worker.cancel()
    assert monitor.in_flight == set()


@pytest.mark.asyncio
async def test_worker_skips_download_finished_since_queued():
    processor = fake_processor(processed=True)
    processor.process_outflank_download = AsyncMock()
    monitor = of_monitor([of_download()], processor)
    monitor.is_running = True
    monitor.in_flight.add("dl1")
    await monitor.queue.put((of_download(), None))
    worker = asyncio.create_task(monitor.process_queue())
    try:
        await asyncio.wait_for(monitor.queue.join(), timeout=2)
    finally:
        worker.cancel()
    processor.process_outflank_download.assert_not_awaited()


@pytest.mark.asyncio
async def test_end_to_end_failure_then_retry_via_monitor(tmp_path):
    """A failed download is not re-queued until its retry is due, then succeeds."""
    h = make_harness(tmp_path, "cobaltstrike")
    try:
        now = [0.0]
        h.processor.state.clock = lambda: now[0]
        h.nemesis.post_file = AsyncMock(side_effect=[ErrorResponse(detail="Upload failed: ConnectError"), accepted()])
        monitor = cs_monitor([h.download()], h.processor, beacons=[])
        monitor.is_running = True
        worker = asyncio.create_task(monitor.process_queue())
        try:
            await monitor.poll_once()
            await asyncio.wait_for(monitor.queue.join(), timeout=2)
            await monitor.poll_once()  # still within the 5 s backoff
            assert monitor.queue.empty()
            now[0] = 5.0
            await monitor.poll_once()
            await asyncio.wait_for(monitor.queue.join(), timeout=2)
        finally:
            worker.cancel()
        assert h.processor.is_processed(h.download())
        assert h.nemesis.post_file.await_count == 2
    finally:
        h.processor.close()


# --- Outflank local-directory mode ---


@pytest.mark.asyncio
async def test_local_dir_file_appearing_later_is_uploaded(tmp_path):
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    nemesis = MagicMock()
    nemesis.post_file = AsyncMock(return_value=accepted())
    processor = OutflankDownloadProcessor(tmp_path / "db", nemesis, "proj", outflank_downloads_dir_path=downloads)
    try:
        download = of_download(uid="late")
        await processor.process_outflank_download(download, None)
        assert processor.state.retry_state("late")["attempts"] == 1

        (downloads / "late").write_bytes(b"data")
        processor.state.clock = lambda: 10**12
        await processor.process_outflank_download(download, None)
        assert processor.is_processed(download)
        assert (downloads / "late").exists()  # local mode never deletes the source
    finally:
        processor.close()


@pytest.mark.asyncio
async def test_local_dir_oversize_file_is_permanent(tmp_path):
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    (downloads / "big").write_bytes(b"x" * 20)
    nemesis = MagicMock()
    nemesis.post_file = AsyncMock()
    processor = OutflankDownloadProcessor(
        tmp_path / "db", nemesis, "proj", outflank_downloads_dir_path=downloads, max_file_size=10
    )
    try:
        download = of_download(uid="big", size=None)
        await processor.process_outflank_download(download, None)
        assert processor.is_processed(download)
        nemesis.post_file.assert_not_awaited()
    finally:
        processor.close()

"""Async Nemesis HTTP transport behavior."""

import asyncio
import io
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from cli.config import NemesisConfig, PasswordCredential, StrictHttpUrl
from cli.nemesis_client import NemesisClient, PreviewNemesisClient, PreviewUploadResult
from common.models2.api import ErrorResponse, FileMetadata


class CapturingTransport(httpx.AsyncBaseTransport):
    def __init__(self, handler):
        self.handler = handler
        self.closed = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self.handler(request)

    async def aclose(self) -> None:
        self.closed = True


class BoundedReadStream(io.BytesIO):
    def __init__(self, content: bytes):
        super().__init__(content)
        self.max_read = 0

    def read(self, size: int = -1) -> bytes:
        assert size >= 0, "upload must not read the whole file at once"
        self.max_read = max(self.max_read, size)
        return super().read(size)


class ChunkCollectingTransport(httpx.AsyncBaseTransport):
    def __init__(self):
        self.body = bytearray()
        self.content_type = ""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.content_type = request.headers["content-type"]
        async for chunk in request.stream:
            self.body.extend(chunk)
        return httpx.Response(
            200,
            json={
                "object_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "submission_id": "f0e1d2c3-b4a5-6789-0abc-def123456789",
            },
        )

    async def aclose(self) -> None:
        pass


def make_config() -> NemesisConfig:
    return NemesisConfig(
        url=StrictHttpUrl("https://nemesis.local:8080"),
        credential=PasswordCredential(username="testuser", password="testpass"),
    )


def make_metadata() -> FileMetadata:
    return FileMetadata(
        agent_id="agent", project="project", timestamp=datetime.now(), expiration=datetime.now(), path="file.txt"
    )


@pytest.mark.asyncio
async def test_metadata_helper_is_synchronous():
    metadata = NemesisClient(make_config()).create_file_metadata("x", "a", "p")
    assert metadata.path == "x"
    assert metadata.expiration.year > metadata.timestamp.year


@pytest.mark.asyncio
async def test_upload_streams_multipart_and_preserves_caller_stream():
    captured = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/health"):
            return httpx.Response(404)
        captured["body"] = await request.aread()
        captured["type"] = request.headers["content-type"]
        return httpx.Response(
            200,
            json={
                "object_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "submission_id": "f0e1d2c3-b4a5-6789-0abc-def123456789",
            },
        )

    stream = io.BytesIO(b"file contents")
    async with NemesisClient(make_config(), transport=httpx.MockTransport(handler)) as client:
        result = await client.post_file(stream, make_metadata())
        assert await client.get_health() == ErrorResponse(detail="Error getting health status: 404")
    assert not stream.closed
    assert "multipart/form-data" in captured["type"]
    assert b"file contents" in captured["body"]
    assert b"application/json" in captured["body"]
    assert result.object_id


@pytest.mark.asyncio
async def test_owned_file_closes_when_upload_is_cancelled(tmp_path):
    entered = asyncio.Event()
    release = asyncio.Event()

    async def handler(_request: httpx.Request) -> httpx.Response:
        entered.set()
        await release.wait()
        return httpx.Response(200, json={})

    file_path = tmp_path / "upload.bin"
    file_path.write_bytes(b"content")
    opened = []
    real_open = Path.open

    def capture_open(path: Path, *args: Any, **kwargs: Any):
        handle = real_open(path, *args, **kwargs)
        opened.append(handle)
        return handle

    transport = CapturingTransport(handler)
    client = NemesisClient(make_config(), transport=transport)
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(Path, "open", capture_open)
        async with client:
            task = asyncio.create_task(client.post_file(file_path, make_metadata()))
            await entered.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert opened[0].closed
            assert client._http is not None
    assert client._http is None
    assert opened[0].closed
    assert transport.closed


@pytest.mark.asyncio
async def test_upload_reads_large_file_in_bounded_chunks():
    content = b"0123456789abcdef" * 200_000
    stream = BoundedReadStream(content)
    transport = ChunkCollectingTransport()
    async with NemesisClient(make_config(), transport=transport) as client:
        result = await client.post_file(stream, make_metadata())
    assert result.object_id
    assert stream.max_read > 0
    assert stream.max_read <= 64 * 1024
    body = bytes(transport.body)
    file_start = body.index(b"\r\n\r\n") + 4
    boundary = transport.content_type.split("boundary=")[1].encode()
    file_end = body.index(b"\r\n--" + boundary, file_start)
    assert body[file_start:file_end] == content


@pytest.mark.asyncio
async def test_retry_only_connection_errors_and_uses_one_then_two_seconds(monkeypatch):
    sleeps = []

    async def sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(asyncio, "sleep", sleep)
    requests = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        if requests < 3:
            raise httpx.ConnectError("refused", request=request)
        return httpx.Response(200, json={"status": "healthy"})

    async with NemesisClient(make_config(), transport=httpx.MockTransport(handler)) as client:
        result = await client.get_health()
    assert result.status == "healthy"
    assert requests == 3
    assert sleeps == [1, 2]


@pytest.mark.asyncio
async def test_retry_exhaustion_returns_error_response(monkeypatch):
    async def no_wait(_delay: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", no_wait)
    requests = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        raise httpx.ConnectError("refused", request=request)

    async with NemesisClient(make_config(), transport=httpx.MockTransport(handler)) as client:
        result = await client.get_health()
    assert isinstance(result, ErrorResponse)
    assert requests == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("error_type", [httpx.ConnectError, httpx.ConnectTimeout])
async def test_upload_connect_failures_retry_with_full_file_body(tmp_path, monkeypatch, error_type):
    async def no_wait(_delay: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", no_wait)
    file_path = tmp_path / "payload.bin"
    file_path.write_bytes(b"retry-file-payload")
    calls = 0
    bodies = []

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls < 3:
            raise error_type("connection not established", request=request)
        bodies.append(await request.aread())
        return httpx.Response(
            200,
            json={
                "object_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "submission_id": "f0e1d2c3-b4a5-6789-0abc-def123456789",
            },
        )

    async with NemesisClient(make_config(), transport=httpx.MockTransport(handler)) as client:
        result = await client.post_file(file_path, make_metadata())
    assert result.object_id
    assert calls == 3
    assert len(bodies) == 1
    assert b"retry-file-payload" in bodies[0]


@pytest.mark.asyncio
async def test_upload_retry_exhaustion_returns_error(tmp_path, monkeypatch):
    async def no_wait(_delay: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", no_wait)
    file_path = tmp_path / "payload.bin"
    file_path.write_bytes(b"payload")
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ConnectError("refused", request=request)

    async with NemesisClient(make_config(), transport=httpx.MockTransport(handler)) as client:
        result = await client.post_file(file_path, make_metadata())
    assert isinstance(result, ErrorResponse)
    assert calls == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403, 500])
async def test_http_errors_are_never_retried(status):
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status)

    async with NemesisClient(make_config(), transport=httpx.MockTransport(handler)) as client:
        result = await client.get_health()
    assert isinstance(result, ErrorResponse)
    assert calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error_type", [httpx.ReadTimeout, httpx.ReadError, httpx.WriteTimeout, httpx.WriteError, httpx.PoolTimeout]
)
async def test_ambiguous_transport_errors_are_never_retried(error_type):
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise error_type("failed", request=request)

    async with NemesisClient(make_config(), transport=httpx.MockTransport(handler)) as client:
        result = await client.get_health()
    assert isinstance(result, ErrorResponse)
    assert calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [httpx.ReadTimeout, httpx.ReadError, httpx.WriteTimeout, httpx.WriteError, httpx.PoolTimeout, 401, 403, 500],
)
async def test_upload_ambiguous_failures_and_http_responses_are_not_retried(tmp_path, failure):
    file_path = tmp_path / "payload.bin"
    file_path.write_bytes(b"payload")
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if isinstance(failure, int):
            return httpx.Response(failure)
        raise failure("failed", request=request)

    async with NemesisClient(make_config(), transport=httpx.MockTransport(handler)) as client:
        result = await client.post_file(file_path, make_metadata())
    assert isinstance(result, ErrorResponse)
    assert calls == 1


@pytest.mark.asyncio
async def test_missing_upload_file_returns_error():
    async with NemesisClient(
        make_config(), transport=httpx.MockTransport(lambda _request: httpx.Response(200))
    ) as client:
        result = await client.post_file("/does/not/exist", make_metadata())
    assert isinstance(result, ErrorResponse)
    assert "not found" in result.detail.lower()


@pytest.mark.asyncio
async def test_upload_permission_error_returns_error(tmp_path, monkeypatch):
    file_path = tmp_path / "unreadable.bin"
    file_path.write_bytes(b"content")
    monkeypatch.setattr("cli.nemesis_client.os.access", lambda *_args: False)
    async with NemesisClient(
        make_config(), transport=httpx.MockTransport(lambda _request: httpx.Response(200))
    ) as client:
        result = await client.post_file(file_path, make_metadata())
    assert isinstance(result, ErrorResponse)
    assert "permission" in result.detail.lower()


@pytest.mark.asyncio
async def test_invalid_health_json_returns_error():
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": "not a health response"})

    async with NemesisClient(make_config(), transport=httpx.MockTransport(handler)) as client:
        result = await client.get_health()
    assert isinstance(result, ErrorResponse)
    assert "status" in result.detail


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [b"not-json", {}])
async def test_malformed_upload_success_response_returns_error_without_retry(tmp_path, payload):
    file_path = tmp_path / "payload.bin"
    file_path.write_bytes(b"payload")
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if isinstance(payload, dict):
            return httpx.Response(200, json=payload)
        return httpx.Response(200, content=payload)

    async with NemesisClient(make_config(), transport=httpx.MockTransport(handler)) as client:
        result = await client.post_file(file_path, make_metadata())
    assert isinstance(result, ErrorResponse)
    assert calls == 1


@pytest.mark.asyncio
async def test_missing_metadata_raises_before_transport():
    async with NemesisClient(
        make_config(), transport=httpx.MockTransport(lambda _request: httpx.Response(200))
    ) as client:
        with pytest.raises(ValueError, match="metadata is required"):
            await client.post_file("/unused", None)


@pytest.mark.asyncio
async def test_auth_and_preflight_timeout_settings_are_applied_to_requests(monkeypatch):
    request_seen = None
    constructor_options = {}
    original_async_client = httpx.AsyncClient

    class RecordingAsyncClient(original_async_client):
        def __init__(self, *args: Any, **kwargs: Any):
            constructor_options.update(kwargs)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", RecordingAsyncClient)

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_seen
        request_seen = request
        return httpx.Response(200, json={"status": "healthy"})

    async with NemesisClient(
        make_config(), verify_ssl=False, connect_timeout=7, transport=httpx.MockTransport(handler)
    ) as client:
        await client.get_health(timeout=3)
        assert client._http.timeout.connect == 7
        assert client._http.timeout.pool == 7
    assert request_seen.headers["authorization"].startswith("Basic ")
    assert request_seen.extensions["timeout"] == {"connect": 3, "read": 3, "write": 3, "pool": 3}
    assert constructor_options["verify"] is False


@pytest.mark.asyncio
async def test_upload_timeout_extensions_keep_long_read_write_limits(tmp_path):
    file_path = tmp_path / "payload.bin"
    file_path.write_bytes(b"payload")
    request_seen = None

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_seen
        request_seen = request
        return httpx.Response(
            200,
            json={
                "object_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "submission_id": "f0e1d2c3-b4a5-6789-0abc-def123456789",
            },
        )

    async with NemesisClient(
        make_config(), verify_ssl=False, connect_timeout=7, transport=httpx.MockTransport(handler)
    ) as client:
        await client.post_file(file_path, make_metadata())
    assert request_seen.extensions["timeout"] == {"connect": 7, "read": 520.0, "write": 520.0, "pool": 7}


@pytest.mark.asyncio
async def test_upload_limit_is_four_and_event_loop_stays_responsive(tmp_path):
    entered = 0
    peak = 0
    all_entered = asyncio.Event()
    release = asyncio.Event()

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal entered, peak
        entered += 1
        peak = max(peak, entered)
        if entered == 4:
            all_entered.set()
        await release.wait()
        entered -= 1
        return httpx.Response(
            200,
            json={
                "object_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "submission_id": "f0e1d2c3-b4a5-6789-0abc-def123456789",
            },
        )

    paths = []
    for index in range(5):
        path = tmp_path / f"{index}.bin"
        path.write_bytes(b"content")
        paths.append(path)
    async with NemesisClient(make_config(), transport=httpx.MockTransport(handler)) as client:
        uploads = [asyncio.create_task(client.post_file(path, make_metadata())) for path in paths]
        await asyncio.wait_for(all_entered.wait(), 1)
        heartbeat = asyncio.Event()
        asyncio.get_running_loop().call_soon(heartbeat.set)
        await asyncio.wait_for(heartbeat.wait(), 1)
        assert peak == 4
        release.set()
        await asyncio.gather(*uploads)


@pytest.mark.asyncio
async def test_info_and_yara_methods_return_typed_errors():
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    async with NemesisClient(make_config(), transport=httpx.MockTransport(handler)) as client:
        assert isinstance(await client.get_api_info(), ErrorResponse)
        assert isinstance(await client.reload_yara_rules(), ErrorResponse)


@pytest.mark.asyncio
async def test_info_and_yara_success_responses_are_typed():
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/":
            return httpx.Response(200, json={"name": "Nemesis", "version": "2.0"})
        return httpx.Response(200, json={"message": "reloaded"})

    async with NemesisClient(make_config(), transport=httpx.MockTransport(handler)) as client:
        info = await client.get_api_info()
        yara = await client.reload_yara_rules()
    assert info.name == "Nemesis"
    assert yara.message == "reloaded"


@pytest.mark.asyncio
async def test_http_response_is_not_retried():
    requests = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(503)

    async with NemesisClient(make_config(), transport=httpx.MockTransport(handler)) as client:
        result = await client.get_health()
    assert isinstance(result, ErrorResponse)
    assert requests == 1


@pytest.mark.asyncio
async def test_async_client_is_required_for_requests():
    with pytest.raises(RuntimeError, match="async with"):
        await NemesisClient(make_config()).get_health()


@pytest.mark.asyncio
async def test_preview_upload_hashes_file_without_returning_a_remote_id(tmp_path: Path, caplog):
    import logging

    caplog.set_level(logging.INFO)
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"preview")

    async with PreviewNemesisClient() as client:
        result = await client.post_file(file_path, make_metadata())

    assert isinstance(result, PreviewUploadResult)
    assert result.size_bytes == 7
    assert result.sha256 == "5975cf1bba432391c94667f5886225f69377c0aa8b9fa21fddfb21c89bcf9092"
    assert not hasattr(result, "object_id")
    assert "WOULD UPLOAD" in caplog.text


@pytest.mark.asyncio
async def test_preview_upload_waits_for_hash_thread_before_propagating_cancellation(tmp_path: Path, monkeypatch):
    import cli.nemesis_client as module

    started = threading.Event()
    release = threading.Event()

    def blocked_hash(_path: Path) -> tuple[int, str]:
        started.set()
        release.wait(timeout=5)
        return 1, "hash"

    monkeypatch.setattr(module, "_hash_file", blocked_hash)
    task = asyncio.create_task(PreviewNemesisClient().post_file(tmp_path / "sample", make_metadata()))
    assert await asyncio.to_thread(started.wait, 1)
    task.cancel()
    await asyncio.sleep(0.01)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task

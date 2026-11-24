"""Mythic connector enforces nemesis.max_file_size (audit #159b)."""

import base64
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cli.mythic_connector import handlers
from cli.mythic_connector.db import Database
from cli.mythic_connector.handlers import FileHandler, FileTooLargeError
from cli.nemesis_client import PreviewUploadResult

MAX_SIZE = 10


class FakeContent:
    def __init__(self, chunks):
        self._chunks = chunks

    async def iter_chunked(self, _size):
        for chunk in self._chunks:
            yield chunk


class FakeResponse:
    def __init__(self, chunks, content_length=None, status=200):
        self.status = status
        self.content_length = content_length
        self.content = FakeContent(chunks)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class FakeSession:
    def __init__(self, response):
        self._response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def get(self, *args, **kwargs):
        return self._response


def patch_session(monkeypatch, response):
    monkeypatch.setattr(handlers.aiohttp, "ClientSession", lambda *a, **kw: FakeSession(response))


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "state"))
    try:
        yield database
    finally:
        database.close()


@pytest.fixture
def nemesis():
    client = SimpleNamespace()
    client.post_file = AsyncMock(return_value=PreviewUploadResult(size_bytes=4, sha256="0" * 64))
    return client


@pytest.fixture
def handler(db, nemesis):
    mythic_client = SimpleNamespace(
        current_operation_id="op-1", http="http://", server_ip="mythic", server_port=7443, apitoken="t"
    )
    config = SimpleNamespace(
        project="proj",
        mythic=SimpleNamespace(url="http://mythic:7443", agent_id="mythic"),
        networking=SimpleNamespace(timeout_sec=5, validate_https_certs=True),
        nemesis=SimpleNamespace(max_file_size=MAX_SIZE, expiration_days=100),
    )
    return FileHandler(mythic_client, nemesis, db, config)


def file_meta(uuid="file-1", **extra):
    meta = {
        "id": 1,
        "agent_file_id": uuid,
        "complete": True,
        "deleted": False,
        "filename_text": base64.b64encode(b"report.txt").decode(),
        "full_remote_path_text": base64.b64encode(b"C:/report.txt").decode(),
        "host": "ws01",
        "timestamp": "2025-01-01T00:00:00.000000",
    }
    meta.update(extra)
    return meta


@pytest.mark.parametrize(
    ("size", "expected"),
    [(None, True), (0, True), (MAX_SIZE, True), (MAX_SIZE + 1, False), ("11", False), ("junk", True), (True, True)],
)
def test_check_file_size(handler, size, expected):
    assert handler._check_file_size(size) is expected


@pytest.mark.asyncio
async def test_file_within_limit_is_uploaded(handler, nemesis, db, monkeypatch):
    patch_session(monkeypatch, FakeResponse([b"abcd", b"ef"], content_length=6))
    await handler.handle_file(file_meta())
    nemesis.post_file.assert_awaited_once()
    assert db.get_strict("filemetafile-1") == b"1"


@pytest.mark.asyncio
async def test_file_exactly_at_limit_is_uploaded(handler, nemesis, monkeypatch):
    patch_session(monkeypatch, FakeResponse([b"x" * MAX_SIZE]))
    await handler.handle_file(file_meta())
    nemesis.post_file.assert_awaited_once()


@pytest.mark.asyncio
async def test_oversized_content_length_is_skipped_before_streaming(handler, nemesis, db, monkeypatch):
    patch_session(monkeypatch, FakeResponse([b"never read"], content_length=MAX_SIZE + 1))
    await handler.handle_file(file_meta())
    nemesis.post_file.assert_not_awaited()
    # Marked processed so it is not retried forever.
    assert db.get_strict("filemetafile-1") == b"1"


@pytest.mark.asyncio
async def test_oversized_stream_without_content_length_is_skipped(handler, nemesis, db, monkeypatch):
    patch_session(monkeypatch, FakeResponse([b"x" * 6, b"x" * 6], content_length=None))
    await handler.handle_file(file_meta())
    nemesis.post_file.assert_not_awaited()
    assert db.get_strict("filemetafile-1") == b"1"


@pytest.mark.asyncio
async def test_lying_content_length_is_still_enforced_while_streaming(handler, monkeypatch, tmp_path):
    patch_session(monkeypatch, FakeResponse([b"x" * (MAX_SIZE + 5)], content_length=1))
    callback = AsyncMock()
    with pytest.raises(FileTooLargeError):
        await handler.download_file("file-1", callback)
    callback.assert_not_awaited()


@pytest.mark.asyncio
async def test_oversized_content_length_skips_upload(handler, nemesis, db, monkeypatch):
    # Mythic's GraphQL filemeta has no size column, so the limit is enforced from the download response.
    patch_session(monkeypatch, FakeResponse([b"x"], content_length=MAX_SIZE + 1))
    await handler.handle_file(file_meta(size=MAX_SIZE + 1))
    nemesis.post_file.assert_not_awaited()
    assert db.get_strict("filemetafile-1") == b"1"


@pytest.mark.asyncio
async def test_temp_file_removed_after_oversized_download(handler, monkeypatch, tmp_path):
    created = []
    real_mkstemp = handlers.tempfile.mkstemp

    def tracking_mkstemp(*args, **kwargs):
        fd, path = real_mkstemp(dir=tmp_path)
        created.append(path)
        return fd, path

    monkeypatch.setattr(handlers.tempfile, "mkstemp", tracking_mkstemp)
    patch_session(monkeypatch, FakeResponse([b"x" * (MAX_SIZE + 1)]))
    with pytest.raises(FileTooLargeError):
        await handler.download_file("file-1", AsyncMock())
    assert created and not any(os.path.exists(p) for p in created)

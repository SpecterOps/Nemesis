"""Mythic connector reliability: TLS, error classification, paths, metadata, reconciliation and pending limits."""

import asyncio
import base64
import json
import ssl
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cli.mythic_connector import config as mythic_config
from cli.mythic_connector import handlers, sync, tls
from cli.mythic_connector.db import Database
from cli.mythic_connector.handlers import FileHandler, FileUnavailableError
from cli.nemesis_client import PreviewUploadResult
from gql.transport.exceptions import TransportClosed, TransportQueryError, TransportServerError
from mythic import mythic_classes, mythic_utilities
from websockets.datastructures import Headers
from websockets.exceptions import InvalidHandshake, InvalidMessage, InvalidStatusCode

# --- fixtures -----------------------------------------------------------------------------------------------


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


def make_config(**sync_settings):
    return SimpleNamespace(
        project="proj",
        mythic=SimpleNamespace(url="http://mythic:7443", agent_id="mythic"),
        networking=SimpleNamespace(timeout_sec=5, validate_https_certs=True),
        nemesis=SimpleNamespace(max_file_size=1000, expiration_days=30),
        sync=mythic_config.SyncConfig(**sync_settings),
    )


def make_handler(db, nemesis, **sync_settings):
    mythic_client = SimpleNamespace(
        current_operation_id="op-1", http="http://", server_ip="mythic", server_port=7443, apitoken="t"
    )
    return FileHandler(mythic_client, nemesis, db, make_config(**sync_settings))


@pytest.fixture
def handler(db, nemesis):
    return make_handler(db, nemesis)


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def file_meta(uuid="file-1", file_id=1, **extra):
    meta = {
        "id": file_id,
        "agent_file_id": uuid,
        "complete": True,
        "deleted": False,
        "filename_text": b64("report.txt"),
        "full_remote_path_text": b64("C:\\Users\\bob\\report.txt"),
        "host": "ws01",
        "timestamp": "2026-03-01T10:20:30.123456",
        "is_screenshot": False,
        "chunks_received": 1,
        "total_chunks": 1,
    }
    meta.update(extra)
    return meta


class FakeContent:
    def __init__(self, chunks):
        self._chunks = chunks

    async def iter_chunked(self, _size):
        for chunk in self._chunks:
            yield chunk


class FakeResponse:
    def __init__(self, chunks=(b"data",), status=200):
        self.status = status
        self.content_length = None
        self.content = FakeContent(list(chunks))

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class FakeSession:
    instances: list["FakeSession"] = []

    def __init__(self, response, **kwargs):
        self._response = response
        self.kwargs = kwargs
        FakeSession.instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def get(self, *args, **kwargs):
        return self._response


def patch_session(monkeypatch, response):
    FakeSession.instances = []
    monkeypatch.setattr(handlers.aiohttp, "ClientSession", lambda *a, **kw: FakeSession(response, **kw))


def pending(db, handler, uuid):
    raw = db.get_strict(f"{handler.state_prefix}pending:{uuid}")
    return json.loads(raw) if raw else None


def failed(db, handler, uuid):
    raw = db.get_strict(f"{handler.state_prefix}failed:{uuid}")
    return json.loads(raw) if raw else None


# --- #145 TLS ------------------------------------------------------------------------------------------------


@pytest.fixture
def restore_tls():
    originals = {name: getattr(mythic_utilities, name) for name in tls._REPLACEMENTS}
    yield
    for name, value in originals.items():
        setattr(mythic_utilities, name, value)
    tls._installed = False
    tls._verify_certificates = True


def mythic_instance(use_ssl: bool):
    return mythic_classes.Mythic(server_ip="mythic.example", server_port=7443, apitoken="tok", ssl=use_ssl)


@pytest.mark.asyncio
async def test_https_transports_verify_certificates(restore_tls):
    tls.install(True)
    instance = mythic_instance(True)
    http = await mythic_utilities.get_http_transport(instance)
    ws = await mythic_utilities.get_ws_transport(instance)
    for transport in (http, ws):
        assert isinstance(transport.ssl, ssl.SSLContext)
        assert transport.ssl.verify_mode == ssl.CERT_REQUIRED
        assert transport.ssl.check_hostname is True


@pytest.mark.asyncio
async def test_verification_can_be_disabled(restore_tls):
    tls.install(False)
    instance = mythic_instance(True)
    assert (await mythic_utilities.get_http_transport(instance)).ssl is False
    ws = await mythic_utilities.get_ws_transport(instance)
    # websockets would verify on wss:// with ssl=False, so an explicit non-verifying context is needed.
    assert isinstance(ws.ssl, ssl.SSLContext)
    assert ws.ssl.verify_mode == ssl.CERT_NONE


@pytest.mark.asyncio
async def test_plain_http_uses_no_tls(restore_tls):
    tls.install(True)
    instance = mythic_instance(False)
    assert (await mythic_utilities.get_http_transport(instance)).ssl is False
    assert (await mythic_utilities.get_ws_transport(instance)).ssl is False


def test_install_replaces_every_library_helper(restore_tls):
    tls.install(True)
    for name, replacement in tls._REPLACEMENTS.items():
        assert getattr(mythic_utilities, name) is replacement


@pytest.mark.asyncio
async def test_login_posts_with_verifying_context(restore_tls, monkeypatch):
    """mythic.login resolves http_post through the module, so the replacement carries the SSL context."""
    from mythic import mythic as mythic_api

    seen = {}

    class LoginSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        def post(self, url, **kwargs):
            seen.update(kwargs)
            raise ConnectionError("stop after recording the request")

    monkeypatch.setattr(tls.aiohttp, "ClientSession", LoginSession)
    tls.install(True)
    with pytest.raises(ConnectionError):
        await mythic_api.login(server_ip="mythic.example", server_port=7443, username="u", password="p", ssl=True)
    assert isinstance(seen["ssl"], ssl.SSLContext) and seen["ssl"].verify_mode == ssl.CERT_REQUIRED


def test_install_fails_loudly_if_library_changes(restore_tls, monkeypatch):
    monkeypatch.delattr(mythic_utilities, "http_get_chunked")
    with pytest.raises(RuntimeError, match="http_get_chunked"):
        tls.install(True)


# --- #12 transient error classification ----------------------------------------------------------------------


def invalid_status_code(status):
    return InvalidStatusCode(status, Headers())


@pytest.mark.parametrize(
    ("exc", "transient"),
    [
        (TransportServerError("connection_error", None), True),
        (TransportServerError("bad gateway", 502), True),
        (TransportServerError("rate limited", 429), True),
        (TransportServerError("unauthorized", 401), False),
        (TransportServerError("forbidden", 403), False),
        (invalid_status_code(502), True),
        (invalid_status_code(503), True),
        (invalid_status_code(401), False),
        (invalid_status_code(403), False),
        (InvalidMessage("did not receive a valid HTTP response"), True),
        (InvalidHandshake("handshake failed"), True),
        (TransportQueryError("database query error"), True),
        (TransportQueryError("access-denied: not allowed to query filemeta"), False),
        (TransportQueryError("field 'nope' not found in type: 'filemeta'"), False),
        (TransportQueryError("Could not verify JWT: JWTExpired"), False),
        (TransportClosed("closed"), True),
        (ValueError("bad config"), False),
    ],
)
def test_transient_classification(exc, transient):
    assert sync._is_transient_mythic_error(exc) is transient


# --- #11 path fallback, #13 metadata times, #149 download timeout --------------------------------------------


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        ({}, "C:\\Users\\bob\\report.txt"),
        ({"full_remote_path_text": "", "is_screenshot": True, "filename_text": b64("shot.png")}, "shot.png"),
        (
            {"full_remote_path_text": None, "is_screenshot": True, "filename_text": b64("shot.png"), "host": None},
            "shot.png",
        ),
        ({"full_remote_path_text": b64(""), "filename_text": b64("notes.txt")}, "notes.txt"),
    ],
)
@pytest.mark.asyncio
async def test_upload_path_falls_back_when_mythic_has_no_full_path(handler, nemesis, monkeypatch, extra, expected):
    patch_session(monkeypatch, FakeResponse())
    await handler.handle_file(file_meta(**extra))
    assert nemesis.post_file.await_args.args[1].path == expected


@pytest.mark.asyncio
async def test_metadata_uses_mythic_timestamp_and_expiration_days(handler, nemesis, monkeypatch):
    patch_session(monkeypatch, FakeResponse())
    collected = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=1)
    await handler.handle_file(file_meta(timestamp=collected.replace(tzinfo=None).isoformat()))
    metadata = nemesis.post_file.await_args.args[1]
    assert metadata.timestamp == collected
    assert timedelta(days=29, hours=23) < metadata.expiration - datetime.now(UTC) <= timedelta(days=30)


@pytest.mark.asyncio
async def test_unparseable_timestamp_falls_back_to_now(handler, nemesis, monkeypatch):
    patch_session(monkeypatch, FakeResponse())
    await handler.handle_file(file_meta(timestamp="not a time"))
    metadata = nemesis.post_file.await_args.args[1]
    assert abs(metadata.timestamp - datetime.now(UTC)) < timedelta(seconds=10)


@pytest.mark.asyncio
async def test_download_has_no_total_timeout(handler, monkeypatch):
    patch_session(monkeypatch, FakeResponse())
    await handler.download_file("file-1", AsyncMock())
    timeout = FakeSession.instances[0].kwargs["timeout"]
    assert timeout.total is None
    assert timeout.connect == 5
    assert timeout.sock_read >= handlers.DOWNLOAD_READ_TIMEOUT_SEC


# --- #16 missing files, stalled downloads ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_complete_file_404_given_up_after_three_attempts(handler, db, monkeypatch):
    handler._enqueue_discovered([file_meta()], 1)
    monkeypatch.setattr(handler, "download_file", AsyncMock(side_effect=FileUnavailableError("404")))
    monkeypatch.setattr(handler, "_refresh_pending", AsyncMock(return_value=[file_meta()]))
    for attempt in range(1, handlers.MAX_MISSING_ATTEMPTS):
        await handler.handle_file(file_meta())
        assert pending(db, handler, "file-1")["missing"] == attempt
        assert failed(db, handler, "file-1") is None
    await handler.handle_file(file_meta())
    assert pending(db, handler, "file-1") is None
    assert "404" in failed(db, handler, "file-1")["reason"]
    # Given-up files are never re-discovered.
    handler._enqueue_discovered([file_meta()], 1)
    assert pending(db, handler, "file-1") is None


@pytest.mark.asyncio
async def test_missing_count_survives_retry_bookkeeping(handler, db, monkeypatch):
    handler._enqueue_discovered([file_meta()], 1)
    monkeypatch.setattr(handler, "download_file", AsyncMock(side_effect=FileUnavailableError("404")))
    monkeypatch.setattr(handler, "_refresh_pending", AsyncMock(return_value=[file_meta()]))
    await handler.process_pending_once([file_meta()])
    entry = pending(db, handler, "file-1")
    assert entry["missing"] == 1 and entry["attempt"] == 1


@pytest.mark.asyncio
async def test_incomplete_file_404_is_not_counted(handler, db, monkeypatch):
    handler._enqueue_discovered([file_meta(complete=False)], 1)
    monkeypatch.setattr(handler, "download_file", AsyncMock(side_effect=FileUnavailableError("404")))
    monkeypatch.setattr(handler, "_refresh_pending", AsyncMock(return_value=[file_meta(complete=False)]))
    await handler.handle_file(file_meta(complete=False))
    assert "missing" not in pending(db, handler, "file-1")


@pytest.mark.asyncio
async def test_stalled_download_is_given_up(handler, db):
    handler._enqueue_discovered([file_meta(complete=False, chunks_received=2, total_chunks=9)], 1)
    key = f"{handler.state_prefix}pending:file-1"
    entry = pending(db, handler, "file-1")
    entry["progress_at"] = time.time() - 8 * 86400
    db.write_batch({key: json.dumps(entry)})
    await handler.process_pending_once([file_meta(complete=False, chunks_received=2, total_chunks=9)])
    assert pending(db, handler, "file-1") is None
    assert "2/9 chunks" in failed(db, handler, "file-1")["reason"]


@pytest.mark.asyncio
async def test_download_progress_resets_stall_clock(handler, db):
    handler._enqueue_discovered([file_meta(complete=False, chunks_received=2, total_chunks=9)], 1)
    key = f"{handler.state_prefix}pending:file-1"
    entry = pending(db, handler, "file-1")
    entry["progress_at"] = time.time() - 8 * 86400
    db.write_batch({key: json.dumps(entry)})
    await handler.process_pending_once([file_meta(complete=False, chunks_received=3, total_chunks=9)])
    entry = pending(db, handler, "file-1")
    assert entry["chunks"] == 3 and time.time() - entry["progress_at"] < 60
    assert failed(db, handler, "file-1") is None


@pytest.mark.asyncio
async def test_slow_but_recent_download_is_kept(handler, db):
    handler._enqueue_discovered([file_meta(complete=False, chunks_received=2)], 1)
    await handler.process_pending_once([file_meta(complete=False, chunks_received=2)])
    assert pending(db, handler, "file-1") is not None


@pytest.mark.asyncio
async def test_legacy_pending_entry_starts_stall_clock(handler, db):
    key = f"{handler.state_prefix}pending:file-1"
    db.write_batch({key: json.dumps({"id": 1, "uuid": "file-1", "attempt": 0, "retry_at": 0})})
    await handler.process_pending_once([file_meta(complete=False, chunks_received=0)])
    assert "progress_at" in pending(db, handler, "file-1")


def test_give_up_days_configurable(db, nemesis):
    assert make_handler(db, nemesis, pending_give_up_days=2).give_up_sec == 2 * 86400


# --- #14 reconciliation ---------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reconcile_enqueues_only_missed_rows(handler, db, monkeypatch):
    handler._enqueue_discovered([file_meta("pending-1", 5, complete=False)], 50)
    db.write_batch({"filemetadone-1": "1", f"{handler.state_prefix}failed:gave-up": "{}"})
    query = AsyncMock(
        return_value={
            "filemeta": [
                {"id": 3, "agent_file_id": "done-1"},
                {"id": 4, "agent_file_id": "late-1", "chunks_received": 1},
                {"id": 5, "agent_file_id": "pending-1"},
                {"id": 6, "agent_file_id": "gave-up"},
                {"id": 7, "agent_file_id": ""},
            ]
        }
    )
    monkeypatch.setattr(handlers.mythic, "execute_custom_query", query)
    assert await handler.reconcile_once() == 1
    assert pending(db, handler, "late-1")["id"] == 4
    assert query.await_args.kwargs["variables"] == {"low": 0, "high": 50}
    assert db.get_strict(f"{handler.state_prefix}cursor") == b"50"


@pytest.mark.asyncio
async def test_reconcile_window_is_bounded(handler, db, monkeypatch):
    db.write_batch({f"{handler.state_prefix}cursor": "5000"})
    query = AsyncMock(return_value={"filemeta": []})
    monkeypatch.setattr(handlers.mythic, "execute_custom_query", query)
    assert await handler.reconcile_once() == 0
    assert query.await_args.kwargs["variables"] == {"low": 5000 - handlers.RECONCILE_ID_WINDOW, "high": 5000}


@pytest.mark.asyncio
async def test_reconcile_without_cursor_does_nothing(handler, monkeypatch):
    query = AsyncMock()
    monkeypatch.setattr(handlers.mythic, "execute_custom_query", query)
    assert await handler.reconcile_once() == 0
    query.assert_not_awaited()


@pytest.mark.asyncio
async def test_reconcile_error_propagates_to_supervisor(handler, db, monkeypatch):
    db.write_batch({f"{handler.state_prefix}cursor": "10"})
    monkeypatch.setattr(handlers.mythic, "execute_custom_query", AsyncMock(side_effect=TransportClosed("gone")))
    with pytest.raises(TransportClosed):
        await handler.reconcile_once()


# --- #16 subscription cap and overflow polling -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_subscriptions_are_capped_and_overflow_is_polled(db, nemesis, monkeypatch):
    handler = make_handler(db, nemesis, max_pending_subscriptions=2)
    records = [file_meta(f"f{i}", i, complete=False) for i in range(1, 451)]
    handler._enqueue_discovered(records, 450)
    opened: list[tuple[int, ...]] = []

    async def fake_stream(ids):
        opened.append(ids)
        await asyncio.Event().wait()

    refresh = AsyncMock(side_effect=lambda entries: [r for r in records if r["id"] in {e["id"] for e in entries}])
    monkeypatch.setattr(handler, "_pending_stream", fake_stream)
    monkeypatch.setattr(handler, "_refresh_pending", refresh)
    task = asyncio.create_task(handler._pending_subscriptions())
    try:
        for _ in range(50):
            await asyncio.sleep(0)
            if refresh.await_count == 3 and len(opened) == 2:
                break
        assert len(opened) == 2
        assert sum(len(ids) for ids in opened) == 200
        assert handler._overflow_ids == set(range(201, 451))
        # Overflow files are fetched immediately (in batches of 100) and their metadata becomes visible.
        assert refresh.await_count == 3
        assert {450, 201} <= set(handler._pending_metadata)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_poll_overflow_drops_rows_that_disappeared(handler, monkeypatch):
    handler._overflow_ids = {1, 2}
    handler._pending_metadata = {1: file_meta("a", 1), 2: file_meta("b", 2)}
    monkeypatch.setattr(handler, "_refresh_pending", AsyncMock(return_value=[file_meta("a", 1, complete=False)]))
    await handler.poll_overflow_once()
    assert set(handler._pending_metadata) == {1}
    assert handler._pending_metadata[1]["complete"] is False


# --- #152 / config ----------------------------------------------------------------------------------------------


def write_settings(tmp_path, extra=""):
    path = tmp_path / "settings.yaml"
    path.write_text(
        'mythic:\n  url: "https://m.example"\n  credential: {username: a, password: b}\n'
        'nemesis:\n  url: "https://n.example"\n  credential: {username: n, password: n}\n' + extra
    )
    return str(path)


def test_db_path_defaults_to_xdg_state_dir(tmp_path, monkeypatch):
    mythic_config.get_settings.cache_clear()
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    settings = mythic_config.get_settings(write_settings(tmp_path))
    assert settings.db.path == str(tmp_path / "xdg" / "nemesis" / "connectors")
    assert settings.sync == mythic_config.SyncConfig(pending_give_up_days=7, max_pending_subscriptions=10)
    mythic_config.get_settings.cache_clear()


def test_db_path_expands_home(tmp_path, monkeypatch):
    mythic_config.get_settings.cache_clear()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    settings = mythic_config.get_settings(write_settings(tmp_path, 'db:\n  path: "~/mythic-state"\n'))
    assert settings.db.path == str(tmp_path / "home" / "mythic-state")
    mythic_config.get_settings.cache_clear()


def test_sync_settings_are_read(tmp_path):
    mythic_config.get_settings.cache_clear()
    settings = mythic_config.get_settings(
        write_settings(tmp_path, "sync:\n  pending_give_up_days: 3\n  max_pending_subscriptions: 4\n")
    )
    assert settings.sync == mythic_config.SyncConfig(pending_give_up_days=3, max_pending_subscriptions=4)
    mythic_config.get_settings.cache_clear()


@pytest.mark.parametrize(
    "values", [{"pending_give_up_days": 0}, {"max_pending_subscriptions": -1}, {"pending_give_up_days": True}]
)
def test_invalid_sync_settings_rejected(values):
    with pytest.raises(ValueError):
        mythic_config.SyncConfig(**values)

"""Fault-oriented integration tests against loopback HTTP and GraphQL servers."""

import asyncio
import hashlib
import os
import sys
from urllib.parse import urlparse

import plyvel
import pytest
import pytest_asyncio
import yaml
from cli.config import NemesisConfig as HttpNemesisConfig
from cli.config import PasswordCredential
from cli.mythic_connector import handlers
from cli.mythic_connector.config import (
    DatabaseConfig,
    MythicConfig,
    NetworkingConfig,
    Settings,
    TokenCredential,
    UsernamePasswordCredential,
)
from cli.mythic_connector.config import (
    NemesisConfig as ConnectorNemesisConfig,
)
from cli.mythic_connector.db import Database
from cli.mythic_connector.handlers import FileHandler
from cli.mythic_connector.sync import SyncService
from cli.nemesis_client import NemesisClient
from mythic import mythic
from tests.integration.mythic_surrogate import MythicSurrogate
from tests.integration.nemesis_surrogate import NemesisSurrogate


@pytest_asyncio.fixture
async def servers():
    mythic_server = await MythicSurrogate().start()
    nemesis_server = await NemesisSurrogate().start()
    try:
        yield mythic_server, nemesis_server
    finally:
        await mythic_server.close()
        await nemesis_server.close()


def config(mythic_server: MythicSurrogate, nemesis_server: NemesisSurrogate, db_path: str) -> Settings:
    return Settings(
        project="integration-test",
        mythic=MythicConfig(mythic_server.url, UsernamePasswordCredential("operator", "password")),
        nemesis=ConnectorNemesisConfig(
            url=urlparse(nemesis_server.url),
            credential=UsernamePasswordCredential("test", "test"),
            expiration_days=100,
            max_file_size=100_000_000,
        ),
        db=DatabaseConfig(db_path),
        networking=NetworkingConfig(timeout_sec=2, validate_https_certs=False),
    )


async def make_handler(cfg: Settings, nemesis_server: NemesisSurrogate) -> tuple[FileHandler, Database, NemesisClient]:
    parsed = urlparse(cfg.mythic.url)
    client = await mythic.login(
        username="operator",
        password="password",
        server_ip=parsed.hostname,
        server_port=parsed.port,
        ssl=False,
        timeout=2,
    )
    db = Database(cfg.db.path)
    nemesis = NemesisClient(
        HttpNemesisConfig(url=nemesis_server.url, credential=PasswordCredential(username="test", password="test")),
        verify_ssl=False,
        connect_timeout=1,
    )
    await nemesis.__aenter__()
    return FileHandler(client, nemesis, db, cfg), db, nemesis


async def wait_for_uploads(server: NemesisSurrogate, count: int, timeout: float = 3) -> None:
    async def poll() -> None:
        while len(server.uploads) < count:
            await asyncio.sleep(0.01)

    await asyncio.wait_for(poll(), timeout)


@pytest.mark.asyncio
async def test_incomplete_older_cursor_row_is_polled_until_complete(servers, tmp_path, monkeypatch):
    mythic_server, nemesis_server = servers
    incomplete = mythic_server.add_file(b"first", complete=False, name="first.txt", path="C:\\first.txt")
    mythic_server.add_file(b"second", name="second.txt", path="C:\\second.txt")
    cfg = config(mythic_server, nemesis_server, str(tmp_path / "state"))
    handler, db, nemesis = await make_handler(cfg, nemesis_server)
    task = asyncio.create_task(handler.subscribe())
    try:
        await wait_for_uploads(nemesis_server, 1)
        assert nemesis_server.uploads[0]["bytes"] == b"second"
        await mythic_server.complete_file(incomplete)
        await wait_for_uploads(nemesis_server, 2)
        assert {bytes(u["bytes"]) for u in nemesis_server.uploads} == {b"first", b"second"}
        assert any(e == {"event": "file_completed", "id": incomplete.id} for e in mythic_server.event_log)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        db.close()
        await nemesis.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["missing", "html", "truncated", "normal"])
async def test_download_rejects_missing_html_and_truncated_bodies_but_accepts_empty(servers, tmp_path, mode):
    mythic_server, nemesis_server = servers
    payload = b"" if mode == "normal" else b"credible-content"
    row = mythic_server.add_file(payload, download_mode=mode)
    cfg = config(mythic_server, nemesis_server, str(tmp_path / f"state-{mode}"))
    handler, db, nemesis = await make_handler(cfg, nemesis_server)
    try:
        if mode == "html":
            with pytest.raises(Exception, match="403"):
                await handler.handle_file(row.metadata())
        else:
            await handler.handle_file(row.metadata())
        if mode == "normal":
            assert len(nemesis_server.uploads) == 1
            assert nemesis_server.uploads[0]["bytes"] == b""
            assert nemesis_server.uploads[0]["sha256"] == hashlib.sha256(b"").hexdigest()
        else:
            assert nemesis_server.uploads == []
    finally:
        db.close()
        await nemesis.aclose()


@pytest.mark.asyncio
async def test_deleted_pending_file_is_removed_without_download(servers, tmp_path):
    mythic_server, nemesis_server = servers
    row = mythic_server.add_file(b"secret", complete=False)
    already_deleted = mythic_server.add_file(b"gone", deleted=True)
    cfg = config(mythic_server, nemesis_server, str(tmp_path / "state"))
    handler, db, nemesis = await make_handler(cfg, nemesis_server)
    try:
        handler._enqueue_discovered([already_deleted.metadata()], already_deleted.id)
        assert db.get_strict(handler.state_prefix + "pending:" + already_deleted.agent_file_id) is None
        handler._enqueue_discovered([row.metadata()], row.id)
        row.deleted = True
        await handler.process_pending_once()
        assert nemesis_server.uploads == []
        assert db.get_strict(handler.state_prefix + "pending:" + row.agent_file_id) is None
    finally:
        db.close()
        await nemesis.aclose()


@pytest.mark.asyncio
async def test_deletion_while_download_request_is_in_flight_prevents_upload(servers, tmp_path):
    mythic_server, nemesis_server = servers
    row = mythic_server.add_file(b"deleted during retrieval")
    mythic_server.download_started = asyncio.Event()
    mythic_server.download_release = asyncio.Event()
    cfg = config(mythic_server, nemesis_server, str(tmp_path / "state"))
    handler, db, nemesis = await make_handler(cfg, nemesis_server)
    try:
        task = asyncio.create_task(handler.handle_file(row.metadata()))
        await asyncio.wait_for(mythic_server.download_started.wait(), timeout=2)
        row.deleted = True
        mythic_server.download_release.set()
        await asyncio.wait_for(task, timeout=2)
        assert nemesis_server.uploads == []
    finally:
        db.close()
        await nemesis.aclose()


@pytest.mark.asyncio
async def test_nemesis_outage_retains_pending_then_uploads_after_recovery(servers, tmp_path, monkeypatch):
    mythic_server, nemesis_server = servers
    row = mythic_server.add_file(b"retry-me")
    cfg = config(mythic_server, nemesis_server, str(tmp_path / "state"))
    handler, db, nemesis = await make_handler(cfg, nemesis_server)
    monkeypatch.setattr(handlers, "RETRY_DELAYS_SEC", (0, 0, 0))
    try:
        handler._enqueue_discovered([row.metadata()], row.id)
        nemesis_server.online = False
        await handler.process_pending_once()
        key = handler.state_prefix + "pending:" + row.agent_file_id
        assert db.get_strict(key) is not None
        nemesis_server.online = True
        await handler.process_pending_once()
        assert len(nemesis_server.uploads) == 1
        assert db.get(f"filemeta{row.agent_file_id}") == 1
    finally:
        db.close()
        await nemesis.aclose()


@pytest.mark.asyncio
async def test_restart_reuses_database_and_skips_successful_file(servers, tmp_path):
    mythic_server, nemesis_server = servers
    row = mythic_server.add_file(b"once")
    cfg = config(mythic_server, nemesis_server, str(tmp_path / "durable-state"))
    handler, db, nemesis = await make_handler(cfg, nemesis_server)
    handler._enqueue_discovered([row.metadata()], row.id)
    await handler.process_pending_once()
    assert len(nemesis_server.uploads) == 1
    db.close()
    handler2, db2, nemesis2 = await make_handler(cfg, nemesis_server)
    try:
        await handler2.process_pending_once()
        assert len(nemesis_server.uploads) == 1
        assert db2.get(f"filemeta{row.agent_file_id}") == 1
    finally:
        db2.close()
        await nemesis.aclose()
        await nemesis2.aclose()


@pytest.mark.asyncio
async def test_restart_resumes_unfinished_pending_file(servers, tmp_path):
    mythic_server, nemesis_server = servers
    row = mythic_server.add_file(b"finish-after-restart", complete=False)
    cfg = config(mythic_server, nemesis_server, str(tmp_path / "unfinished-state"))
    handler, db, nemesis = await make_handler(cfg, nemesis_server)
    handler._enqueue_discovered([row.metadata()], row.id)
    await handler.process_pending_once()
    pending_key = handler.state_prefix + "pending:" + row.agent_file_id
    assert db.get_strict(pending_key) is not None
    db.close()
    handler2, db2, nemesis2 = await make_handler(cfg, nemesis_server)
    try:
        await mythic_server.complete_file(row)
        await handler2.process_pending_once()
        assert len(nemesis_server.uploads) == 1
        assert bytes(nemesis_server.uploads[0]["bytes"]) == b"finish-after-restart"
    finally:
        db2.close()
        await nemesis.aclose()
        await nemesis2.aclose()


@pytest.mark.asyncio
async def test_accepted_upload_with_dropped_response_retries_without_false_success(servers, tmp_path, monkeypatch):
    mythic_server, nemesis_server = servers
    row = mythic_server.add_file(b"at-least-once")
    cfg = config(mythic_server, nemesis_server, str(tmp_path / "state"))
    handler, db, nemesis = await make_handler(cfg, nemesis_server)
    monkeypatch.setattr(handlers, "RETRY_DELAYS_SEC", (0, 0, 0))
    try:
        handler._enqueue_discovered([row.metadata()], row.id)
        nemesis_server.drop_accepted_response = True
        await handler.process_pending_once()
        assert len(nemesis_server.uploads) == 1
        assert db.get(f"filemeta{row.agent_file_id}") is None
        nemesis_server.drop_accepted_response = False
        await handler.process_pending_once()
        assert len(nemesis_server.uploads) == 2
        assert db.get(f"filemeta{row.agent_file_id}") == 1
    finally:
        db.close()
        await nemesis.aclose()


@pytest.mark.asyncio
async def test_bad_password_and_revoked_token_are_rejected_by_real_sdk(servers):
    mythic_server, _ = servers
    bad_password_rejected = False
    try:
        await mythic.login(
            username="operator",
            password="wrong",
            server_ip="127.0.0.1",
            server_port=mythic_server.port,
            ssl=False,
            timeout=2,
        )
    except Exception:
        bad_password_rejected = True
    assert bad_password_rejected
    client = await mythic.login(
        username="operator",
        password="password",
        server_ip="127.0.0.1",
        server_port=mythic_server.port,
        ssl=False,
        timeout=2,
    )
    mythic_server.token_valid = False
    revoked_token_rejected = False
    try:
        await mythic.execute_custom_query(mythic=client, query="query revokedToken { meHook { status } }")
    except Exception:
        revoked_token_rejected = True
    assert revoked_token_rejected


@pytest.mark.asyncio
async def test_sync_service_treats_invalid_credentials_and_revoked_tokens_as_fatal(servers, tmp_path):
    mythic_server, nemesis_server = servers
    bad_password_cfg = config(mythic_server, nemesis_server, str(tmp_path / "bad-password-db"))
    bad_password_cfg.mythic.credential = UsernamePasswordCredential("operator", "wrong")
    with pytest.raises(RuntimeError, match="Permanent Mythic"):
        await asyncio.wait_for(SyncService(bad_password_cfg).run(), timeout=3)

    invalid_token_cfg = config(mythic_server, nemesis_server, str(tmp_path / "invalid-token-db"))
    invalid_token_cfg.mythic.credential = TokenCredential("not-a-valid-token")
    with pytest.raises(RuntimeError, match="Permanent Mythic"):
        await asyncio.wait_for(SyncService(invalid_token_cfg).run(), timeout=3)

    denied_filemeta_cfg = config(mythic_server, nemesis_server, str(tmp_path / "denied-filemeta-db"))
    denied_filemeta_cfg.mythic.credential = UsernamePasswordCredential("operator", "password")
    mythic_server.filemeta_denied = True
    with pytest.raises(RuntimeError, match="Permanent Mythic"):
        await asyncio.wait_for(SyncService(denied_filemeta_cfg).run(), timeout=3)
    assert any(event["event"] == "filemeta_denied" for event in mythic_server.event_log)

    mythic_server.filemeta_denied = False
    revoked_token_cfg = config(mythic_server, nemesis_server, str(tmp_path / "revoked-token-db"))
    revoked_token_cfg.mythic.credential = TokenCredential(mythic_server.token)
    mythic_server.token_valid = False
    with pytest.raises(RuntimeError, match="Permanent Mythic"):
        await asyncio.wait_for(SyncService(revoked_token_cfg).run(), timeout=3)


@pytest.mark.asyncio
async def test_legacy_completed_cursor_subscription_reproduces_missed_older_row(servers):
    mythic_server, _ = servers
    older = mythic_server.add_file(b"older", complete=False)
    mythic_server.add_file(b"newer")
    client = await mythic.login(
        username="operator",
        password="password",
        server_ip="127.0.0.1",
        server_port=mythic_server.port,
        ssl=False,
        timeout=2,
    )
    legacy_query = """subscription Legacy {
      filemeta_stream(cursor:{initial_value:{id:0}},batch_size:100,
        where:{is_download_from_agent:{_eq:true},complete:{_eq:true}}) { id agent_file_id complete }
    }"""
    stream = mythic.subscribe_custom_query(mythic=client, query=legacy_query, timeout=5)
    try:
        first = await asyncio.wait_for(anext(stream), timeout=2)
        assert [item["id"] for item in first["filemeta_stream"]] == [2]
        await mythic_server.complete_file(older)
        await asyncio.sleep(0.1)
        sent_ids = [
            file_id for event in mythic_server.event_log if event["event"] == "ws_data" for file_id in event["ids"]
        ]
        assert older.id not in sent_ids
    finally:
        await stream.aclose()


@pytest.mark.asyncio
async def test_real_cli_dry_run_downloads_without_touching_configured_database(servers, tmp_path, monkeypatch):
    mythic_server, _ = servers
    row = mythic_server.add_file(b"preview bytes", name="preview.txt", path="C:\\evidence\\preview.txt")
    monkeypatch.setenv("MYTHIC_SYNC_PROJECT", "inherited-environment-override")
    production_db = tmp_path / "production-state"
    sentinel_db = plyvel.DB(str(production_db), create_if_missing=True)
    sentinel_db.put(b"sentinel", b"preserve-me")
    sentinel_db.close()
    config_path = tmp_path / "settings.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "project": "integration-test",
                "mythic": {"url": mythic_server.url, "credential": {"username": "operator", "password": "password"}},
                "nemesis": {
                    "url": "http://127.0.0.1:1",
                    "credential": {"username": "unused", "password": "unused"},
                    "expiration_days": 30,
                    "max_file_size": 1000000,
                },
                "db": {"path": str(production_db)},
                "networking": {"timeout_sec": 2, "validate_https_certs": False},
            }
        ),
        encoding="utf-8",
    )
    child_env = {key: value for key, value in os.environ.items() if not key.startswith("MYTHIC_SYNC_")}
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "cli",
        "connect-mythic",
        "--config",
        str(config_path),
        "--dry-run",
        env=child_env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    assert process.stdout is not None
    output = bytearray()
    try:
        async with asyncio.timeout(12):
            while b"WOULD UPLOAD" not in output:
                line = await process.stdout.readline()
                if not line:
                    raise AssertionError(f"CLI exited before previewing the file: {output.decode(errors='replace')}")
                output.extend(line)
        assert b"preview.txt" in output
        assert b"project=integration-test" in output
        assert b"path=C:\\evidence\\preview.txt" in output
        assert b"size=13" in output
        assert hashlib.sha256(b"preview bytes").hexdigest().encode() in output
    finally:
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=3)
            except TimeoutError:
                process.kill()
                await process.wait()
        if process.stdout:
            output.extend(await process.stdout.read())
    check_db = plyvel.DB(str(production_db), create_if_missing=False)
    try:
        assert check_db.get(b"sentinel") == b"preserve-me"
        assert check_db.get(b"last_file_id") is None
        assert check_db.get(f"filemeta{row.agent_file_id}".encode()) is None
    finally:
        check_db.close()


@pytest.mark.asyncio
async def test_service_recovers_from_ws_drop_and_mythic_server_restart(servers, tmp_path, monkeypatch):
    mythic_server, nemesis_server = servers
    cfg = config(mythic_server, nemesis_server, str(tmp_path / "supervisor-state"))
    import cli.mythic_connector.sync as sync_module

    monkeypatch.setattr(sync_module, "RECONNECT_DELAYS_SEC", (0.05, 0.05, 0.05))
    service = SyncService(cfg)
    task = asyncio.create_task(service.run())

    async def wait_for_ws_ready(target: int) -> None:
        async def poll() -> None:
            while sum(event["event"] == "ws_ready" for event in mythic_server.event_log) < target:
                await asyncio.sleep(0.01)

        await asyncio.wait_for(poll(), timeout=5)

    try:
        await wait_for_ws_ready(1)
        port = mythic_server.port
        await mythic_server.complete_subscriptions()
        await wait_for_ws_ready(2)
        await mythic_server.disconnect_websockets()
        await wait_for_ws_ready(3)
        first = mythic_server.add_file(b"after-ws-drop")
        await mythic_server.publish(first)
        await wait_for_uploads(nemesis_server, 1)
        assert any(bytes(item["bytes"]) == b"after-ws-drop" for item in nemesis_server.uploads)

        await mythic_server.close()
        await asyncio.sleep(0.1)
        await mythic_server.start()
        assert mythic_server.port == port
        second = mythic_server.add_file(b"after-server-restart")
        await wait_for_ws_ready(4)
        await wait_for_uploads(nemesis_server, 2)
        assert {bytes(item["bytes"]) for item in nemesis_server.uploads} == {b"after-ws-drop", b"after-server-restart"}
        assert first.agent_file_id != second.agent_file_id
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

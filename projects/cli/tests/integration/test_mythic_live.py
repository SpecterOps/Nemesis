"""Opt-in fault reproduction against the isolated real Mythic/Hasura deployment.

Set NEMESIS_REAL_MYTHIC_DIR to the directory prepared by real_mythic/setup.py.
The fixed Docker project name and loopback endpoints deliberately cannot target
an arbitrary operational Mythic deployment.
"""

import asyncio
import contextlib
import os
import subprocess
import sys
import uuid
from pathlib import Path

import aiohttp
import pytest
import yaml
from cli.config import NemesisConfig as HttpNemesisConfig
from cli.config import PasswordCredential
from cli.mythic_connector import handlers
from cli.mythic_connector.config import (
    DatabaseConfig,
    MythicConfig,
    NemesisConfig,
    NetworkingConfig,
    Settings,
    TokenCredential,
    UsernamePasswordCredential,
)
from cli.mythic_connector.db import Database
from cli.mythic_connector.handlers import FileHandler, FileUnavailableError
from cli.mythic_connector.sync import SyncService
from cli.nemesis_client import NemesisClient as HttpNemesisClient
from cli.nemesis_client import PreviewNemesisClient
from gql.transport.exceptions import TransportQueryError
from mythic import mythic
from tests.integration.nemesis_surrogate import NemesisSurrogate

WORKDIR = os.environ.get("NEMESIS_REAL_MYTHIC_DIR")
pytestmark = [pytest.mark.asyncio, pytest.mark.skipif(not WORKDIR, reason="requires isolated real Mythic stack")]


def docker(*args):
    return subprocess.run(["docker", *args], check=True, text=True, capture_output=True, timeout=60).stdout.strip()


def sql(query):
    return docker(
        "exec", "nemesis-real-mythic-postgres-1", "psql", "-U", "mythic_user", "-d", "mythic_db", "-Atc", query
    )


def compose(*args):
    return docker("compose", "--env-file", "/dev/null", "-f", str(Path(WORKDIR) / "compose.yaml"), *args)


@pytest.fixture
def cfg(tmp_path):
    return Settings(
        project="real-mythic-reproduction",
        mythic=MythicConfig("http://127.0.0.1:18443", UsernamePasswordCredential("operator", "isolated-test-password")),
        nemesis=NemesisConfig("http://127.0.0.1:1", UsernamePasswordCredential("unused", "unused"), 100, 100_000_000),
        db=DatabaseConfig(str(tmp_path / "state")),
        networking=NetworkingConfig(5, False),
    )


@pytest.fixture
def files():
    rows = []

    def add(content=b"harmless-real-mythic-fixture", complete=True):
        file_uuid = str(uuid.uuid4())
        path = Path(WORKDIR) / "server/src" / f"nemesis-test-{file_uuid}"
        path.write_bytes(content)
        remote_path = f"/usr/src/app/{path.name}"
        row_id = int(
            sql(
                "INSERT INTO filemeta (agent_file_id,path,operation_id,operator_id,filename,full_remote_path,host,"
                "is_download_from_agent,complete,delete_after_fetch) VALUES "
                f"('{file_uuid}','{remote_path}',1,1,convert_to('test.txt','UTF8'),"
                f"convert_to('C:\\test.txt','UTF8'),'TEST-HOST',true,{str(complete).lower()},false) RETURNING id"
            ).splitlines()[0]
        )
        rows.append((row_id, path))
        return row_id, file_uuid

    yield add
    for row_id, path in rows:
        sql(f"DELETE FROM filemeta WHERE id={row_id}")
        path.unlink(missing_ok=True)


async def client(cfg):
    service = SyncService(cfg)
    await service.initialize_mythic()
    return service.mythic


async def wait_until(predicate, task=None, timeout=15):
    async def poll():
        while not predicate():
            if task and task.done():
                task.result()
                raise AssertionError("subscription ended unexpectedly")
            await asyncio.sleep(0.1)

    await asyncio.wait_for(poll(), timeout)


async def test_legacy_cursor_misses_late_completion(cfg, files):
    older, _ = files(complete=False)
    newer, _ = files()
    sdk = await client(cfg)
    query = f"""subscription LegacyCursor {{ filemeta_stream(
      cursor:{{initial_value:{{id:{older - 1}}}}}, batch_size:100,
      where:{{is_download_from_agent:{{_eq:true}},complete:{{_eq:true}}}}) {{id}} }}"""
    received = []

    async def consume():
        async for batch in mythic.subscribe_custom_query(mythic=sdk, query=query):
            received.extend(row["id"] for row in batch["filemeta_stream"])

    task = asyncio.create_task(consume())
    try:
        await wait_until(lambda: newer in received, task)
        sql(f"UPDATE filemeta SET complete=true WHERE id={older}")
        # Hasura's default streaming subscription refetch interval is one second.
        await asyncio.sleep(3)
        assert older not in received
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_fixed_connector_recovers_late_completion(cfg, files, monkeypatch):
    older, old_uuid = files(complete=False)
    _, new_uuid = files()
    sdk = await client(cfg)
    db = Database(cfg.db.path)
    async with PreviewNemesisClient() as preview:
        handler = FileHandler(sdk, preview, db, cfg)
        monkeypatch.setattr(handlers, "DISCOVERY_POLL_INTERVAL_SEC", 0.1)
        task = asyncio.create_task(handler.subscribe())
        try:
            await wait_until(lambda: handler._is_file_processed(new_uuid), task)
            assert not handler._is_file_processed(old_uuid)
            sql(f"UPDATE filemeta SET complete=true WHERE id={older}")
            await wait_until(lambda: handler._is_file_processed(old_uuid), task)
            assert handler._successful_files_count == 2
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            db.close()


async def test_sdk_silently_accepts_404_but_connector_rejects(cfg, tmp_path):
    sdk = await client(cfg)
    missing = str(uuid.uuid4())
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{cfg.mythic.url}/direct/download/{missing}", headers={"apitoken": sdk.apitoken}
        ) as resp:
            assert resp.status == 404
            body = await resp.read()
    # The actual SDK returns the error response bytes as though it were a file.
    assert await mythic.download_file(mythic=sdk, file_uuid=missing) == body
    db = Database(str(tmp_path / "download-state"))
    async with PreviewNemesisClient() as preview:
        handler = FileHandler(sdk, preview, db, cfg)
        called = []

        async def upload(path):
            called.append(path)

        try:
            with pytest.raises(FileUnavailableError, match="404"):
                await handler.download_file(missing, upload)
            assert not called
        finally:
            db.close()


async def test_invalid_api_token_is_only_detected_by_probe(cfg):
    sdk = await mythic.login(apitoken="invalid-test-token", server_ip="127.0.0.1", server_port=18443, ssl=False)
    assert sdk.apitoken == "invalid-test-token"
    cfg.mythic.credential = TokenCredential("invalid-test-token")
    with pytest.raises(TransportQueryError, match="access-denied"):
        await SyncService(cfg).initialize_mythic()


async def test_invalid_password_is_fatal(cfg):
    cfg.mythic.credential = UsernamePasswordCredential("operator", "wrong-password")
    with pytest.raises(Exception, match="Authentication Failed"):
        await SyncService(cfg).initialize_mythic()


async def test_pending_deletion_is_retired(cfg, files):
    row_id, file_uuid = files(complete=False)
    sdk = await client(cfg)
    db = Database(cfg.db.path)
    async with PreviewNemesisClient() as preview:
        handler = FileHandler(sdk, preview, db, cfg)
        try:
            handler._enqueue_discovered([{"id": row_id, "agent_file_id": file_uuid}], row_id)
            sql(f"UPDATE filemeta SET deleted=true WHERE id={row_id}")
            await handler.process_pending_once()
            assert not handler._pending_entries()
            assert not handler._is_file_processed(file_uuid)
            assert handler._successful_files_count == 0
        finally:
            db.close()


async def test_hasura_restart_reconnects_and_recovers_pending(cfg, files, monkeypatch):
    row_id, file_uuid = files(complete=False)
    monkeypatch.setattr(handlers, "DISCOVERY_POLL_INTERVAL_SEC", 0.1)
    service = SyncService(cfg)
    async with PreviewNemesisClient() as preview:
        service.nemesis = preview
        service.dry_run = True
        task = asyncio.create_task(service._run_with_nemesis())
        stopped = False
        try:
            await wait_until(lambda: service.file_handler and bool(service.file_handler._pending_entries()), task)
            previous = service.file_handler
            compose("stop", "hasura")
            stopped = True
            sql(f"UPDATE filemeta SET complete=true WHERE id={row_id}")
            compose("start", "hasura")
            stopped = False
            await wait_until(
                lambda: service.file_handler is not previous and service.file_handler._is_file_processed(file_uuid),
                task,
                timeout=40,
            )
        finally:
            if stopped:
                compose("start", "hasura")
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task


async def test_revoked_token_is_rejected_on_next_query(cfg):
    sdk = await client(cfg)
    token_id = int(sql("SELECT id FROM apitokens WHERE active=true AND operator_id=1 ORDER BY id LIMIT 1"))
    sql(f"UPDATE apitokens SET active=false WHERE id={token_id}")
    try:
        with pytest.raises(TransportQueryError, match="access-denied"):
            await mythic.execute_custom_query(mythic=sdk, query="query RevokedToken { filemeta(limit:1) { id } }")
    finally:
        sql(f"UPDATE apitokens SET active=true WHERE id={token_id}")


async def test_upload_outage_keeps_real_mythic_file_pending(cfg, files):
    content = b"actual Mythic download, temporary Nemesis upload failure"
    row_id, file_uuid = files(content)
    sdk = await client(cfg)
    endpoint = await NemesisSurrogate().start()
    db = Database(cfg.db.path)
    try:
        async with HttpNemesisClient(
            HttpNemesisConfig(url=endpoint.url, credential=PasswordCredential(username="test", password="test")),
            verify_ssl=False,
        ) as nemesis:
            handler = FileHandler(sdk, nemesis, db, cfg)
            handler._enqueue_discovered([{"id": row_id, "agent_file_id": file_uuid}], row_id)
            endpoint.online = False
            await handler.process_pending_once()
            assert not handler._is_file_processed(file_uuid)
            assert len(handler._pending_entries()) == 1
            assert not endpoint.uploads
            endpoint.online = True
            # Make the persisted retry due now; do not mock network operations.
            key, entry = handler._pending_entries()[0]
            import json

            entry["retry_at"] = 0
            db.write_batch({key: json.dumps(entry)})
            await handler.process_pending_once()
            assert handler._is_file_processed(file_uuid)
            assert not handler._pending_entries()
            assert endpoint.uploads[0]["bytes"] == content
    finally:
        db.close()
        await endpoint.close()


async def test_valid_empty_file_is_previewed(cfg, files):
    row_id, file_uuid = files(b"")
    sdk = await client(cfg)
    db = Database(cfg.db.path)
    try:
        async with PreviewNemesisClient() as preview:
            handler = FileHandler(sdk, preview, db, cfg)
            handler._enqueue_discovered([{"id": row_id, "agent_file_id": file_uuid}], row_id)
            await handler.process_pending_once()
            assert handler._is_file_processed(file_uuid)
            assert handler._successful_files_count == 1
    finally:
        db.close()


async def test_real_cli_dry_run_downloads_without_nemesis(cfg, files, tmp_path):
    _, file_uuid = files(b"real CLI dry run against actual Mythic")
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        yaml.safe_dump(
            {
                "project": cfg.project,
                "mythic": {
                    "url": cfg.mythic.url,
                    "credential": {"username": "operator", "password": "isolated-test-password"},
                },
                "nemesis": {"url": "http://127.0.0.1:1", "credential": {"username": "unused", "password": "unused"}},
                "db": {"path": cfg.db.path},
                "networking": {"timeout_sec": 5, "validate_https_certs": False},
            }
        )
    )
    output = tmp_path / "connector.log"
    child_env = {key: value for key, value in os.environ.items() if not key.startswith("MYTHIC_SYNC_")}
    with output.open("w") as stream:
        process = subprocess.Popen(
            [sys.executable, "-m", "cli", "connect-mythic", "--config", str(settings), "--dry-run"],
            stdout=stream,
            stderr=subprocess.STDOUT,
            env=child_env,
        )
        try:
            await wait_until(lambda: file_uuid in output.read_text() and "WOULD UPLOAD" in output.read_text())
            assert process.poll() is None
            assert not Path(cfg.db.path).exists()
        finally:
            process.terminate()
            try:
                await asyncio.to_thread(process.wait, 10)
            except subprocess.TimeoutExpired:
                process.kill()
                await asyncio.to_thread(process.wait, 10)

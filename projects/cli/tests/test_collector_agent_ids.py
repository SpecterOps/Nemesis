"""Exercise collector configuration, upload metadata, and persistent state together."""

import asyncio
import base64
import logging
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import plyvel
import pytest
import yaml
from cli.cobaltstrike_connector import cobaltstrike_connector as cs
from cli.collector_state import collector_state_path
from cli.config import CobaltStrikeConfig, MythicConfig, OutflankConfig, load_config
from cli.mythic_connector.config import MythicConfig as RuntimeMythicConfig
from cli.mythic_connector.config import UsernamePasswordCredential, get_settings
from cli.mythic_connector.handlers import FileHandler
from cli.mythic_connector.sync import SyncService
from cli.stage1_connector import stage1_connector as stage1
from common.models2.api import FileWithMetadataResponse
from dynaconf import ValidationError as SettingsValidationError
from pydantic import ValidationError

SETTINGS_DIR = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("model", [CobaltStrikeConfig, OutflankConfig, MythicConfig])
@pytest.mark.parametrize("agent_id", ["", " \t\n", None, 123])
def test_invalid_agent_id(model, agent_id):
    data = {"url": "https://c2.local", "credential": {"username": "u", "password": "p"}, "agent_id": agent_id}
    if model is CobaltStrikeConfig:
        data["project"] = "assessment"
    with pytest.raises(ValidationError):
        model(**data)


def mythic_settings(tmp_path, monkeypatch, agent_id):
    # Keep tests independent of local credentials and environment overrides.
    for key in list(os.environ):
        if key.startswith("MYTHIC_SYNC_"):
            monkeypatch.delenv(key)
    from cli.mythic_connector import config

    original_dynaconf = config.Dynaconf

    def without_dotenv(**kwargs):
        return original_dynaconf(**{**kwargs, "load_dotenv": False})

    monkeypatch.setattr(config, "Dynaconf", without_dotenv)
    data = yaml.safe_load((SETTINGS_DIR / "settings_mythic.yaml").read_text())
    data["mythic"].pop("agent_id", None)
    if agent_id is not ...:
        data["mythic"]["agent_id"] = agent_id
    data["db"]["path"] = str(tmp_path / "state")
    path = tmp_path / "mythic.yaml"
    path.write_text(yaml.safe_dump(data))
    get_settings.cache_clear()
    return get_settings(str(path))


@pytest.mark.parametrize("agent_id", ["", " \t\n", None, 123])
def test_mythic_loader_rejects_invalid_id(tmp_path, monkeypatch, agent_id):
    with pytest.raises(SettingsValidationError):
        mythic_settings(tmp_path, monkeypatch, agent_id)


def test_runtime_mythic_constructor_default():
    assert RuntimeMythicConfig("https://mythic.local", UsernamePasswordCredential("u", "p")).agent_id == "mythic"


@pytest.mark.asyncio
@pytest.mark.parametrize("agent_id", [..., "mythic-initial"])
async def test_mythic_id_reaches_upload(tmp_path, monkeypatch, agent_id):
    cfg = mythic_settings(tmp_path, monkeypatch, agent_id)
    svc = SyncService(cfg)
    await svc.initialize_db()
    nemesis = MagicMock()
    nemesis.post_file.return_value = FileWithMetadataResponse(object_id=uuid4(), submission_id=uuid4())

    async def chunks(**kwargs):
        yield b"downloaded content"

    monkeypatch.setattr("cli.mythic_connector.handlers.mythic.download_file_chunked", chunks)
    meta = {
        "id": 1,
        "agent_file_id": "file-1",
        "filename_text": base64.b64encode(b"test.txt").decode(),
        "full_remote_path_text": base64.b64encode(b"C:/test.txt").decode(),
        "host": "workstation",
    }
    try:
        handler = FileHandler(MagicMock(), nemesis, svc.db, cfg)
        await handler.handle_file(meta)
        nemesis.post_file.assert_called_once()
        uploaded = nemesis.post_file.call_args.args[1]
        assert uploaded.agent_id == ("mythic" if agent_id is ... else agent_id)
        assert uploaded.path == "C:/test.txt"
        assert svc.db.get("filemetafile-1") == 1
    finally:
        svc.db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["cobaltstrike", "outflank-api", "outflank-directory"])
@pytest.mark.parametrize("custom", [False, True])
async def test_configured_collectors_upload_and_isolate_state(tmp_path, monkeypatch, mode, custom):
    framework = "cobaltstrike" if mode == "cobaltstrike" else "outflank"
    module = cs if framework == "cobaltstrike" else stage1
    data = yaml.safe_load((SETTINGS_DIR / f"settings_{framework}.yaml").read_text())
    data["cache_db_path"] = str(tmp_path / "cache")
    entry = data[framework][0]
    entry.pop("agent_id", None)
    if custom:
        entry["agent_id"] = f"{framework}-initial"
    if mode == "outflank-directory":
        downloads = tmp_path / "downloads"
        downloads.mkdir()
        (downloads / "1").write_bytes(b"downloaded content")
        entry["downloads_dir_path"] = str(downloads)
    # Two servers with the same agent ID and overlapping download IDs must run concurrently.
    data[framework].append({**entry, "url": "https://second.local:7443"})
    config_path = tmp_path / "settings.yaml"
    config_path.write_text(yaml.safe_dump(data))
    cfg = load_config(str(config_path))
    client = MagicMock()
    client.authenticate = AsyncMock(return_value=True)
    client.get_project_info = AsyncMock(return_value={"name": "assessment"})

    async def download_file(_id, path):
        Path(path).write_bytes(b"downloaded content")
        return True

    client.download_file = AsyncMock(side_effect=download_file)
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=client)
    monkeypatch.setattr(
        module,
        "CobaltStrikeClient" if framework == "cobaltstrike" else "OutflankC2Client",
        MagicMock(return_value=context),
    )
    cache = MagicMock()
    cache.initialize = AsyncMock()
    monkeypatch.setattr(module, "ImplantCache", MagicMock(return_value=cache))
    nemesis = MagicMock()
    nemesis.post_file.return_value = FileWithMetadataResponse(object_id=uuid4(), submission_id=uuid4())
    monkeypatch.setattr(module, "NemesisClient", MagicMock(return_value=nemesis))
    processors = []
    ready = asyncio.Event()
    download = SimpleNamespace(id="1", uid="1", bid="beacon", implant_uid="implant", path="C:/data", name="test.txt")
    host = SimpleNamespace(computer="host", hostname="host")

    def monitor_factory(_client, _cache, processor, _poll):
        processors.append(processor)

        async def start():
            if len(processors) == 2:
                ready.set()
            await asyncio.wait_for(ready.wait(), timeout=5)
            assert not processor.is_processed(download)
            process = (
                processor.process_cobaltstrike_download
                if framework == "cobaltstrike"
                else processor.process_outflank_download
            )
            await process(download, host)
            assert processor.is_processed(download)

        return SimpleNamespace(start=start)

    monkeypatch.setattr(
        module,
        "CobaltStrikeDownloadMonitor" if framework == "cobaltstrike" else "OutflankDownloadMonitor",
        monitor_factory,
    )
    setup = module.setup_cobaltstrike_monitor if framework == "cobaltstrike" else module.setup_outflank_monitor
    await asyncio.gather(*(setup(item, cfg, logging.getLogger(__name__)) for item in getattr(cfg, framework)))
    assert nemesis.post_file.call_count == 2
    expected_id = f"{framework}-initial" if custom else ("cobaltstrike" if framework == "cobaltstrike" else "stage1")
    assert all(call.args[1].agent_id == expected_id for call in nemesis.post_file.call_args_list)
    assert len(list((tmp_path / "cache").iterdir())) == 2
    # Setup closes the databases; both reopen with their own persisted records.
    for directory in (tmp_path / "cache").iterdir():
        with plyvel.DB(str(directory)) as db:
            assert db.get(b"download:1") is not None


@pytest.mark.asyncio
async def test_mythic_state_isolated_and_persistent(tmp_path, monkeypatch):
    cfg = mythic_settings(tmp_path, monkeypatch, ...)
    first = SyncService(cfg)
    await first.initialize_db()
    first.db.mset({"last_file_id": 100, "filemetafile-1": 1})
    cfg.mythic.url = "https://second.local:7443"
    second = SyncService(cfg)
    try:
        await second.initialize_db()
        assert second.db.get("last_file_id") is None
        assert second.db.get("filemetafile-1") is None
    finally:
        first.db.close()
        if second.db:
            second.db.close()
    cfg.mythic.url = "https://mythic.local:7443"
    restarted = SyncService(cfg)
    try:
        await restarted.initialize_db()
        assert restarted.db.get("last_file_id") == 100
    finally:
        restarted.db.close()


@pytest.mark.parametrize("component", ["framework", "url", "project", "agent_id"])
def test_state_identity_and_safe_paths(tmp_path, component):
    identity = {"framework": "mythic", "url": "https://c2.local", "project": "assessment", "agent_id": "../../agent"}
    original = collector_state_path(tmp_path, **identity)
    assert original.parent == tmp_path
    assert original == collector_state_path(tmp_path, **{**identity, "url": identity["url"] + "/"})
    assert original != collector_state_path(tmp_path, **{**identity, component: "different"})


def test_legacy_database_is_retained(tmp_path):
    root = tmp_path / "legacy"
    with plyvel.DB(str(root), create_if_missing=True) as db:
        db.put(b"download:1", b"legacy record")
    state = collector_state_path(root, "cobaltstrike", "https://c2.local", "assessment", "cobaltstrike")
    with plyvel.DB(str(state), create_if_missing=True) as db:
        assert db.get(b"download:1") is None
        db.put(b"download:1", b"instance record")
    with plyvel.DB(str(root)) as db:
        assert db.get(b"download:1") == b"legacy record"

"""Connector dry runs use previews and isolated temporary cache paths."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cli.cobaltstrike_connector.cobaltstrike_connector import run_cobaltstrike_connector
from cli.cobaltstrike_connector.download_processor import (
    CobaltStrikeDownloadProcessor,
)
from cli.cobaltstrike_connector.download_processor import (
    DownloadedFileInfo as CobaltDownloadedFileInfo,
)
from cli.config import Config
from cli.mythic_connector.config import (
    DatabaseConfig,
    MythicConfig,
    NetworkingConfig,
    Settings,
    UsernamePasswordCredential,
)
from cli.mythic_connector.config import (
    NemesisConfig as MythicNemesisConfig,
)
from cli.mythic_connector.sync import SyncService
from cli.nemesis_client import PreviewNemesisClient
from cli.stage1_connector.download_processor import (
    DownloadedFileInfo as OutflankDownloadedFileInfo,
)
from cli.stage1_connector.download_processor import (
    OutflankDownloadProcessor,
)
from cli.stage1_connector.stage1_connector import run_outflank_connector


def connector_config(cache_path):
    return Config(
        nemesis={"url": "https://nemesis.local", "credential": {"username": "n", "password": "n"}},
        outflank=[{"url": "https://outflank.local", "credential": {"username": "c2", "password": "pw"}}],
        cobaltstrike=[
            {
                "url": "https://cobalt.local",
                "credential": {"username": "c2", "password": "pw"},
                "project": "project",
            }
        ],
        conn_timeout_sec=2,
        validate_https_certs=True,
        cache_db_path=cache_path,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "runner,monitor_path",
    [
        (run_outflank_connector, "cli.stage1_connector.stage1_connector.setup_outflank_monitor"),
        (run_cobaltstrike_connector, "cli.cobaltstrike_connector.cobaltstrike_connector.setup_cobaltstrike_monitor"),
    ],
)
async def test_connector_dry_run_uses_preview_and_temporary_cache(tmp_path, runner, monitor_path):
    production_cache = tmp_path / "production" / "cache.db"
    config = connector_config(production_cache)
    observed = {}

    async def monitor(_c2, cfg, _logger, client):
        observed.update(cache_path=cfg.cache_db_path, client=client)

    with (
        patch(monitor_path, side_effect=monitor),
        patch(
            "cli.stage1_connector.stage1_connector.check_nemesis_availability", new_callable=AsyncMock
        ) as outflank_preflight,
        patch(
            "cli.cobaltstrike_connector.cobaltstrike_connector.check_nemesis_availability", new_callable=AsyncMock
        ) as cobalt_preflight,
    ):
        await runner(config, MagicMock(), dry_run=True)

    assert isinstance(observed["client"], PreviewNemesisClient)
    assert observed["cache_path"] != production_cache
    assert not Path(observed["cache_path"]).exists()
    assert config.cache_db_path == production_cache
    assert not production_cache.exists()
    outflank_preflight.assert_not_awaited()
    cobalt_preflight.assert_not_awaited()


@pytest.mark.asyncio
async def test_mythic_dry_run_uses_preview_and_temporary_cache(tmp_path):
    config = Settings(
        project="project",
        mythic=MythicConfig("http://mythic.local", UsernamePasswordCredential("user", "pw")),
        nemesis=MythicNemesisConfig("https://nemesis.local", UsernamePasswordCredential("user", "pw"), 10, 1000),
        db=DatabaseConfig(str(tmp_path / "production.db")),
        networking=NetworkingConfig(2, True),
    )
    service = SyncService(config)
    observed = {}

    async def run_without_connections():
        observed.update(cache_path=config.db.path, client=service.nemesis)

    service._run_with_nemesis = run_without_connections
    await service.run(dry_run=True)

    assert isinstance(observed["client"], PreviewNemesisClient)
    assert observed["cache_path"] != config.db.path
    assert not Path(observed["cache_path"]).exists()
    assert config.db.path == str(tmp_path / "production.db")
    assert not (tmp_path / "production.db").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("connector", ["outflank", "cobaltstrike"])
async def test_c2_processor_preview_is_successful_without_remote_ids(tmp_path, caplog, connector):
    import logging

    caplog.set_level(logging.INFO)
    source_file = tmp_path / "download.bin"
    source_file.write_bytes(b"sample")
    preview = PreviewNemesisClient()

    if connector == "outflank":
        processor = OutflankDownloadProcessor(tmp_path / "outflank.db", preview, "project", outflank=MagicMock())
        download = SimpleNamespace(uid="download-1", implant_uid="implant-1", path="C:/download.bin")
        processor._get_downloaded_file = AsyncMock(return_value=OutflankDownloadedFileInfo(source_file, False, True))
        process = processor.process_outflank_download(download, SimpleNamespace(hostname="host-a"))
        key = b"download:download-1"
    else:
        processor = CobaltStrikeDownloadProcessor(tmp_path / "cobalt.db", preview, "project", cobalt_strike=MagicMock())
        download = SimpleNamespace(id="download-2", bid="beacon-1", path="C:/", name="download.bin")
        processor._get_downloaded_file = AsyncMock(return_value=CobaltDownloadedFileInfo(source_file, False, True))
        process = processor.process_cobaltstrike_download(download, SimpleNamespace(computer="host-b"))
        key = b"download:download-2"

    try:
        await process
        cached = json.loads(processor.db.get(key))
        assert cached["success"] is True
        assert cached["object_id"] is None
        assert cached["submission_id"] is None
        assert "WOULD UPLOAD" in caplog.text
        assert "Successfully uploaded" not in caplog.text
        assert "Error in process_download" not in caplog.text
    finally:
        processor.close()

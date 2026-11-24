"""C2 download IDs must never escape local directories or temp file prefixes (audit #156)."""

import os
import tempfile
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from cli.c2_download_state import PermanentDownloadError
from cli.c2_ids import is_safe_c2_id, safe_child_path
from cli.cobaltstrike_connector.cobaltstrike_client import Download as CSDownload
from cli.cobaltstrike_connector.download_processor import CobaltStrikeDownloadProcessor
from cli.nemesis_client import PreviewUploadResult
from cli.stage1_connector.download_processor import OutflankDownloadProcessor
from cli.stage1_connector.outflankc2_client import Download as OutflankDownload

UNSAFE_IDS = ["..", ".", "../etc/passwd", "/etc/passwd", "a/b", "a\\b", "", "x\x00y", "evil\n", None, 5]


def outflank_download(uid):
    return OutflankDownload(
        uid=uid,
        timestamp=datetime.now(),
        path="C:/Users/bob/secret.txt",
        name="secret.txt",
        size=4,
        progress=100.0,
        task_uid="task-1",
        implant_uid="implant-1",
        implant_username="bob",
        implant_hostname="ws01",
    )


def cs_download(download_id):
    return CSDownload(
        id=download_id, bid="12345", name="secret.txt", path="C:/Users/bob", size=4, timestamp=datetime.now()
    )


def preview_client():
    client = MagicMock()
    client.post_file = AsyncMock(return_value=PreviewUploadResult(size_bytes=4, sha256="0" * 64))
    return client


# --- helpers ---


@pytest.mark.parametrize("value", ["abc", "0a1b-2c3d", "file_1.bin", "A.B-C_D", "a" * 128])
def test_safe_ids_accepted(value):
    assert is_safe_c2_id(value)


@pytest.mark.parametrize("value", UNSAFE_IDS + ["a" * 129])
def test_unsafe_ids_rejected(value):
    assert not is_safe_c2_id(value)


def test_safe_child_path_inside_dir(tmp_path):
    assert safe_child_path(tmp_path, "abc") == tmp_path / "abc"


@pytest.mark.parametrize("value", ["..", "../x", "/etc/passwd"])
def test_safe_child_path_rejects_traversal(tmp_path, value):
    assert safe_child_path(tmp_path, value) is None


def test_safe_child_path_rejects_symlink_escape(tmp_path):
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    (downloads / "link").symlink_to(outside)
    assert safe_child_path(downloads, "link") is None


# --- Outflank processor ---


@pytest.fixture
def outflank_dir_processor(tmp_path):
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    client = preview_client()
    processor = OutflankDownloadProcessor(tmp_path / "db", client, "proj", outflank_downloads_dir_path=downloads)
    try:
        yield processor, client, downloads
    finally:
        processor.close()


@pytest.mark.asyncio
async def test_outflank_local_file_with_valid_uid_is_uploaded(outflank_dir_processor):
    processor, client, downloads = outflank_dir_processor
    (downloads / "abc-123").write_bytes(b"data")
    download = outflank_download("abc-123")

    await processor.process_outflank_download(download, SimpleNamespace(hostname="ws01", uid="implant-1"))

    client.post_file.assert_awaited_once()
    assert client.post_file.await_args.args[0] == str(downloads / "abc-123")
    assert processor.is_processed(download)
    assert (downloads / "abc-123").exists()  # local mode never deletes the source file


@pytest.mark.asyncio
@pytest.mark.parametrize("uid", ["../outside.txt", "/etc/passwd", ".."])
async def test_outflank_traversal_uid_is_skipped_and_marked(outflank_dir_processor, tmp_path, uid):
    processor, client, _ = outflank_dir_processor
    (tmp_path / "outside.txt").write_text("secret")
    download = outflank_download(uid)

    await processor.process_outflank_download(download, SimpleNamespace(hostname="ws01", uid="implant-1"))

    client.post_file.assert_not_awaited()
    assert processor.is_processed(download)  # logged + skipped once, not retried every poll


@pytest.mark.asyncio
async def test_outflank_symlink_escape_is_refused(outflank_dir_processor, tmp_path):
    processor, client, downloads = outflank_dir_processor
    (tmp_path / "outside.txt").write_text("secret")
    (downloads / "abc").symlink_to(tmp_path / "outside.txt")

    await processor.process_outflank_download(
        outflank_download("abc"), SimpleNamespace(hostname="ws01", uid="implant-1")
    )

    client.post_file.assert_not_awaited()


@pytest.mark.asyncio
async def test_outflank_missing_local_file_is_retried_later(outflank_dir_processor):
    processor, client, _ = outflank_dir_processor
    download = outflank_download("missing")
    await processor.process_outflank_download(download, SimpleNamespace(hostname="ws01", uid="implant-1"))
    client.post_file.assert_not_awaited()
    # The file may still be on its way into the downloads directory: retry instead of giving up.
    assert not processor.is_processed(download)
    assert processor.state.retry_state("missing")["attempts"] == 1
    assert not processor.is_due(download)


@pytest.mark.asyncio
async def test_outflank_api_mode_rejects_unsafe_uid_before_mkstemp(tmp_path, monkeypatch):
    outflank = MagicMock()
    outflank.download_file = AsyncMock(return_value=True)
    mkstemp = MagicMock(side_effect=AssertionError("mkstemp must not be called"))
    monkeypatch.setattr(tempfile, "mkstemp", mkstemp)
    processor = OutflankDownloadProcessor(tmp_path / "db", preview_client(), "proj", outflank=outflank)
    try:
        with pytest.raises(PermanentDownloadError):
            await processor._download_from_c2(outflank_download("../../etc/cron.d/x"))
        outflank.download_file.assert_not_awaited()
    finally:
        processor.close()


@pytest.mark.asyncio
async def test_outflank_api_mode_valid_uid_uses_temp_dir(tmp_path):
    seen = {}

    async def fake_download(uid, dest, **_kwargs):
        seen["dest"] = dest
        Path(dest).write_bytes(b"data")
        return True

    outflank = MagicMock()
    outflank.download_file = AsyncMock(side_effect=fake_download)
    client = preview_client()
    processor = OutflankDownloadProcessor(tmp_path / "db", client, "proj", outflank=outflank)
    try:
        await processor.process_outflank_download(
            outflank_download("abc-123"), SimpleNamespace(hostname="ws01", uid="implant-1")
        )
        assert Path(seen["dest"]).parent == Path(tempfile.gettempdir())
        assert os.path.basename(seen["dest"]).startswith("nemesis_abc-123_")
        client.post_file.assert_awaited_once()
        assert not Path(seen["dest"]).exists()  # temp file cleaned up
    finally:
        processor.close()


# --- Cobalt Strike processor ---


@pytest.fixture
def cs_processor(tmp_path):
    cobalt_strike = MagicMock()
    client = preview_client()
    processor = CobaltStrikeDownloadProcessor(tmp_path / "db", client, "proj", cobalt_strike=cobalt_strike)
    try:
        yield processor, client, cobalt_strike
    finally:
        processor.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("download_id", ["../../tmp/evil", "/abs", "..", "a/b"])
async def test_cobaltstrike_unsafe_id_is_skipped(cs_processor, monkeypatch, download_id):
    processor, client, cobalt_strike = cs_processor
    cobalt_strike.download_file = AsyncMock(return_value=True)
    monkeypatch.setattr(tempfile, "mkstemp", MagicMock(side_effect=AssertionError("mkstemp must not be called")))
    download = cs_download(download_id)

    await processor.process_cobaltstrike_download(download, SimpleNamespace(computer="ws01", bid="12345"))

    cobalt_strike.download_file.assert_not_awaited()
    client.post_file.assert_not_awaited()
    assert processor.is_processed(download)


@pytest.mark.asyncio
async def test_cobaltstrike_direct_download_rejects_unsafe_id(cs_processor):
    processor, _, cobalt_strike = cs_processor
    cobalt_strike.download_file = AsyncMock(return_value=True)
    with pytest.raises(PermanentDownloadError):
        await processor._download_from_c2(cs_download("../x"))
    cobalt_strike.download_file.assert_not_awaited()


@pytest.mark.asyncio
async def test_cobaltstrike_valid_id_is_downloaded_and_uploaded(cs_processor):
    processor, client, cobalt_strike = cs_processor
    seen = {}

    async def fake_download(download_id, dest, **_kwargs):
        seen["dest"] = dest
        Path(dest).write_bytes(b"data")
        return True

    cobalt_strike.download_file = AsyncMock(side_effect=fake_download)
    download = cs_download("9f8e7d")

    await processor.process_cobaltstrike_download(download, SimpleNamespace(computer="ws01", bid="12345"))

    assert os.path.basename(seen["dest"]).startswith("nemesis_9f8e7d_")
    client.post_file.assert_awaited_once()
    assert processor.is_processed(download)
    assert not Path(seen["dest"]).exists()


# --- settings_outflank.yaml sample (audit #157 field-name fix) ---


def test_outflank_sample_commented_field_is_valid_when_uncommented(tmp_path):
    import yaml
    from cli.config import load_config

    sample = (Path(__file__).resolve().parent.parent / "settings_outflank.yaml").read_text()
    assert "outflank_upload_path" not in sample
    uncommented = sample.replace("    # downloads_dir_path:", "    downloads_dir_path:")
    assert uncommented != sample
    path = tmp_path / "settings.yaml"
    path.write_text(uncommented)
    cfg = load_config(str(path))
    assert cfg.outflank[0].downloads_dir_path == Path(yaml.safe_load(uncommented)["outflank"][0]["downloads_dir_path"])

"""Tests for web_api.container_monitor: config parsing and source-file handling after processing.

LargeContainerProcessor is mocked; no Dapr/S3/PostgreSQL calls are made.
"""

from queue import Queue
from unittest.mock import MagicMock, patch

import pytest
from web_api import container_monitor
from web_api.container_monitor import (
    ContainerFileHandler,
    ContainerMonitor,
    parse_config_file,
)
from web_api.large_containers import ContainerExtractionError, ContainerMetadataError

# --- parse_config_file -------------------------------------------------------------------


def _write_config(tmp_path, text):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(text)
    return cfg


def test_parse_config_defaults_without_config(tmp_path):
    meta = parse_config_file(None, tmp_path / "disk.dd")
    assert meta == {"agent_id": "mounted_container", "project": "unknown", "source": "disk", "file_filters": None}


def test_parse_config_coerces_scalar_types(tmp_path):
    cfg = _write_config(tmp_path, "metadata:\n  agent_id: 42\n  project: 2024\n  source: host1\n")
    meta = parse_config_file(cfg, tmp_path / "disk.dd")
    assert meta["agent_id"] == "42"
    assert meta["project"] == "2024"
    assert meta["source"] == "host1"


def test_parse_config_sets_default_pattern_type(tmp_path):
    cfg = _write_config(tmp_path, "file_filters:\n  include:\n    - foo\n")
    meta = parse_config_file(cfg, tmp_path / "disk.dd")
    assert meta["file_filters"] == {"include": ["foo"], "pattern_type": "regex"}


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("metadata:\n  project: [a, b]\n", "project"),
        ("metadata:\n  project: yes\n", "boolean"),
        ("metadata:\n  agent_id:\n", "agent_id"),
        ("metadata:\n  project: " + "x" * 300 + "\n", "too long"),
        ("metadata: just-a-string\n", "mapping"),
        ("file_filters: [a]\n", "mapping"),
        ("- a\n- b\n", "mapping"),
        ("metadata: {unclosed\n", "Error parsing"),
    ],
)
def test_parse_config_rejects_invalid(tmp_path, text, match):
    cfg = _write_config(tmp_path, text)
    with pytest.raises(ContainerMetadataError, match=match):
        parse_config_file(cfg, tmp_path / "disk.dd")


# --- ContainerFileHandler ----------------------------------------------------------------


def test_handler_ignores_failed_and_completed_folders(tmp_path):
    handler = ContainerFileHandler(Queue(), tmp_path)
    assert handler._should_ignore_path(tmp_path / "failed" / "disk.dd")
    assert handler._should_ignore_path(tmp_path / "completed" / "disk.dd")
    assert not handler._should_ignore_path(tmp_path / "case" / "disk.dd")


def test_handler_does_not_queue_container_with_invalid_config(tmp_path):
    (tmp_path / "config.yaml").write_text("metadata:\n  project: [bad]\n")
    disk = tmp_path / "disk.dd"
    disk.write_bytes(b"\x00" * 10)
    queue = Queue()
    handler = ContainerFileHandler(queue, tmp_path)
    with patch("web_api.container_monitor.time.sleep"):
        handler._handle_file(disk)
    assert queue.empty()


def test_handler_queues_container_with_valid_config(tmp_path):
    (tmp_path / "config.yaml").write_text("metadata:\n  project: 2024\n")
    disk = tmp_path / "disk.dd"
    disk.write_bytes(b"\x00" * 10)
    queue = Queue()
    handler = ContainerFileHandler(queue, tmp_path)
    with patch("web_api.container_monitor.time.sleep"):
        handler._handle_file(disk)
    item = queue.get_nowait()
    assert item["metadata"]["project"] == "2024"


# --- ContainerMonitor processing ---------------------------------------------------------


@pytest.fixture
def monitor(tmp_path):
    mon = ContainerMonitor.__new__(ContainerMonitor)
    mon.mounted_path = tmp_path
    mon.completed_path = tmp_path / "completed"
    mon.failed_path = tmp_path / "failed"
    mon.container_queue = Queue()
    mon.processor = MagicMock()
    mon.observer = None
    mon.processing_thread = None
    mon.running = True
    return mon


@pytest.fixture
def disk(tmp_path):
    p = tmp_path / "case" / "disk.dd"
    p.parent.mkdir()
    p.write_bytes(b"evidence")
    return p


def _run_once(monitor, disk, outcome, cleanup=True):
    """Queue one container and run the processing loop until it has been handled."""

    def process(container_id, file_path, metadata):
        monitor.running = False
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monitor.processor.process_container_from_path.side_effect = process
    monitor.container_queue.put({"file_path": disk, "metadata": {"agent_id": "a", "project": "p"}})
    with (
        patch.object(container_monitor, "wait_for_file_stability", return_value=True),
        patch.object(container_monitor, "CLEANUP_CONTAINERS_AFTER_PROCESSING", cleanup),
    ):
        monitor._process_containers()


def test_successful_extraction_deletes_source_when_cleanup_enabled(monitor, disk):
    _run_once(monitor, disk, {"success": True, "processed_files": 3})
    assert not disk.exists()
    assert not (monitor.failed_path / "disk.dd").exists()


def test_successful_extraction_moves_to_completed_when_cleanup_disabled(monitor, disk):
    _run_once(monitor, disk, {"success": True, "processed_files": 3}, cleanup=False)
    assert not disk.exists()
    assert (monitor.completed_path / "disk.dd").read_bytes() == b"evidence"


def test_zero_files_extracted_keeps_source_in_failed_folder(monitor, disk):
    _run_once(monitor, disk, {"success": False, "processed_files": 0, "error_message": "No files"})
    assert (monitor.failed_path / "disk.dd").read_bytes() == b"evidence"


def test_result_without_success_flag_is_not_deleted(monitor, disk):
    _run_once(monitor, disk, {"processed_files": 5})
    assert (monitor.failed_path / "disk.dd").exists()


def test_extraction_error_keeps_source_in_failed_folder(monitor, disk):
    _run_once(monitor, disk, ContainerExtractionError("no filesystem"))
    assert (monitor.failed_path / "disk.dd").read_bytes() == b"evidence"


def test_unexpected_error_leaves_source_in_place(monitor, disk):
    _run_once(monitor, disk, RuntimeError("db down"))
    assert disk.read_bytes() == b"evidence"


def test_failed_folder_name_conflict_gets_counter(monitor, disk):
    monitor.failed_path.mkdir()
    (monitor.failed_path / "disk.dd").write_bytes(b"older")
    _run_once(monitor, disk, {"success": False})
    assert (monitor.failed_path / "disk.dd").read_bytes() == b"older"
    assert (monitor.failed_path / "disk_1.dd").read_bytes() == b"evidence"


def test_scan_existing_skips_failed_and_completed(monitor, tmp_path):
    for folder in ("failed", "completed", "new"):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "disk.dd").write_bytes(b"x")
    monitor._scan_existing_files()
    queued = [monitor.container_queue.get_nowait()["file_path"] for _ in range(monitor.container_queue.qsize())]
    assert queued == [tmp_path / "new" / "disk.dd"]


def test_scan_existing_skips_invalid_config(monitor, tmp_path):
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "config.yaml").write_text("metadata:\n  project: [x]\n")
    (tmp_path / "bad" / "disk.dd").write_bytes(b"x")
    monitor._scan_existing_files()
    assert monitor.container_queue.empty()


def test_get_status_includes_failed_path(monitor):
    assert monitor.get_status()["failed_path"] == str(monitor.failed_path)

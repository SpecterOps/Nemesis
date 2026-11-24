"""Folder monitor: files are submitted once, only after they are completely written (Linux and macOS)."""

import logging
import os
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cli import monitor
from cli.monitor import FileStabilityTracker, NewFileHandler
from watchdog.events import (
    DirCreatedEvent,
    FileClosedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
)


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds: float):
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def submit():
    with patch.object(monitor, "submit_files", return_value=True) as mock:
        yield mock


@pytest.fixture
def handler(clock, submit):
    return NewFileHandler(
        "nemesis:7443",
        "user",
        "pass",
        "proj",
        "agent",
        logging.getLogger("test-monitor"),
        container=False,
        source="host://box",
        verify_ssl=False,
        quiet_period=2.0,
        clock=clock,
    )


def drain(handler: NewFileHandler) -> list[Path]:
    """Run one scheduler pass and submit everything it made ready, synchronously."""
    ready = handler.process_ready()
    while not handler._uploads.empty():
        path = handler._uploads.get_nowait()
        handler._uploads.task_done()
        handler.submit_path(path)
    return ready


def write(path: Path, data: bytes, mtime_ns: int | None = None):
    path.write_bytes(data)
    if mtime_ns is not None:
        os.utime(path, ns=(mtime_ns, mtime_ns))


def submitted_paths(submit) -> list[Path]:
    return [call.kwargs["paths"][0] for call in submit.call_args_list]


def test_growing_file_not_submitted_until_stable(tmp_path, handler, clock, submit):
    f = tmp_path / "loot.bin"
    write(f, b"a", 1_000)
    handler.on_created(FileCreatedEvent(str(f)))
    clock.advance(1.5)
    write(f, b"ab", 2_000)  # still growing; scheduler notices the size change
    assert drain(handler) == []
    clock.advance(1.9)
    assert drain(handler) == []
    clock.advance(0.2)
    assert drain(handler) == [f]
    assert submitted_paths(submit) == [f]
    kwargs = submit.call_args.kwargs
    assert kwargs["recursive"] is False and kwargs["workers"] == 1 and kwargs["verify_ssl"] is False
    assert kwargs["source"] == "host://box" and kwargs["project"] == "proj" and kwargs["agent_id"] == "agent"


def test_closed_event_fast_path(tmp_path, handler, submit):
    f = tmp_path / "done.txt"
    write(f, b"complete")
    handler.on_created(FileCreatedEvent(str(f)))
    handler.on_closed(FileClosedEvent(str(f)))
    assert drain(handler) == [f]
    assert submit.call_count == 1


def test_closed_then_changed_waits_again(tmp_path, handler, clock, submit):
    f = tmp_path / "reopened.txt"
    write(f, b"a", 1_000)
    handler.on_closed(FileClosedEvent(str(f)))
    write(f, b"ab", 2_000)  # reopened and appended before the scheduler ran
    assert drain(handler) == []
    clock.advance(2.1)
    assert drain(handler) == [f]


@pytest.mark.parametrize(
    "name",
    ["x.tmp", "x.part", "x.partial", "x.crdownload", "x.download", "~$doc.docx", ".~lock.x#", ".x.swp", ".DS_Store"]
    + ["._photo.jpg", "report.docx"],
)
def test_every_file_name_is_submitted(tmp_path, handler, clock, submit, name):
    """No name is filtered: temp, partial, lock and metadata files are uploaded once stable, like any other file."""
    f = tmp_path / name
    write(f, b"content")
    handler.on_created(FileCreatedEvent(str(f)))
    clock.advance(2.1)
    assert drain(handler) == [f]
    assert submitted_paths(submit) == [f]


def test_temp_file_stable_before_rename_is_submitted_too(tmp_path, handler, clock, submit):
    partial = tmp_path / "file.zip.part"
    final = tmp_path / "file.zip"
    write(partial, b"zipdata")
    handler.on_created(FileCreatedEvent(str(partial)))
    clock.advance(2.1)
    assert drain(handler) == [partial]
    partial.rename(final)
    handler.on_moved(FileMovedEvent(str(partial), str(final)))
    clock.advance(2.1)
    assert drain(handler) == [final]
    assert submitted_paths(submit) == [partial, final]


def test_rename_into_place_submits_final_name_once(tmp_path, handler, clock, submit):
    partial = tmp_path / "file.zip.part"
    final = tmp_path / "file.zip"
    write(partial, b"zipdata")
    handler.on_created(FileCreatedEvent(str(partial)))
    handler.on_modified(FileModifiedEvent(str(partial)))
    partial.rename(final)
    handler.on_moved(FileMovedEvent(str(partial), str(final)))
    clock.advance(2.1)
    assert drain(handler) == [final]
    handler.on_modified(FileModifiedEvent(str(final)))  # trailing event for the same content
    clock.advance(5)
    assert drain(handler) == []
    assert submitted_paths(submit) == [final]


def test_burst_of_modified_events_single_upload(tmp_path, handler, clock, submit):
    f = tmp_path / "burst.log"
    write(f, b"x" * 10, 5_000)
    for _ in range(50):
        handler.on_modified(FileModifiedEvent(str(f)))
        clock.advance(0.01)
    assert handler.tracker.pending_count() == 1
    clock.advance(2.1)
    drain(handler)
    handler.on_modified(FileModifiedEvent(str(f)))
    handler.on_closed(FileClosedEvent(str(f)))
    clock.advance(3)
    drain(handler)
    assert submit.call_count == 1


def test_rewrite_after_upload_submits_again(tmp_path, handler, clock, submit):
    f = tmp_path / "creds.txt"
    write(f, b"v1", 1_000)
    handler.on_created(FileCreatedEvent(str(f)))
    clock.advance(2.1)
    drain(handler)
    write(f, b"version2", 9_000)
    handler.on_modified(FileModifiedEvent(str(f)))
    clock.advance(2.1)
    drain(handler)
    assert submitted_paths(submit) == [f, f]


def test_file_deleted_before_ready(tmp_path, handler, clock, submit):
    f = tmp_path / "gone.txt"
    write(f, b"bye")
    handler.on_created(FileCreatedEvent(str(f)))
    f.unlink()
    clock.advance(2.1)
    assert drain(handler) == []
    handler.on_deleted(FileDeletedEvent(str(f)))
    handler.on_modified(FileModifiedEvent(str(f)))  # stale event for a missing file
    assert handler.tracker.pending_count() == 0
    submit.assert_not_called()


def test_submit_error_logged_and_monitor_continues(tmp_path, handler, clock, submit, caplog):
    bad = tmp_path / "bad.txt"
    good = tmp_path / "good.txt"
    write(bad, b"bad")
    write(good, b"good")
    submit.side_effect = [RuntimeError("nemesis down"), True]
    handler.on_created(FileCreatedEvent(str(bad)))
    handler.on_created(FileCreatedEvent(str(good)))
    clock.advance(2.1)
    with caplog.at_level(logging.ERROR, logger="test-monitor"):
        drain(handler)
    assert "nemesis down" in caplog.text
    assert submit.call_count == 2


def test_failed_submit_is_retried_on_next_event(tmp_path, handler, clock, submit):
    f = tmp_path / "retry.txt"
    write(f, b"data")
    submit.side_effect = [False, True]
    handler.on_created(FileCreatedEvent(str(f)))
    clock.advance(2.1)
    drain(handler)
    handler.on_modified(FileModifiedEvent(str(f)))  # same content, but the first upload failed
    clock.advance(2.1)
    drain(handler)
    assert submit.call_count == 2


def test_fsevents_style_modified_only(tmp_path, handler, clock, submit):
    """macOS FSEvents may coalesce a create+write into a single modified event and never send a close."""
    f = tmp_path / "mac.bin"
    write(f, b"content")
    handler.on_modified(FileModifiedEvent(str(f)))
    clock.advance(2.1)
    assert drain(handler) == [f]


def test_directory_events_ignored(tmp_path, handler, clock, submit):
    d = tmp_path / "sub"
    d.mkdir()
    handler.on_created(DirCreatedEvent(str(d)))
    clock.advance(5)
    assert drain(handler) == []


def test_unreadable_file_waits(tmp_path, clock):
    f = tmp_path / "locked.bin"
    write(f, b"x")
    tracker = FileStabilityTracker(quiet_period=1, clock=clock)
    tracker.touch(f)
    clock.advance(2)
    with patch.object(monitor, "_is_readable", return_value=False):
        assert tracker.poll() == []
    assert tracker.poll() == [f]


def test_scheduler_and_worker_threads_submit_and_stop(tmp_path, submit):
    h = NewFileHandler("h", "u", "p", "proj", "agent", logging.getLogger("t"), quiet_period=0.05, poll_interval=0.01)
    f = tmp_path / "threaded.txt"
    write(f, b"t")
    h.start()
    try:
        h.on_created(FileCreatedEvent(str(f)))
        deadline = time.monotonic() + 5
        while submit.call_count == 0 and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        h.stop(timeout=5)
    assert submitted_paths(submit) == [f]
    assert not any(t.is_alive() for t in threading.enumerate() if t.name.startswith("nemesis-monitor"))


def test_real_observer_waits_for_slow_writer(tmp_path, submit):
    """End to end with the platform's real watchdog observer (inotify, FSEvents or kqueue)."""
    from watchdog.observers import Observer

    h = NewFileHandler("h", "u", "p", "proj", "agent", logging.getLogger("t"), quiet_period=0.3, poll_interval=0.05)
    observer = Observer()
    observer.schedule(h, str(tmp_path), recursive=True)
    h.start()
    observer.start()
    f = tmp_path / "slow.bin"
    try:
        with open(f, "wb") as out:
            for _ in range(5):
                out.write(b"x" * 1024)
                out.flush()
                os.fsync(out.fileno())
                time.sleep(0.1)
                assert submit.call_count == 0
        deadline = time.monotonic() + 10
        while submit.call_count == 0 and time.monotonic() < deadline:
            time.sleep(0.05)
        time.sleep(0.5)  # trailing events must not cause a duplicate submission
    finally:
        observer.stop()
        observer.join(5)
        h.stop(timeout=5)
    assert submitted_paths(submit) == [f]
    assert f.stat().st_size == 5 * 1024


def test_monitor_main_rejects_missing_path(tmp_path):
    with patch.object(monitor, "setup_logging", return_value=MagicMock()), pytest.raises(SystemExit):
        monitor.monitor_main(str(tmp_path / "nope"), False, "h", "u", "p", "proj", "a", True, 1, False)

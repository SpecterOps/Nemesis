# monitor.py
"""Watch a folder and submit files to Nemesis once they are completely written.

Completion is detected portably: every filesystem event only "touches" a path, and a background scheduler submits
the file once its size and mtime have stayed unchanged for a quiet period and it can be opened for reading. On Linux
an inotify close-after-write event (``on_closed``) short-circuits the wait. macOS (FSEvents) and kqueue deliver no
close events and may coalesce or drop created/modified events, so the stability check is the primary mechanism.
"""

import logging
import os
import queue
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import click
from cli.log import setup_logging
from cli.submit import UNKNOWN_SOURCE_WARNING, submit_files
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

DEFAULT_QUIET_PERIOD_SEC = 2.0
DEFAULT_POLL_INTERVAL_SEC = 0.5

Signature = tuple[int, int]  # (size, mtime_ns)


def _signature(path: Path) -> Signature | None:
    """Return (size, mtime_ns) for a regular file, or None if it is missing or not a regular file."""
    try:
        st = path.stat()
    except OSError:
        return None
    if not os.path.isfile(path):
        return None
    return (st.st_size, st.st_mtime_ns)


def _is_readable(path: Path) -> bool:
    try:
        with open(path, "rb"):
            return True
    except OSError:
        return False


@dataclass
class _Pending:
    signature: Signature
    last_change: float
    closed: bool = False


class FileStabilityTracker:
    """Debounces filesystem events per path and reports files that are ready to submit.

    Thread-safe: watchdog's event thread calls ``touch``/``mark_closed`` while the scheduler thread calls ``poll``.
    """

    def __init__(self, quiet_period: float = DEFAULT_QUIET_PERIOD_SEC, clock: Callable[[], float] = time.monotonic):
        self.quiet_period = quiet_period
        self.clock = clock
        self._pending: dict[Path, _Pending] = {}
        # Signature each path had when it was last handed out, so trailing events for the same write burst are
        # ignored while a later rewrite (new size or mtime) is submitted again.
        self._submitted: dict[Path, Signature] = {}
        self._lock = threading.Lock()

    def touch(self, path: Path, closed: bool = False) -> None:
        """Record activity on ``path``; ``closed`` marks a close-after-write event (Linux inotify only)."""
        signature = _signature(path)
        with self._lock:
            if signature is None:
                self._pending.pop(path, None)
                return
            entry = self._pending.get(path)
            if entry is None:
                if self._submitted.get(path) == signature:
                    return
                self._pending[path] = _Pending(signature, self.clock(), closed)
                return
            if entry.signature != signature:
                entry.signature = signature
                entry.last_change = self.clock()
                entry.closed = closed
            elif closed:
                entry.closed = True

    def forget(self, path: Path) -> None:
        """Drop a path that was deleted or moved away."""
        with self._lock:
            self._pending.pop(path, None)
            self._submitted.pop(path, None)

    def submission_failed(self, path: Path) -> None:
        """Allow a later event for ``path`` to submit it again after a failed upload."""
        with self._lock:
            self._submitted.pop(path, None)

    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    def poll(self) -> list[Path]:
        """Return paths that are complete, removing them from the pending set."""
        now = self.clock()
        with self._lock:
            candidates = list(self._pending.items())
        ready: list[Path] = []
        for path, entry in candidates:
            signature = _signature(path)
            with self._lock:
                if self._pending.get(path) is not entry:
                    continue
                if signature is None:
                    del self._pending[path]
                    continue
                if signature != entry.signature:
                    entry.signature = signature
                    entry.last_change = now
                    entry.closed = False
                    continue
                if not entry.closed and now - entry.last_change < self.quiet_period:
                    continue
            if not _is_readable(path):
                continue
            with self._lock:
                if self._pending.get(path) is entry and entry.signature == signature:
                    del self._pending[path]
                    self._submitted[path] = signature
                    ready.append(path)
        return ready


class NewFileHandler(FileSystemEventHandler):
    """Feeds watchdog events into a FileStabilityTracker and submits files once they are complete."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        project: str,
        agent_id: str,
        logger: logging.Logger,
        container: bool = False,
        source: str | None = None,
        verify_ssl: bool = True,
        ca_file: str | None = None,
        *,
        quiet_period: float = DEFAULT_QUIET_PERIOD_SEC,
        poll_interval: float = DEFAULT_POLL_INTERVAL_SEC,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.project = project
        self.agent_id = agent_id
        self.logger = logger
        self.container = container
        self.source = source
        self.verify_ssl = verify_ssl
        self.ca_file = ca_file
        self.poll_interval = poll_interval
        self.tracker = FileStabilityTracker(quiet_period=quiet_period, clock=clock)
        self._uploads: queue.Queue[Path | None] = queue.Queue()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    # --- watchdog callbacks: never block here --------------------------------------------------------------

    def _touch(self, raw_path: bytes | str, closed: bool = False) -> None:
        path = Path(os.fsdecode(raw_path))
        self.tracker.touch(path, closed=closed)

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.logger.info(f"New file detected: {os.fsdecode(event.src_path)}")
            self._touch(event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._touch(event.src_path)

    def on_closed(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._touch(event.src_path, closed=True)

    def on_moved(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self.tracker.forget(Path(os.fsdecode(event.src_path)))
        if event.dest_path:
            self.logger.info(f"File moved into directory: {os.fsdecode(event.dest_path)}")
            self._touch(event.dest_path)

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.tracker.forget(Path(os.fsdecode(event.src_path)))

    # --- scheduler and upload worker ------------------------------------------------------------------------

    def process_ready(self) -> list[Path]:
        """Move complete files to the upload queue; returns them (used by the scheduler and tests)."""
        ready = self.tracker.poll()
        for path in ready:
            self._uploads.put(path)
        return ready

    def submit_path(self, file_path: Path) -> bool:
        """Submit one complete file; errors are logged and never propagate."""
        self.logger.info(f"Submitting completed file: {file_path}")
        try:
            ok = submit_files(
                paths=[file_path],
                host=self.host,
                recursive=False,  # Single file
                workers=1,
                username=self.username,
                password=self.password,
                project=self.project,
                agent_id=self.agent_id,
                container=self.container,
                source=self.source,
                verify_ssl=self.verify_ssl,
                ca_file=self.ca_file,
            )
        except Exception as e:
            self.logger.error(f"Failed to submit file {file_path}: {e}")
            ok = False
        else:
            if ok is False:
                self.logger.error(f"Failed to submit file {file_path}")
        if ok is False:
            self.tracker.submission_failed(file_path)
            return False
        return True

    def _scheduler_loop(self) -> None:
        while not self._stop.wait(self.poll_interval):
            try:
                self.process_ready()
            except Exception as e:  # keep monitoring even if one check fails
                self.logger.error(f"Error checking pending files: {e}")

    def _upload_loop(self) -> None:
        while True:
            path = self._uploads.get()
            try:
                if path is None:
                    return
                self.submit_path(path)
            finally:
                self._uploads.task_done()

    def start(self) -> None:
        self._stop.clear()
        self._threads = [
            threading.Thread(target=self._scheduler_loop, name="nemesis-monitor-scheduler", daemon=True),
            threading.Thread(target=self._upload_loop, name="nemesis-monitor-upload", daemon=True),
        ]
        for thread in self._threads:
            thread.start()

    def stop(self, timeout: float | None = None) -> None:
        """Stop scheduling; uploads already queued finish before the worker exits."""
        self._stop.set()
        self._uploads.put(None)
        for thread in self._threads:
            thread.join(timeout)
        self._threads = []


def monitor_main(
    path: str,
    debug: bool,
    host: str,
    username: str,
    password: str,
    project: str,
    agent_id: str,
    only_monitor: bool,
    workers: int,
    container: bool,
    source: str | None = None,
    verify_ssl: bool = True,
    ca_file: str | None = None,
):
    """Monitor a folder for new files and submit them to Nemesis"""
    try:
        logger = setup_logging(debug)
        if not source:
            logger.warning(UNKNOWN_SOURCE_WARNING)

        # Validate that path is a directory
        folder_path = Path(path)
        if not folder_path.exists():
            logger.error(f"Path does not exist: {folder_path}")
            sys.exit(1)

        if not folder_path.is_dir():
            logger.error(f"Path is not a directory: {folder_path}")
            sys.exit(1)

        logger.info(f"Monitoring folder: {folder_path}")

        # Set up the watcher before submitting existing files so files written meanwhile are not missed.
        event_handler = NewFileHandler(
            host,
            username,
            password,
            project,
            agent_id,
            logger,
            container,
            source,
            verify_ssl=verify_ssl,
            ca_file=ca_file,
        )
        observer = Observer()
        observer.schedule(event_handler, str(folder_path), recursive=True)
        event_handler.start()
        observer.start()

        try:
            # Submit existing files if not in only-monitor mode
            if not only_monitor:
                logger.info("Submitting existing files...")
                success = submit_files(
                    paths=[folder_path],
                    host=host,
                    recursive=True,  # Process subdirectories recursively
                    workers=workers,
                    username=username,
                    password=password,
                    project=project,
                    agent_id=agent_id,
                    container=container,
                    source=source,
                    verify_ssl=verify_ssl,
                    ca_file=ca_file,
                )

                if not success:
                    logger.error("Failed to submit existing files.")
            else:
                logger.info("Skipping existing files (--only-monitor enabled)")

            logger.info("File monitoring started. Press Ctrl+C to stop...")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping monitor...")
        finally:
            observer.stop()
            observer.join()
            event_handler.stop()

        logger.info("Monitor stopped")

    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

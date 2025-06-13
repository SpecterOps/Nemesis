# main.py
import json
import logging
import os
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from queue import Empty, Queue
from threading import Event, Thread
from typing import Optional

import click
import requests
import urllib3
from tqdm import tqdm
import colorlog

# Disable SSL warnings for the submit functionality
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up colored logging
handler = colorlog.StreamHandler()
handler.setFormatter(
    colorlog.ColoredFormatter(
        fmt="%(log_color)s%(levelname)-8s%(reset)s %(message)s",
        log_colors={
            "DEBUG": "cyan",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "red,bg_white",
        },
    )
)

logger = colorlog.getLogger(__name__)
logger.addHandler(handler)
logger.propagate = False
logger.setLevel(logging.DEBUG)


class UploadTracker:
    def __init__(self):
        self.successful = 0
        self.failed = 0
        self.bytes_uploaded = 0
        self.failures = []  # (path, error) tuples
        self.successes = []  # (path, bytes) tuples
        self.lock = threading.Lock()

    @property
    def total_files(self) -> int:
        """Total number of files processed (success + failed)"""
        return self.successful + self.failed

    def add_success(self, path: Path, bytes_uploaded: int):
        """Track a successful upload with path and bytes"""
        with self.lock:
            self.successful += 1
            self.bytes_uploaded += bytes_uploaded
            self.successes.append((path, bytes_uploaded))

    def add_failure(self, path: Path, error: Optional[str]):
        """Track a failed upload with path and error message"""
        with self.lock:
            self.failed += 1
            self.failures.append((path, error))

    def format_bytes(self) -> str:
        """Convert bytes to human readable format"""
        bytes_remaining = self.bytes_uploaded
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if bytes_remaining < 1024.0:
                return f"{bytes_remaining:.2f} {unit}"
            bytes_remaining /= 1024.0
        return f"{bytes_remaining:.2f} PB"

    def get_failures(self) -> list[tuple[Path, str]]:
        """Get list of failures with their error messages"""
        with self.lock:
            return self.failures.copy()

    def get_successes(self) -> list[tuple[Path, int]]:
        """Get list of successful uploads with their sizes"""
        with self.lock:
            return self.successes.copy()

    def display_summary(self):
        """Display a summary of the upload operation"""
        total = self.total_files
        if total == 0:
            logger.info("No files were processed")
            return

        success_rate = (self.successful / total) * 100 if total > 0 else 0

        logger.info("\nUpload Summary:")
        logger.info("─" * 40)
        logger.info(f"Total Files:     {total:,}")
        logger.info(f"Successful:      {self.successful:,}")
        logger.info(f"Failed:          {self.failed:,}")
        logger.info(f"Success Rate:    {success_rate:.1f}%")
        logger.info(f"Total Uploaded:  {self.format_bytes()}")

        if self.failed > 0:
            logger.info("\nFailed Uploads:")
            logger.info("─" * 40)
            for path, error in self.get_failures():
                logger.warning(f"• {path}: {error}")


def submit_main(
    debug: bool,
    paths: tuple[str, ...],
    host: str,
    recursive: bool,
    workers: int,
    username: str,
    password: str,
    project: str,
    agent_id: str,
    file_path: str,
):
    """Submit files to Nemesis for processing.

    PATHS... One or more files or directories to upload. If a directory is specified,
    all files within it will be uploaded. Use -r to process subdirectories recursively.

    Examples:

        # Upload a single file:
        main.py submit /etc/issue

        # Upload a single file (backwards compatible):
        main.py submit -f /etc/issue

        # Upload multiple files and recursively folder contents:
        main.py submit /etc/issue /etc/timezone /etc/ -r

        # Change the API endpoint:
        main.py submit /etc/issue -h 10.0.0.1:8080

        # Upload with basic auth:
        main.py submit /etc/issue -u admin -p secret
    """
    try:
        if debug:
            logger.setLevel(logging.DEBUG)

        # Handle backwards compatibility with -f/--file option
        if file_path:
            if paths:
                logger.error("Cannot specify both PATHS and --file option")
                sys.exit(1)
            paths = (file_path,)

        if not paths:
            logger.error("No files or paths specified")
            sys.exit(1)

        # Convert to Path objects
        path_objects = [Path(p) for p in paths]

        # Submit files
        success = submit_files(
            paths=path_objects,
            host=host,
            recursive=recursive,
            verbose=debug,
            workers=workers,
            username=username,
            password=password,
            project=project,
            agent_id=agent_id
        )

        if not success:
            sys.exit(1)

    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


def submit_files(
    paths: list[Path],
    host: str = "0.0.0.0:7443",
    recursive: bool = False,
    verbose: bool = False,
    workers: int = 10,
    username: str = "n",
    password: str = "n",
    project: str = "assess-test",
    agent_id: str = "beacon123",
):
    """Submit files to Nemesis"""

    file_queue = Queue()
    error_queue = Queue()
    tracker = UploadTracker()
    stop_event = Event()

    # Start counting total files (this will also start filling the queue)
    total_files = stream_files(paths, recursive, file_queue)

    if total_files == 0:
        logger.error("No files found to upload")
        return False

    # Validate authentication before starting uploads
    # Disable SSL warnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    auth = (username, password) if username and password else None
    if not validate_auth(host, auth):
        return False

    # Create progress bar
    with tqdm(
        total=total_files,
        desc="Uploading files",
        unit="file",
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
    ) as pbar:
        # Create and start worker threads
        threads = []
        # Auth credentials already validated above
        for _ in range(min(workers, total_files)):
            thread = Thread(
                target=worker,
                args=(file_queue, host, tracker, pbar, error_queue, stop_event, verbose, auth, project, agent_id),
            )
            thread.start()
            threads.append(thread)

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

    # Display final metrics
    tracker.display_summary()
    return tracker.failed == 0  # Return True if no failures


def stream_files(paths: list[Path], recursive: bool, file_queue: Queue) -> int:
    """Stream files into the queue as they're discovered"""
    total_files = 0

    for path in paths:
        try:
            if path.is_file():
                file_queue.put(path)
                total_files += 1
                continue

            pattern = "**/*" if recursive else "*"
            for item in path.glob(pattern):
                try:
                    if item.is_file():
                        file_queue.put(item)
                        total_files += 1
                except PermissionError:
                    logger.warning(f"Cannot access: {item}")
                except Exception as e:
                    logger.warning(f"Error with {item}: {str(e)}")

        except PermissionError:
            logger.error(f"Cannot access path: {path}")
        except Exception as e:
            logger.error(f"Error with path {path}: {str(e)}")

    return total_files


def validate_auth(host_port: str, auth: Optional[tuple[str, str]] = None) -> bool:
    """
    Validate authentication credentials before starting uploads.
    Returns True if auth is valid or not required, False otherwise.
    """
    try:
        # Try a GET request to /api/ endpoint to check auth
        response = requests.get(f"https://{host_port}/api/system/info", auth=auth, verify=False)
        if response.status_code == 401:
            logger.error("Authentication failed. Please check your credentials.")
            return False
        elif response.status_code == 403:
            logger.error("Authorization failed. User does not have required permissions.")
            return False
        elif response.status_code >= 400:
            logger.error(f"Unexpected server error during auth check: {response.status_code}")
            return False
        return True
    except requests.exceptions.ConnectionError:
        logger.error(f"Could not connect to server when testing authentication: {host_port}")
        return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during auth check: {str(e)}")
        return False


def create_metadata(path: str, project: str = "assess-test", agent_id: str = "beacon123") -> dict:
    return {
        "agent_id": agent_id,
        "project": project,
        "timestamp": datetime.now(UTC).isoformat(),
        "expiration": datetime.now(UTC).replace(year=datetime.now().year + 1).isoformat(),
        "path": str(path),
    }


def upload_file(
    file_path: Path,
    host_port: str,
    auth: Optional[tuple[str, str]] = None,
    project: str = "assess-test",
    agent_id: str = "beacon123",
) -> tuple[bool, Optional[str], int]:
    """
    Attempt to upload a file. Returns (success, error_message, bytes_uploaded).
    If success is True, error_message will be None.
    """
    try:
        if not os.access(file_path, os.R_OK):
            raise PermissionError(f"No read permission for {file_path}")

        metadata = create_metadata(str(file_path), project, agent_id)
        file_size = file_path.stat().st_size

        with open(file_path, "rb") as f:
            files = {"file": f, "metadata": (None, json.dumps(metadata))}
            response = requests.post(f"https://{host_port}/api/files", files=files, auth=auth, verify=False)
            response.raise_for_status()
            return True, None, file_size

    except PermissionError:
        return False, f"Permission denied: {file_path}", 0
    except FileNotFoundError:
        return False, f"File not found: {file_path}", 0
    except requests.exceptions.RequestException as e:
        return False, f"Upload failed: {file_path} - {str(e)}", 0
    except Exception as e:
        return False, f"Unexpected error with {file_path}: {str(e)}", 0


def worker(
    queue: Queue,
    host_port: str,
    tracker: UploadTracker,
    progress_bar: tqdm,
    error_queue: Queue,
    stop_event: Event,
    verbose: bool,
    auth: Optional[tuple[str, str]] = None,
    project: str = "assess-test",
    agent_id: str = "beacon123",
):
    """Worker thread to process files from the queue"""
    while not stop_event.is_set():
        try:
            file_path = queue.get_nowait()
        except Empty:
            break

        success, error, bytes_uploaded = upload_file(file_path, host_port, auth, project, agent_id)
        if success:
            tracker.add_success(file_path, bytes_uploaded)
            if verbose:
                logger.debug(f"✓ {file_path} ({bytes_uploaded:,} bytes)")
        else:
            tracker.add_failure(file_path, error)
            if error:
                error_queue.put(error)
                logger.warning(error)

        progress_bar.update(1)
        progress_bar.set_description(
            f"Uploading (✓:{tracker.successful} ✗:{tracker.failed} | {tracker.format_bytes()})"
        )
        queue.task_done()

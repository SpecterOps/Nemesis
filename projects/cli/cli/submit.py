# main.py
import json
import logging
import os
import sys
import threading
import time
from pathlib import Path
from queue import Empty, Queue
from threading import Event, Thread
from typing import Optional

import click
import colorlog
import requests
import urllib3
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from tqdm import tqdm

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


def parse_filters(
    filters_file: Optional[str],
    include_patterns: tuple[str, ...],
    exclude_patterns: tuple[str, ...],
    pattern_type: str,
) -> Optional[dict]:
    """Parse filter options into the format expected by the API"""

    # If a filters file is provided, load it
    if filters_file:
        if include_patterns or exclude_patterns:
            raise ValueError("Cannot specify both --filters file and --include-pattern/--exclude-pattern options")

        try:
            with open(filters_file) as f:
                filters_data = json.load(f)

            # Validate the structure
            if not isinstance(filters_data, dict):
                raise ValueError("Filters file must contain a JSON object")

            # Ensure pattern_type is set if not specified in file
            if "pattern_type" not in filters_data:
                filters_data["pattern_type"] = pattern_type

            return filters_data

        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in filters file: {e}") from e
        except Exception as e:
            raise ValueError(f"Error reading filters file: {e}") from e

    # If inline patterns are provided, build the filter object
    elif include_patterns or exclude_patterns:
        file_filters = {"pattern_type": pattern_type}

        if include_patterns:
            file_filters["include"] = list(include_patterns)
        if exclude_patterns:
            file_filters["exclude"] = list(exclude_patterns)

        return file_filters

    return None


def validate_filters(file_filters: dict) -> None:
    """Validate the structure of file filters"""
    allowed_fields = {"include", "exclude", "pattern_type"}

    if not isinstance(file_filters, dict):
        raise ValueError("file_filters must be a dictionary")

    # Check for unknown fields
    unknown_fields = set(file_filters.keys()) - allowed_fields
    if unknown_fields:
        raise ValueError(f"Unknown filter fields: {', '.join(unknown_fields)}")

    # Validate pattern_type
    pattern_type = file_filters.get("pattern_type", "glob")
    if pattern_type not in ["glob", "regex"]:
        raise ValueError(f"pattern_type must be 'glob' or 'regex', got: {pattern_type}")

    # Validate include/exclude are lists of strings
    for field in ["include", "exclude"]:
        if field in file_filters:
            patterns = file_filters[field]
            if not isinstance(patterns, list):
                raise ValueError(f"{field} must be a list of strings")
            if not all(isinstance(p, str) for p in patterns):
                raise ValueError(f"All {field} patterns must be strings")

    # At least one of include or exclude should be present
    if not any(field in file_filters for field in ["include", "exclude"]):
        raise ValueError("At least one of 'include' or 'exclude' patterns must be specified")


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
    container: bool,
    source: Optional[str] = None,
    filters: Optional[str] = None,
    include_pattern: tuple[str, ...] = (),
    exclude_pattern: tuple[str, ...] = (),
    pattern_type: str = "glob",
    repeat: int = 0,
    folder: Optional[str] = None,
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

        # Upload container with filters from file:
        main.py submit archive.zip --container --filters filters.json

        # Upload container with inline patterns:
        main.py submit archive.zip --container --include-pattern "*.exe" --exclude-pattern "*/temp/*"

        # Submit file twice (original + 1 repeat):
        main.py submit /etc/issue --repeat 1

        # Upload files with custom parent folder path:
        main.py submit /tmp/data --folder "C:\\Users\\Admin\\Documents" -r
        # Files at /tmp/data/file.txt will have path "C:\\Users\\Admin\\Documents\\file.txt"
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

        # Validate repeat parameter
        if repeat < 0:
            logger.error("Repeat count must be at least 0")
            sys.exit(1)

        # Validate filter options
        file_filters = None
        if container and (filters or include_pattern or exclude_pattern):
            file_filters = parse_filters(filters, include_pattern, exclude_pattern, pattern_type)

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
            agent_id=agent_id,
            container=container,
            source=source,
            file_filters=file_filters,
            repeat=repeat,
            folder=folder,
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
    workers: int = 5,
    username: str = "n",
    password: str = "n",
    project: str = "assess-test",
    agent_id: str = "submit.sh",
    container: bool = False,
    source: Optional[str] = None,
    file_filters: Optional[dict] = None,
    repeat: int = 0,
    folder: Optional[str] = None,
):
    """Submit files to Nemesis"""

    # Validate that filters are only used with container mode
    if file_filters and not container:
        logger.error("File filters can only be used with --container flag")
        return False

    # Validate authentication before starting uploads
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    auth = (username, password) if username and password else None
    if not validate_auth(host, auth):
        return False

    # Create session with retry logic and connection pooling
    session = create_session_with_retries()

    # Total submissions = 1 original + repeat additional submissions
    total_submissions = 1 + repeat

    # Get list of files once
    temp_queue = Queue()
    total_files = stream_files(paths, recursive, temp_queue)

    if total_files == 0:
        logger.error("No files found to upload")
        return False

    # Convert queue to list for reuse across submissions
    files_to_submit = []
    while not temp_queue.empty():
        try:
            files_to_submit.append(temp_queue.get_nowait())
        except Empty:
            break

    # Calculate total operations for progress bar
    total_operations = total_files * total_submissions

    # Create shared structures for concurrent submission
    overall_tracker = UploadTracker()
    error_queue = Queue()
    stop_event = Event()

    if total_submissions > 1:
        logger.info(f"Starting {total_submissions} concurrent submissions ({total_files} files × {total_submissions} submissions = {total_operations} total operations)")

    # Create progress bar for all operations
    with tqdm(
        total=total_operations,
        desc="Uploading files concurrently" if total_submissions > 1 else "Uploading files",
        unit="upload",
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
    ) as pbar:
        # Create worker threads - each handles multiple submissions of the same file
        threads = []
        file_submission_queue = Queue()

        # Populate queue with (file, submission_number) pairs
        for submission_num in range(total_submissions):
            for file_path in files_to_submit:
                file_submission_queue.put((file_path, submission_num))

        # Create worker threads
        for _ in range(min(workers, total_operations)):
            thread = Thread(
                target=concurrent_worker,
                args=(
                    file_submission_queue,
                    host,
                    session,
                    overall_tracker,
                    pbar,
                    error_queue,
                    stop_event,
                    verbose,
                    auth,
                    project,
                    agent_id,
                    container,
                    source,
                    file_filters,
                    paths,
                    folder,
                ),
            )
            thread.start()
            threads.append(thread)

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

    # Display final metrics
    overall_tracker.display_summary()
    return overall_tracker.failed == 0


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


def calculate_metadata_path(file_path: Path, base_paths: Optional[list[Path]], folder: Optional[str]) -> str:
    """
    Calculate the path to use in metadata, applying folder transformation if specified.

    If folder is provided:
    - Find the common base from base_paths
    - Calculate relative path from that base
    - Join with the folder parameter

    Otherwise, return the file path as-is.
    """
    if folder is None or not base_paths:
        return str(file_path)

    # Resolve to absolute paths
    abs_file_path = file_path.resolve()

    # Find which base path this file is under
    matching_base = None
    for base_path in base_paths:
        abs_base = base_path.resolve()
        try:
            # Check if file is under this base path
            abs_file_path.relative_to(abs_base)
            matching_base = abs_base
            break
        except ValueError:
            # Not under this base, try next
            continue

    if matching_base is None:
        # File is not under any base path, use as-is
        return str(file_path)

    # Calculate relative path from the matching base
    try:
        if matching_base.is_file():
            # Base is a file, so the relative part is just the filename
            rel_path = abs_file_path.name
        else:
            # Base is a directory, calculate relative path
            rel_path = abs_file_path.relative_to(matching_base)
    except ValueError:
        # Shouldn't happen, but fallback
        return str(file_path)

    # Normalize the relative path to use forward slashes
    rel_path_normalized = str(rel_path).replace('\\', '/')

    # If folder is empty string, return just the relative path without any prefix
    if folder == "":
        return rel_path_normalized

    # Ensure folder ends with path separator if it doesn't
    folder_normalized = folder.rstrip('/\\')

    # Join folder with relative path using Unix-style paths
    result = folder_normalized + '/' + rel_path_normalized

    return result


def create_metadata(
    path: str,
    project: str = "assess-test",
    agent_id: str = "submit.sh",
    source: Optional[str] = None,
    file_filters: Optional[dict] = None,
) -> dict:
    """Create metadata dictionary for file submission"""
    metadata = {
        "agent_id": agent_id,
        "project": project,
        # "timestamp": datetime.now(UTC).isoformat(), # these have defaults in the submission API now
        # "expiration": datetime.now(UTC).replace(year=datetime.now().year + 1).isoformat(),
        "path": str(path),
    }
    if source:
        metadata["source"] = source
    if file_filters:
        # Validate filters before adding to metadata
        validate_filters(file_filters)
        metadata["file_filters"] = file_filters
    return metadata


def create_session_with_retries() -> requests.Session:
    """
    Create a requests session with retry logic and connection pooling.
    """
    session = requests.Session()

    # Configure retry strategy with exponential backoff
    retry_strategy = Retry(
        total=3,  # Total number of retries
        status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry on
        # method_whitelist=["HEAD", "GET", "POST"],  # HTTP methods to retry
        backoff_factor=1,  # Exponential backoff factor (1, 2, 4 seconds)
        raise_on_status=False,  # Don't raise on status codes in status_forcelist
    )

    # Configure HTTP adapter with retry strategy
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=10,  # Number of connection pools
        pool_maxsize=20,  # Maximum number of connections in pool
        pool_block=False,  # Don't block when pool is full
    )

    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session


def upload_file(
    file_path: Path,
    host_port: str,
    session: requests.Session,
    auth: Optional[tuple[str, str]] = None,
    project: str = "assess-test",
    agent_id: str = "submit.sh",
    container: bool = False,
    source: Optional[str] = None,
    file_filters: Optional[dict] = None,
    base_paths: Optional[list[Path]] = None,
    folder: Optional[str] = None,
) -> tuple[bool, Optional[str], int]:
    """
    Attempt to upload a file with retry logic. Returns (success, error_message, bytes_uploaded).
    If success is True, error_message will be None.
    """
    max_retries = 3
    base_delay = 1.0

    for attempt in range(max_retries):
        try:
            if not os.access(file_path, os.R_OK):
                raise PermissionError(f"No read permission for {file_path}")

            # Calculate the metadata path (transformed if folder is provided)
            metadata_path = calculate_metadata_path(file_path, base_paths, folder)

            metadata = create_metadata(metadata_path, project, agent_id, source, file_filters)
            file_size = file_path.stat().st_size

            endpoint = "/api/containers" if container else "/api/files"

            with open(file_path, "rb") as f:
                files = {"file": f, "metadata": (None, json.dumps(metadata))}
                response = session.post(
                    f"https://{host_port}{endpoint}",
                    files=files,
                    auth=auth,
                    verify=False,
                    timeout=(30, 300),
                )
                response.raise_for_status()
                return True, None, file_size

        except PermissionError:
            return False, f"Permission denied: {file_path}", 0
        except FileNotFoundError:
            return False, f"File not found: {file_path}", 0
        except (requests.exceptions.SSLError, requests.exceptions.ConnectionError) as e:
            if attempt < max_retries - 1:
                delay = base_delay * (2**attempt)
                logger.debug(f"SSL/Connection error on attempt {attempt + 1}, retrying in {delay}s: {str(e)}")
                time.sleep(delay)
                continue
            return False, f"Upload failed: {file_path} - {str(e)}", 0
        except requests.exceptions.Timeout as e:
            if attempt < max_retries - 1:
                delay = base_delay * (2**attempt)
                logger.debug(f"Timeout on attempt {attempt + 1}, retrying in {delay}s: {str(e)}")
                time.sleep(delay)
                continue
            return False, f"Upload failed: {file_path} - {str(e)}", 0
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1 and "504" in str(e):
                delay = base_delay * (2**attempt)
                logger.debug(f"Server error on attempt {attempt + 1}, retrying in {delay}s: {str(e)}")
                time.sleep(delay)
                continue
            return False, f"Upload failed: {file_path} - {str(e)}", 0
        except Exception as e:
            return False, f"Unexpected error with {file_path}: {str(e)}", 0

    return False, f"Upload failed after {max_retries} attempts: {file_path}", 0


def concurrent_worker(
    queue: Queue,
    host_port: str,
    session: requests.Session,
    tracker: UploadTracker,
    progress_bar: tqdm,
    error_queue: Queue,
    stop_event: Event,
    verbose: bool,
    auth: Optional[tuple[str, str]] = None,
    project: str = "assess-test",
    agent_id: str = "submit.sh",
    container: bool = False,
    source: Optional[str] = None,
    file_filters: Optional[dict] = None,
    base_paths: Optional[list[Path]] = None,
    folder: Optional[str] = None,
):
    """Worker thread to process (file, submission_number) pairs from the queue"""
    while not stop_event.is_set():
        try:
            file_path, submission_num = queue.get_nowait()
        except Empty:
            break

        success, error, bytes_uploaded = upload_file(
            file_path, host_port, session, auth, project, agent_id, container, source, file_filters, base_paths, folder
        )
        if success:
            tracker.add_success(file_path, bytes_uploaded)
            if verbose:
                logger.debug(f"✓ {file_path} submission #{submission_num} ({bytes_uploaded:,} bytes)")
        else:
            tracker.add_failure(file_path, error)
            if error:
                error_queue.put(error)
                logger.warning(f"✗ {file_path} submission #{submission_num}: {error}")

        progress_bar.update(1)
        progress_bar.set_description(
            f"Uploading (✓:{tracker.successful} ✗:{tracker.failed} | {tracker.format_bytes()})"
        )
        queue.task_done()


def worker(
    queue: Queue,
    host_port: str,
    session: requests.Session,
    tracker: UploadTracker,
    progress_bar: tqdm,
    error_queue: Queue,
    stop_event: Event,
    verbose: bool,
    auth: Optional[tuple[str, str]] = None,
    project: str = "assess-test",
    agent_id: str = "submit.sh",
    container: bool = False,
    source: Optional[str] = None,
    file_filters: Optional[dict] = None,
    base_paths: Optional[list[Path]] = None,
    folder: Optional[str] = None,
):
    """Worker thread to process files from the queue"""
    while not stop_event.is_set():
        try:
            file_path = queue.get_nowait()
        except Empty:
            break

        success, error, bytes_uploaded = upload_file(
            file_path, host_port, session, auth, project, agent_id, container, source, file_filters, base_paths, folder
        )
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

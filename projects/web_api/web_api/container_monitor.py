import asyncio
import os
import shutil
import threading
import time
import uuid
import zipfile
from pathlib import Path
from queue import Empty, Queue
from typing import Any

import yaml
from common.logger import get_logger
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from web_api.large_containers import LargeContainerProcessor

logger = get_logger(__name__)

MOUNTED_CONTAINER_PATH = os.getenv("MOUNTED_CONTAINER_PATH", "/mounted-containers")
COMPLETED_FOLDER = "completed"


def is_container_file(file_path: Path) -> bool:
    """
    Check if a file is a container that can be processed.
    Returns True for ZIP files and formats that can be processed by pytsk3.
    """
    if not file_path.is_file():
        return False

    filename_lower = file_path.name.lower()

    # Check ZIP files by extension first
    if filename_lower.endswith(".zip"):
        try:
            return zipfile.is_zipfile(file_path)
        except Exception:
            return False

    # Check disk images by extension - all formats supported by Sleuth Kit
    disk_image_extensions = (
        # Raw disk images
        ".dd",
        ".raw",
        ".img",
        ".image",
        ".bin",
        ".dmg",
        # Forensic formats
        ".e01",
        ".ex01",
        ".l01",
        ".lx01",
        ".ewf",
        ".s01",
    )

    if any(filename_lower.endswith(ext) for ext in disk_image_extensions):
        return True

    # For unknown extensions, check if it's a ZIP file
    try:
        if zipfile.is_zipfile(file_path):
            return True
    except Exception:
        pass

    return False


def find_config_file(start_path: Path, root_path: Path) -> Path | None:
    """
    Find config.yaml or settings.yaml (or .yml) starting from start_path
    and searching upward until root_path.

    Config format:

        metadata:
            agent_id: agent123
            project: example
            source: server1
        file_filters:
            pattern_type: regex # default of regex
            include:
                - "^(?:[A-Za-z]://|/)?[Ww]indows/[Ss]ystem32/config/"
            exclude:
                - "^(?:[A-Za-z]://|/)?[Ww]indows/"
                - "^(?:[A-Za-z]://|/)?[Pp]rogram [Ff]iles/"
                - "^(?:[A-Za-z]://|/)?[Pp]rogram [Ff]iles \\(x86\\)/"

    """
    current_path = start_path
    config_names = ["config.yaml", "config.yml", "settings.yaml", "settings.yml"]

    while True:
        # Check each possible config file name in the current directory
        for config_name in config_names:
            config_file = current_path / config_name
            if config_file.exists() and config_file.is_file():
                logger.info(f"Found config file: {config_file}")
                return config_file

        # Move up one directory
        parent = current_path.parent

        # Stop if we've reached the root path or can't go up further
        if current_path == root_path or current_path == parent:
            break

        current_path = parent

    logger.info(f"No config file found from {start_path} up to {root_path}")
    return None


def wait_for_file_stability(file_path: Path, max_wait_seconds: int = (60 * 60), check_interval: float = 20.0) -> bool:
    """
    Wait for a file to be stable (not being written to) before processing.

    Args:
        file_path: Path to the file to monitor
        max_wait_seconds: Maximum time to wait in seconds (default 5 minutes)
        check_interval: How often to check file stability in seconds

    Returns:
        True if file is stable, False if timeout occurred
    """
    if not file_path.exists():
        logger.warning(f"File does not exist: {file_path}")
        return False

    logger.info(f"Waiting for file stability: {file_path}")

    start_time = time.time()
    last_size = -1
    last_mtime = -1
    stable_checks = 0
    required_stable_checks = max(3, int(60 / check_interval))  # At least 3 checks, or 60 seconds worth

    while time.time() - start_time < max_wait_seconds:
        try:
            stat = file_path.stat()
            current_size = stat.st_size
            current_mtime = stat.st_mtime

            # Check if file size and modification time haven't changed
            if current_size == last_size and current_mtime == last_mtime:
                stable_checks += 1
                if stable_checks >= required_stable_checks:
                    logger.info(f"File is stable after {time.time() - start_time:.1f}s: {file_path}")
                    return True
            else:
                # File changed, reset counter
                stable_checks = 0
                last_size = current_size
                last_mtime = current_mtime
                logger.debug(f"File still changing - size: {current_size}, mtime: {current_mtime}")

            time.sleep(check_interval)

        except Exception as e:
            logger.warning(f"Error checking file stability for {file_path}: {e}")
            time.sleep(check_interval)

    logger.warning(f"File stability timeout after {max_wait_seconds}s: {file_path}")
    return False


def parse_config_file(config_path: Path | None, container_file: Path) -> dict[str, Any]:
    """
    Parse config file and return metadata with defaults.
    """
    metadata = {
        "agent_id": "mounted_container",
        "project": "unknown",
        "source": container_file.stem,  # base filename without extension
        "file_filters": None,
    }

    if not config_path:
        return metadata

    try:
        with open(config_path) as f:
            config = yaml.safe_load(f)

        if not config:
            return metadata

        # Extract metadata section
        if "metadata" in config:
            meta_section = config["metadata"]
            if "agent_id" in meta_section:
                metadata["agent_id"] = meta_section["agent_id"]
            if "project" in meta_section:
                metadata["project"] = meta_section["project"]
            if "source" in meta_section:
                metadata["source"] = meta_section["source"]

        # Extract file_filters section
        if "file_filters" in config:
            filters = config["file_filters"]
            # Set default pattern_type to 'regex' if not specified
            if "pattern_type" not in filters:
                filters["pattern_type"] = "regex"
            metadata["file_filters"] = filters

        logger.info(f"Parsed config from {config_path}", metadata=metadata)

    except Exception as e:
        logger.warning(f"Error parsing config file {config_path}: {e}")

    return metadata


class ContainerFileHandler(FileSystemEventHandler):
    """Handler for container file events in the monitored directory"""

    def __init__(self, container_queue: Queue, root_path: Path):
        self.container_queue = container_queue
        self.root_path = root_path
        self.completed_path = root_path / COMPLETED_FOLDER

    def _should_ignore_path(self, file_path: Path) -> bool:
        """Check if a path should be ignored (e.g., in completed folder)"""
        try:
            # Check if the file is in the completed folder
            file_path.resolve().relative_to(self.completed_path.resolve())
            return True
        except ValueError:
            # File is not in completed folder
            return False

    def on_created(self, event):
        """Called when a file is created"""
        if not event.is_directory:
            self._handle_file(Path(event.src_path))

    def on_moved(self, event):
        """Called when a file is moved into the monitored directory"""
        if not event.is_directory:
            self._handle_file(Path(event.dest_path))

    def _handle_file(self, file_path: Path):
        """Handle a new or moved file"""
        try:
            # Ignore files in completed folder
            if self._should_ignore_path(file_path):
                logger.debug(f"Ignoring file in completed folder: {file_path}")
                return

            # Small delay to let file creation settle
            time.sleep(0.5)

            # Check if file still exists (could have been moved/deleted quickly)
            if not file_path.exists():
                logger.debug(f"File no longer exists, ignoring: {file_path}")
                return

            # Check if it's a container file
            if is_container_file(file_path):
                logger.info(f"New container file detected: {file_path}")

                # Find config file
                config_path = find_config_file(file_path.parent, self.root_path)

                # Parse config and create metadata
                metadata = parse_config_file(config_path, file_path)

                # Add to processing queue
                self.container_queue.put({"file_path": file_path, "metadata": metadata})
            else:
                logger.debug(f"Non-container file ignored: {file_path}")

        except Exception as e:
            logger.exception(f"Error handling file {file_path}: {e}")


class ContainerMonitor:
    """Monitor for container files with background processing"""

    def __init__(self):
        self.mounted_path = Path(MOUNTED_CONTAINER_PATH)
        self.completed_path = self.mounted_path / COMPLETED_FOLDER
        self.container_queue = Queue()
        self.processor = LargeContainerProcessor()
        self.observer = None
        self.processing_thread = None
        self.running = False

        # Ensure completed directory exists
        self.completed_path.mkdir(exist_ok=True)

    def _move_to_completed(self, file_path: Path):
        """Move a container file to the completed folder"""
        try:
            # Create completed folder if it doesn't exist
            self.completed_path.mkdir(exist_ok=True)

            # Calculate destination path
            dest_path = self.completed_path / file_path.name

            # Handle name conflicts by adding a counter
            counter = 1
            while dest_path.exists():
                stem = file_path.stem
                suffix = file_path.suffix
                dest_path = self.completed_path / f"{stem}_{counter}{suffix}"
                counter += 1

            # Move the file
            shutil.move(str(file_path), str(dest_path))
            logger.info(f"Moved completed container to: {dest_path}")

        except Exception as e:
            logger.error(f"Error moving file {file_path} to completed folder: {e}")

    def _process_containers(self):
        """Background thread function to process containers one at a time"""
        logger.info("Container processing thread started")

        while self.running:
            try:
                # Get next container from queue (blocking with timeout)
                try:
                    container_info = self.container_queue.get(timeout=1.0)
                except Empty:  # Raised when the timeout hits
                    continue

                file_path = container_info["file_path"]
                metadata = container_info["metadata"]

                logger.info(f"Processing container: {file_path}")

                try:
                    # Wait for file to be stable before processing
                    if not wait_for_file_stability(file_path):
                        logger.error(f"File stability timeout, skipping: {file_path}")
                        continue

                    # Generate container ID
                    container_id = str(uuid.uuid4())

                    # Add file information to metadata
                    file_stats = file_path.stat()
                    processing_metadata = metadata.copy()
                    processing_metadata.update(
                        {
                            "filename": file_path.name,
                            "path": str(file_path),
                            "content_type": "application/octet-stream",
                            "size": file_stats.st_size,
                            "source_type": "mounted_monitor",
                        }
                    )

                    # Process the container
                    result = self.processor.process_container_from_path(container_id, file_path, processing_metadata)

                    logger.info(
                        f"Container processing completed: {file_path}", container_id=container_id, result=result
                    )

                    # Move file to completed folder
                    self._move_to_completed(file_path)

                except Exception as e:
                    logger.exception(f"Error processing container {file_path}: {e}")

                finally:
                    self.container_queue.task_done()

            except Exception as e:
                logger.exception(f"Unexpected error in container processing thread: {e}")

        logger.info("Container processing thread stopped")

    def _scan_existing_files(self):
        """Scan for existing container files on startup"""
        try:
            logger.info(f"Scanning for existing container files in: {self.mounted_path}")

            for file_path in self.mounted_path.rglob("*"):
                # Skip files in completed folder
                if self.completed_path in file_path.parents or file_path == self.completed_path:
                    continue

                # Check if it's a container file
                if is_container_file(file_path):
                    logger.info(f"Found existing container file: {file_path}")

                    # Find config file
                    config_path = find_config_file(file_path.parent, self.mounted_path)

                    # Parse config and create metadata
                    metadata = parse_config_file(config_path, file_path)

                    # Add to processing queue
                    self.container_queue.put({"file_path": file_path, "metadata": metadata})

        except Exception as e:
            logger.exception(f"Error scanning existing files: {e}")

    def start(self):
        """Start the container monitor"""
        if self.running:
            logger.warning("Container monitor is already running")
            return

        try:
            # Validate mounted path exists
            if not self.mounted_path.exists():
                logger.error(f"Mounted container path does not exist: {self.mounted_path}")
                return

            logger.info(f"Starting container monitor for: {self.mounted_path}")

            self.running = True

            # Start processing thread
            self.processing_thread = threading.Thread(
                target=self._process_containers, daemon=True, name="ContainerProcessor"
            )
            self.processing_thread.start()

            # Scan for existing files
            self._scan_existing_files()

            # Set up file system watcher
            event_handler = ContainerFileHandler(self.container_queue, self.mounted_path)
            self.observer = Observer()
            self.observer.schedule(event_handler, str(self.mounted_path), recursive=True)

            # Start monitoring
            self.observer.start()
            logger.info("Container file monitoring started")

        except Exception as e:
            logger.exception(f"Error starting container monitor: {e}")
            self.stop()

    def stop(self):
        """Stop the container monitor"""
        if not self.running:
            return

        logger.info("Stopping container monitor...")
        self.running = False

        # Stop file system observer
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None

        # Wait for processing thread to finish
        if self.processing_thread and self.processing_thread.is_alive():
            logger.info("Waiting for container processing to complete...")
            self.processing_thread.join(timeout=30)  # Wait up to 30 seconds
            if self.processing_thread.is_alive():
                logger.warning("Container processing thread did not stop cleanly")

        logger.info("Container monitor stopped")

    def get_status(self) -> dict[str, Any]:
        """Get monitor status information"""
        return {
            "running": self.running,
            "mounted_path": str(self.mounted_path),
            "completed_path": str(self.completed_path),
            "queue_size": self.container_queue.qsize(),
            "processing_thread_alive": self.processing_thread.is_alive() if self.processing_thread else False,
        }


# Global monitor instance
_monitor_instance: ContainerMonitor | None = None


def get_monitor() -> ContainerMonitor:
    """Get the global monitor instance"""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = ContainerMonitor()
    return _monitor_instance


async def start_monitor():
    """Start the container monitor"""

    def _start():
        monitor = get_monitor()
        monitor.start()

    # Run in thread pool to avoid blocking
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _start)


async def stop_monitor():
    """Stop the container monitor"""

    def _stop():
        monitor = get_monitor()
        monitor.stop()

    # Run in thread pool to avoid blocking
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _stop)

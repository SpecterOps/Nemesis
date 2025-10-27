import json
import os
import re
import tempfile
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytsk3
from common.db import get_postgres_connection_str
from common.logger import get_logger
from common.models import File as FileModel
from common.models2.api import FileFilters
from common.storage import StorageMinio
from dapr.clients import DaprClient
from fastapi import HTTPException

logger = get_logger(__name__)

# Dapr state store name for container processing
DAPR_STORE_NAME = "container_processing"

MOUNTED_CONTAINER_PATH = os.getenv("MOUNTED_CONTAINER_PATH", "/mounted-containers/")
DEFAULT_EXPIRATION_DAYS = int(os.getenv("DEFAULT_EXPIRATION_DAYS", 100))


class ContainerStatus:
    """Container processing status enumeration"""

    SUBMITTED = "submitted"
    PROCESSING = "processing"
    EXTRACTING = "extracting"
    EXTRACTED = "extracted"
    WORKFLOWS_COMPLETE = "workflows_complete"
    FAILED = "failed"


class ContainerType:
    """Supported container types"""

    ZIP = "zip"
    DD_IMAGE = "dd_image"


class ContainerProgress:
    """In-memory progress tracking for container processing"""

    def __init__(self):
        self._progress: dict[str, dict[str, Any]] = {}

    def initialize(self, container_id: str, total_files: int, total_bytes: int):
        """Initialize progress tracking for a container"""
        self._progress[container_id] = {
            "total_files": total_files,
            "total_bytes": total_bytes,
            "processed_files": 0,
            "processed_bytes": 0,
            "current_file": None,
            "started_at": datetime.now(),
        }

    def update_file_progress(self, container_id: str, filename: str, file_size: int):
        """Update progress for a processed file"""
        if container_id in self._progress:
            progress = self._progress[container_id]
            progress["processed_files"] += 1
            progress["processed_bytes"] += file_size
            progress["current_file"] = filename

    def get_progress(self, container_id: str) -> dict[str, Any] | None:
        """Get current progress for a container"""
        return self._progress.get(container_id)

    def cleanup(self, container_id: str):
        """Clean up progress tracking for completed container"""
        self._progress.pop(container_id, None)

    def get_container_info(self, container_id: str) -> dict[str, Any] | None:
        """Get container info including originating container ID"""
        return self._progress.get(container_id, {}).get("container_info")

    def set_container_info(self, container_id: str, container_info: dict[str, Any]):
        """Set container info for tracking"""
        if container_id in self._progress:
            self._progress[container_id]["container_info"] = container_info


class BaseContainerExtractor:
    """Base class for container extractors"""

    def __init__(self, storage: StorageMinio, dapr_client: DaprClient, progress_tracker: ContainerProgress):
        self.storage = storage
        self.dapr_client = dapr_client
        self.progress_tracker = progress_tracker
        self.container_id = None
        self.file_metadata = None
        self.file_filter = None
        self.filter_stats = {"files_processed": 0, "files_skipped_by_filter": 0, "files_skipped_by_error": 0}

    def set_container_info(self, container_id: str, file_metadata: dict[str, Any]):
        """Set container processing information"""
        self.container_id = container_id
        self.file_metadata = file_metadata

        # Handle timestamp - use current UTC time if not provided
        if self.file_metadata.get("timestamp") is None:
            current_utc = datetime.now(UTC)
            self.file_metadata["timestamp"] = current_utc.isoformat()

        # Handle expiration - use timestamp + DEFAULT_EXPIRATION_DAYS if not provided
        if self.file_metadata.get("expiration") is None:
            expiration_dt = datetime.now(UTC) + timedelta(days=DEFAULT_EXPIRATION_DAYS)
            self.file_metadata["expiration"] = expiration_dt.isoformat()

        # Initialize file filter if provided
        filters = file_metadata.get("file_filters")
        if filters:
            if isinstance(filters, dict):
                filters = FileFilters(**filters)
            self.file_filter = FilePathFilter(filters)

            logger.info(
                "File filters configured for container",
                container_id=container_id,
                filter_stats=self.file_filter.get_filter_stats(),
            )
        else:
            self.file_filter = FilePathFilter()  # No filters

    def should_process_file(self, file_path: str) -> bool:
        """Check if a file should be processed based on filters"""
        should_include = self.file_filter.should_include_file(file_path)

        if not should_include:
            self.filter_stats["files_skipped_by_filter"] += 1
        #     logger.debug(
        #         "File skipped by filter",
        #         container_id=self.container_id,
        #         file_path=file_path
        #     )
        # else:
        #     logger.debug(
        #         "File included by filter",
        #         container_id=self.container_id,
        #         file_path=file_path
        #     )

        return should_include

    def publish_file_message(self, temp_file_path: str, object_id: str, real_path: str):
        """Publish file message to the message bus"""
        file_message = FileModel(
            object_id=object_id,
            agent_id=self.file_metadata["agent_id"],
            project=self.file_metadata["project"],
            source=self.file_metadata["source"],
            timestamp=self.file_metadata["timestamp"],
            expiration=self.file_metadata["expiration"],
            path=real_path,
            originating_object_id=self.file_metadata.get("originating_object_id"),
            nesting_level=(self.file_metadata.get("nesting_level", 0) + 1),
            originating_container_id=self.container_id,
        )

        data = json.dumps(file_message.model_dump(exclude_unset=True, mode="json"))
        self.dapr_client.publish_event(
            pubsub_name="pubsub",
            topic_name="file",
            data=data,
            data_content_type="application/json",
        )

        # Update progress and stats
        file_size = os.path.getsize(temp_file_path)
        self.progress_tracker.update_file_progress(self.container_id, os.path.basename(real_path), file_size)
        self.filter_stats["files_processed"] += 1

        logger.info(
            "Published file message for extracted file",
            container_id=self.container_id,
            object_id=object_id,
            path=real_path,
        )

    def get_processing_stats(self) -> dict:
        """Get processing statistics including filter stats"""
        return {
            **self.filter_stats,
            "filter_config": self.file_filter.get_filter_stats() if self.file_filter else {"filters_enabled": False},
        }

    def extract_and_process(self, container_file_path: Path) -> int:
        """Extract container and process files sequentially. Returns number of files processed."""
        raise NotImplementedError("Subclasses must implement extract_and_process")

    def estimate_container_contents(self, container_file_path: Path) -> tuple[int, int]:
        """Estimate number of files and total size. Returns (file_count, total_size)."""
        raise NotImplementedError("Subclasses must implement estimate_container_contents")


class FilePathFilter:
    """Handles file path filtering with glob and regex patterns"""

    def __init__(self, filters: FileFilters | None = None):
        self.filters = filters
        self.compiled_regex_include_patterns = []
        self.compiled_regex_exclude_patterns = []

        if filters:
            self._compile_regex_patterns()

    def _compile_regex_patterns(self):
        """Pre-compile regex patterns for performance (only used when pattern_type is 'regex')"""
        if not self.filters or self.filters.pattern_type != "regex":
            return

        if self.filters.include:
            self.compiled_regex_include_patterns = [
                re.compile(pattern, re.IGNORECASE) for pattern in self.filters.include
            ]
        if self.filters.exclude:
            self.compiled_regex_exclude_patterns = [
                re.compile(pattern, re.IGNORECASE) for pattern in self.filters.exclude
            ]

    def normalize_path(self, path: str) -> str:
        """Normalize path separators and format for consistent matching"""
        # Convert backslashes to forward slashes
        normalized = path.replace("\\", "/")

        return normalized

    def _matches_glob_pattern(self, normalized_path: str, pattern: str) -> bool:
        """Check if path matches a glob pattern using glob.fnmatch.filter"""
        return Path(normalized_path).match(pattern)

    def _matches_glob_patterns(self, normalized_path: str, patterns: list[str]) -> bool:
        """Check if path matches any glob pattern in the list"""
        for pattern in patterns:
            if self._matches_glob_pattern(normalized_path, pattern):
                return True
        return False

    def _matches_regex_patterns(self, normalized_path: str, compiled_patterns: list[re.Pattern]) -> bool:
        """Check if path matches any compiled regex pattern"""
        for pattern in compiled_patterns:
            if pattern.search(normalized_path):
                return True
        return False

    def should_include_file(self, file_path: str) -> bool:
        """
        Determine if a file should be included based on include/exclude patterns.

        Logic based on which patterns are provided:

        1. No filters: Include everything
        2. Only include patterns: Only include files matching include patterns (allowlist mode)
        3. Only exclude patterns: Include everything except files matching exclude patterns (blocklist mode)
        4. Both include and exclude: Include everything, apply excludes, then re-include matches from include patterns (exception mode)

        This creates a natural hierarchy where include patterns act as exceptions to exclusions when both are present.

        Args:
            file_path: The file path to check

        Returns:
            bool: True if file should be included, False if it should be skipped
        """
        if not self.filters:
            return True

        normalized_path = self.normalize_path(file_path)

        has_include_patterns = self.filters.include and len(self.filters.include) > 0
        has_exclude_patterns = self.filters.exclude and len(self.filters.exclude) > 0

        # Check if file matches include patterns
        include_match = False
        if has_include_patterns:
            if self.filters.pattern_type == "glob":
                include_match = self._matches_glob_patterns(normalized_path, self.filters.include)
            else:  # regex
                include_match = self._matches_regex_patterns(normalized_path, self.compiled_regex_include_patterns)

        # Check if file matches exclude patterns
        exclude_match = False
        if has_exclude_patterns:
            if self.filters.pattern_type == "glob":
                exclude_match = self._matches_glob_patterns(normalized_path, self.filters.exclude)
            else:  # regex
                exclude_match = self._matches_regex_patterns(normalized_path, self.compiled_regex_exclude_patterns)

        # Apply logic based on which patterns are present
        if has_include_patterns and has_exclude_patterns:
            # Both present: include all, apply excludes, then re-include matches from include (exception mode)
            if include_match:
                return True  # Include pattern acts as exception to exclude
            else:
                return not exclude_match  # Normal exclude logic

        elif has_include_patterns and not has_exclude_patterns:
            # Only include patterns: allowlist mode
            return include_match

        elif has_exclude_patterns and not has_include_patterns:
            # Only exclude patterns: blocklist mode
            return not exclude_match

        else:
            # No patterns (shouldn't reach here due to early return, but for completeness)
            return True

    def get_filter_stats(self) -> dict:
        """Get statistics about the configured filters"""
        if not self.filters:
            return {"filters_enabled": False}

        return {
            "filters_enabled": True,
            "pattern_type": self.filters.pattern_type,
            "include_patterns_count": len(self.filters.include) if self.filters.include else 0,
            "exclude_patterns_count": len(self.filters.exclude) if self.filters.exclude else 0,
            "include_patterns": self.filters.include or [],
            "exclude_patterns": self.filters.exclude or [],
            "compiled_regex_include_count": len(self.compiled_regex_include_patterns),
            "compiled_regex_exclude_count": len(self.compiled_regex_exclude_patterns),
        }


class ZipContainerExtractor(BaseContainerExtractor):
    """ZIP file extractor that processes files sequentially with filtering"""

    def estimate_container_contents(self, container_file_path: Path) -> tuple[int, int]:
        """Estimate ZIP contents with filtering"""
        try:
            with zipfile.ZipFile(container_file_path, "r") as zip_ref:
                file_count = 0
                total_size = 0

                for info in zip_ref.infolist():
                    if info.is_dir():
                        continue

                    # Security checks (same as extraction)
                    if info.filename.startswith("/") or ".." in info.filename:
                        continue

                    if len(os.path.basename(info.filename)) > 255:
                        continue

                    # Apply file filters
                    if not self.should_process_file(info.filename):
                        continue

                    file_count += 1
                    total_size += info.file_size

                return file_count, total_size
        except Exception as e:
            logger.warning(f"Error estimating ZIP contents: {e}")
            return 0, 0

    def extract_and_process(self, container_file_path: Path) -> int:
        """Extract ZIP file and process each file individually with filtering"""
        processed_count = 0

        try:
            with zipfile.ZipFile(container_file_path, "r") as zip_ref:
                for info in zip_ref.infolist():
                    if info.is_dir():
                        continue

                    # Security checks
                    if info.filename.startswith("/") or ".." in info.filename:
                        logger.warning(f"Skipping unsafe path: {info.filename}")
                        self.filter_stats["files_skipped_by_error"] += 1
                        continue

                    if len(os.path.basename(info.filename)) > 255:
                        logger.warning(f"Skipping filename too long: {info.filename}")
                        self.filter_stats["files_skipped_by_error"] += 1
                        continue

                    # Apply file filters
                    if not self.should_process_file(info.filename):
                        continue  # Skip this file due to filter

                    try:
                        # Extract single file to temporary location
                        with tempfile.NamedTemporaryFile(delete=False) as temp_extracted:
                            temp_extracted.write(zip_ref.read(info))
                            temp_extracted.flush()

                            # Upload to storage
                            object_id = self.storage.upload_file(temp_extracted.name)

                            # Calculate real path
                            base_dir = os.path.dirname(self.file_metadata["path"])
                            real_path = os.path.join(base_dir, info.filename).removeprefix(MOUNTED_CONTAINER_PATH)

                            # Publish file message
                            self.publish_file_message(temp_extracted.name, str(object_id), real_path)
                            processed_count += 1

                    except Exception as e:
                        logger.warning(f"Error processing file {info.filename}: {e}")
                        self.filter_stats["files_skipped_by_error"] += 1
                    finally:
                        # Clean up temporary file
                        if "temp_extracted" in locals() and os.path.exists(temp_extracted.name):
                            os.unlink(temp_extracted.name)

        except Exception as e:
            logger.exception(f"Error extracting ZIP file: {e}")
            raise

        # Log final statistics
        stats = self.get_processing_stats()
        logger.info("Container extraction completed", container_id=self.container_id, stats=stats)

        return processed_count


class DDImageContainerExtractor(BaseContainerExtractor):
    """DD disk image extractor that processes files from filesystem structures"""

    def estimate_container_contents(self, container_file_path: Path) -> tuple[int, int]:
        """Estimate DD image contents by parsing filesystem with filtering"""
        try:
            # Open the image file directly
            img_info = pytsk3.Img_Info(str(container_file_path))

            # Try to open the filesystem
            try:
                fs_info = pytsk3.FS_Info(img_info)

                # Walk the filesystem to count files and calculate size
                file_count = 0
                total_size = 0

                def walk_directory(directory, path="", stack=None):
                    """Recursively walk directory to count files with filtering"""
                    nonlocal file_count, total_size

                    if stack is None:
                        stack = []

                    for entry in directory:
                        # Skip . and .. entries
                        if entry.info.name.name in [b".", b".."]:
                            continue

                        # Skip if entry doesn't have metadata
                        if not hasattr(entry.info.meta, "type"):
                            continue

                        try:
                            # Get the file name
                            filename = entry.info.name.name.decode("utf-8", errors="replace")
                            file_path = os.path.join(path, filename)

                            # If it's a directory, recurse
                            if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                                try:
                                    sub_directory = entry.as_directory()
                                    # Prevent infinite loops
                                    inode = entry.info.meta.addr
                                    if inode not in stack:
                                        walk_directory(sub_directory, file_path, stack + [inode])
                                except Exception:
                                    # Some directories might not be accessible
                                    pass
                            # If it's a regular file, count it with filtering
                            elif entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                                # Security checks (same as extraction)
                                if file_path.startswith("/") or ".." in file_path:
                                    continue

                                if len(os.path.basename(filename)) > 255:
                                    continue

                                # Apply file filters
                                if not self.should_process_file(file_path):
                                    continue

                                # Skip empty files (same as extraction)
                                if entry.info.meta.size == 0:
                                    continue

                                # logger.debug(f"file_path: {file_path}")
                                file_count += 1
                                if hasattr(entry.info.meta, "size"):
                                    total_size += entry.info.meta.size

                        except Exception:
                            # Skip entries that can't be processed
                            continue

                # Start walking from root
                root_dir = fs_info.open_dir(path="/")
                walk_directory(root_dir)

            except Exception as e:
                logger.warning(f"Could not parse filesystem, will return 0 estimates: {e}")
                file_count = 0
                total_size = 0

            return file_count, total_size

        except Exception as e:
            logger.warning(f"Error estimating DD image contents: {e}")
            return 0, 0

    def extract_and_process(self, container_file_path: Path) -> int:
        """Extract DD image and process each file individually with filtering"""
        processed_count = 0

        try:
            # Open the image file directly
            img_info = pytsk3.Img_Info(str(container_file_path))

            try:
                # Try to open the filesystem
                fs_info = pytsk3.FS_Info(img_info)

                # Process files from the filesystem
                processed_count = self._process_filesystem(fs_info, img_info)

            except Exception as e:
                logger.exception(f"Could not parse filesystem: {e}")

        except Exception as e:
            logger.exception(f"Error extracting DD image: {e}")
            raise

        # Log final statistics
        stats = self.get_processing_stats()
        logger.info("Container extraction completed", container_id=self.container_id, stats=stats)

        return processed_count

    def _process_filesystem(self, fs_info: pytsk3.FS_Info, img_info: pytsk3.Img_Info) -> int:
        """Process files from a parsed filesystem"""
        processed_count = 0

        def process_directory(directory, path=""):
            """Recursively process files in directory"""
            nonlocal processed_count

            for entry in directory:
                # Skip . and .. entries
                if entry.info.name.name in [b".", b".."]:
                    continue

                # Skip if entry doesn't have metadata
                if not hasattr(entry.info.meta, "type"):
                    continue

                try:
                    # Get the file name
                    filename = entry.info.name.name.decode("utf-8", errors="replace")
                    file_path = os.path.join(path, filename)

                    # If it's a directory, recurse
                    if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        try:
                            sub_directory = entry.as_directory()
                            process_directory(sub_directory, file_path)
                        except Exception as e:
                            logger.debug(f"Could not access directory {file_path}: {e}")

                    # If it's a regular file, process it
                    elif entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                        # Security checks
                        if file_path.startswith("/") or ".." in file_path:
                            logger.warning(f"Skipping unsafe path: {file_path}")
                            self.filter_stats["files_skipped_by_error"] += 1
                            continue

                        if len(os.path.basename(filename)) > 255:
                            logger.warning(f"Skipping filename too long: {file_path}")
                            self.filter_stats["files_skipped_by_error"] += 1
                            continue

                        # Apply file filters
                        if not self.should_process_file(file_path):
                            continue

                        # Skip empty files
                        if entry.info.meta.size == 0:
                            logger.debug(f"Skipping empty file: {file_path}")
                            continue

                        try:
                            # Read file content
                            file_content = entry.read_random(0, entry.info.meta.size)

                            # Save to temporary file and upload
                            with tempfile.NamedTemporaryFile(delete=False) as temp_extracted:
                                temp_extracted.write(file_content)
                                temp_extracted.flush()

                                # Upload to storage
                                object_id = self.storage.upload_file(temp_extracted.name)

                                # Calculate real path
                                base_dir = os.path.dirname(self.file_metadata["path"])
                                real_path = os.path.join(base_dir, file_path).removeprefix(MOUNTED_CONTAINER_PATH)

                                # Publish file message
                                self.publish_file_message(temp_extracted.name, str(object_id), real_path)
                                processed_count += 1

                                # Clean up temporary file
                                os.unlink(temp_extracted.name)

                        except Exception as e:
                            logger.warning(f"Error processing file {file_path}: {e}")
                            self.filter_stats["files_skipped_by_error"] += 1

                except Exception as e:
                    logger.warning(f"Error processing entry: {e}")
                    self.filter_stats["files_skipped_by_error"] += 1

        # Start processing from root
        try:
            root_dir = fs_info.open_dir(path="/")
            process_directory(root_dir)
        except Exception as e:
            logger.error(f"Error opening root directory: {e}")

        return processed_count


class LargeContainerProcessor:
    """Main processor for large container files"""

    def __init__(self):
        self.storage = StorageMinio()
        self.progress_tracker = ContainerProgress()
        self.extractors = {
            ContainerType.ZIP: ZipContainerExtractor,
            ContainerType.DD_IMAGE: DDImageContainerExtractor,
        }

        # Get postgres connection string from Dapr secrets
        self.postgres_connection_string = get_postgres_connection_str()

    def create_container_record(
        self,
        container_id: str,
        container_type: str,
        file_metadata: dict[str, Any],
        estimated_files: int,
        estimated_size: int,
    ) -> None:
        """Create initial container processing record in database"""
        try:
            with psycopg.connect(self.postgres_connection_string) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO container_processing (
                            container_id, container_type, original_filename, original_size,
                            agent_id, source, project, status, workflows_total,
                            processing_started_at, expiration
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                        (
                            container_id,
                            container_type,
                            file_metadata.get("filename", os.path.basename(file_metadata.get("path", ""))),
                            file_metadata.get("size", 0),
                            file_metadata.get("agent_id"),
                            file_metadata.get("source"),
                            file_metadata.get("project"),
                            ContainerStatus.PROCESSING,
                            estimated_files,
                            datetime.now(),
                            file_metadata.get("expiration"),
                        ),
                    )
                    conn.commit()

            logger.info(
                "Created container processing record", container_id=container_id, estimated_files=estimated_files
            )
        except Exception as e:
            logger.error(f"Error creating container record: {e}", container_id=container_id)
            raise

    def update_container_extraction_progress(
        self, container_id: str, total_files_extracted: int, total_bytes_extracted: int
    ) -> None:
        """Update container extraction progress in database"""
        try:
            with psycopg.connect(self.postgres_connection_string) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE container_processing
                        SET total_files_extracted = %s,
                            total_bytes_extracted = %s,
                            status = %s
                        WHERE container_id = %s
                    """,
                        (total_files_extracted, total_bytes_extracted, ContainerStatus.EXTRACTED, container_id),
                    )
                    conn.commit()

            logger.debug(
                "Updated container extraction progress",
                container_id=container_id,
                files_extracted=total_files_extracted,
            )
        except Exception as e:
            logger.error(f"Error updating container extraction progress: {e}", container_id=container_id)

    def update_container_workflow_progress(
        self, container_id: str, file_size: int = 0, increment_completed: bool = False, increment_failed: bool = False
    ) -> bool:
        """Update workflow completion progress and return True if all workflows are complete"""
        try:
            with psycopg.connect(self.postgres_connection_string) as conn:
                with conn.cursor() as cur:
                    # Update counters and bytes processed (only for completed workflows)
                    if increment_completed:
                        cur.execute(
                            """
                            UPDATE container_processing
                            SET workflows_completed = workflows_completed + 1,
                                total_bytes_processed = total_bytes_processed + %s
                            WHERE container_id = %s
                        """,
                            (file_size, container_id),
                        )
                    elif increment_failed:
                        cur.execute(
                            """
                            UPDATE container_processing
                            SET workflows_failed = workflows_failed + 1
                            WHERE container_id = %s
                        """,
                            (container_id,),
                        )

                    # Check if all workflows are complete
                    cur.execute(
                        """
                        SELECT workflows_completed, workflows_failed, workflows_total
                        FROM container_processing
                        WHERE container_id = %s
                    """,
                        (container_id,),
                    )

                    row = cur.fetchone()
                    if row:
                        completed, failed, total = row
                        all_complete = (completed + failed) >= total

                        if all_complete:
                            cur.execute(
                                """
                                UPDATE container_processing
                                SET status = %s, processing_completed_at = %s
                                WHERE container_id = %s
                            """,
                                (ContainerStatus.WORKFLOWS_COMPLETE, datetime.now(), container_id),
                            )

                            logger.info(
                                "Container processing completed",
                                container_id=container_id,
                                completed=completed,
                                failed=failed,
                                total=total,
                            )

                        conn.commit()
                        return all_complete

                    conn.commit()
                    return False

        except Exception as e:
            logger.error(f"Error updating workflow progress: {e}", container_id=container_id)
            return False

    def get_container_status(self, container_id: str) -> dict[str, Any] | None:
        """Get container status from database"""
        try:
            with psycopg.connect(self.postgres_connection_string) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT container_id, container_type, status, total_files_extracted,
                               total_bytes_extracted, total_bytes_processed, workflows_completed,
                               workflows_failed, workflows_total, processing_started_at, processing_completed_at
                        FROM container_processing
                        WHERE container_id = %s
                    """,
                        (container_id,),
                    )

                    row = cur.fetchone()
                    if row:
                        return {
                            "container_id": row[0],
                            "container_type": row[1],
                            "status": row[2],
                            "total_files_extracted": row[3],
                            "total_bytes_extracted": row[4],
                            "total_bytes_processed": row[5],
                            "workflows_completed": row[6],
                            "workflows_failed": row[7],
                            "workflows_total": row[8],
                            "processing_started_at": row[9].isoformat() if row[9] else None,
                            "processing_completed_at": row[10].isoformat() if row[10] else None,
                        }
                    return None
        except Exception as e:
            logger.error(f"Error getting container status: {e}", container_id=container_id)
            return None

    def detect_container_type(self, filename: str, container_file_path: Path) -> str | None:
        """Detect container type from file path"""
        filename_lower = filename.lower()

        # Check ZIP files by extension first
        if filename_lower.endswith(".zip"):
            return ContainerType.ZIP

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
            return ContainerType.DD_IMAGE

        # For unknown extensions, check file content
        try:
            if zipfile.is_zipfile(container_file_path):
                return ContainerType.ZIP
        except Exception as e:
            logger.warning(f"Error detecting container type: {e}")

        return None

    def process_container_from_path(self, container_id: str, file_path: Path, metadata: dict) -> dict[str, Any]:
        """Process a container file from a filesystem path."""
        try:
            # Detect container type
            container_type = self.detect_container_type(metadata.get("filename", file_path.name), file_path)

            if not container_type:
                raise HTTPException(status_code=400, detail="Unsupported container type")

            # Get appropriate extractor
            #   TODO: error if the container isn't detected properly?
            extractor_class = self.extractors[container_type]

            with DaprClient() as dapr_client:
                extractor = extractor_class(self.storage, dapr_client, self.progress_tracker)
                extractor.set_container_info(container_id, metadata)

                # Estimate contents for progress tracking and create database record
                file_count, total_size = extractor.estimate_container_contents(file_path)

                logger.debug(f"Estimated container contents: {file_count} files, {total_size} bytes")

                self.create_container_record(container_id, container_type, metadata, file_count, total_size)

                # Initialize in-memory progress tracking
                self.progress_tracker.initialize(container_id, file_count, total_size)

                # Store container info for tracking
                self.progress_tracker.set_container_info(container_id, {"container_id": container_id})

                # Process the container
                processed_files = extractor.extract_and_process(file_path)

                # Update extraction completion in database
                progress = self.progress_tracker.get_progress(container_id)
                if progress:
                    self.update_container_extraction_progress(
                        container_id, processed_files, progress["processed_bytes"]
                    )

                return {
                    "container_id": container_id,
                    "container_type": container_type,
                    "processed_files": processed_files,
                    "estimated_files": file_count,
                    "estimated_size": total_size,
                    "status": ContainerStatus.EXTRACTED,
                }

        except Exception as e:
            logger.exception(f"Error processing container {container_id}: {e}")
            raise

    def get_container_progress(self, container_id: str) -> dict[str, Any]:
        """Get processing progress for a container"""
        progress = self.progress_tracker.get_progress(container_id)
        if not progress:
            return {"error": "Container not found or processing not started"}

        total_files = progress["total_files"]
        processed_files = progress["processed_files"]
        total_bytes = progress["total_bytes"]
        processed_bytes = progress["processed_bytes"]

        file_progress = (processed_files / total_files * 100) if total_files > 0 else 0
        byte_progress = (processed_bytes / total_bytes * 100) if total_bytes > 0 else 0

        return {
            "container_id": container_id,
            "progress_percent_files": round(file_progress, 2),
            "progress_percent_bytes": round(byte_progress, 2),
            "processed_files": processed_files,
            "total_files": total_files,
            "processed_bytes": processed_bytes,
            "total_bytes": total_bytes,
            "current_file": progress.get("current_file"),
            "started_at": progress["started_at"].isoformat(),
        }

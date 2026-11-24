import asyncio
import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

import plyvel
from cli.c2_download_state import (
    DownloadStateStore,
    PermanentDownloadError,
    TransientDownloadError,
    classify_download_error,
    classify_upload_error,
    ensure_complete_size,
    remote_file_path,
)
from cli.c2_ids import is_safe_c2_id
from cli.c2_metadata import collection_times, join_remote_path
from cli.cobaltstrike_connector.cobaltstrike_client import Beacon, CobaltStrikeClient, Download
from cli.nemesis_client import PreviewUploadResult, UploadClient
from common.models2.api import FileMetadata, FileWithMetadataResponse

logger = logging.getLogger(__name__)


@dataclass
class DownloadedFileInfo:
    file_path: Path | None
    delete_after: bool
    success: bool
    temp_file: Path | None = None

    def __post_init__(self):
        # Track temp file separately for cleanup
        if self.delete_after and self.file_path:
            self.temp_file = self.file_path


class CobaltStrikeDownloadProcessor:
    """Processes and tracks downloads from Cobalt Strike, uploading them to Nemesis.

    This class handles the lifecycle of downloads from Cobalt Strike:
    - Retrieves files directly from the Cobalt Strike REST API
    - Records finished downloads so they are never processed twice
    - Schedules retries with backoff for transient failures
    - Uploads files to Nemesis
    """

    def __init__(
        self,
        db_path: Path,
        nemesis: UploadClient,
        project: str,
        cobalt_strike: CobaltStrikeClient | None = None,
        *,
        agent_id: str = "cobaltstrike",
        max_file_size: int | None = None,
        expiration_days: int = 100,
    ):
        """Initialize with LevelDB path and optional components

        Args:
            db_path: Path to LevelDB database
            nemesis: Configured NemesisClient instance
            project: Name of the project
            cobalt_strike: Configured CobaltStrikeClient instance
            agent_id: Agent identifier sent with uploads
            max_file_size: Skip downloads larger than this many bytes
            expiration_days: Days after collection until Nemesis deletes the file
        """

        # Check that cobalt_strike client is configured
        if not cobalt_strike:
            raise ValueError("cobalt_strike is required")

        logger.info("Using Cobalt Strike API to obtain downloads")

        if not nemesis:
            raise ValueError("NemesisClient is required")

        self.project = project
        self.agent_id = agent_id
        self.max_file_size = max_file_size
        self.expiration_days = expiration_days
        self.client = nemesis
        self.cobalt_strike = cobalt_strike
        self.db = plyvel.DB(str(db_path), create_if_missing=True)
        self.state = DownloadStateStore(self.db)

    def is_processed(self, download: Download) -> bool:
        """True once the download is finished: uploaded, or failed permanently."""
        return self.state.is_finished(download.id)

    def is_due(self, download: Download) -> bool:
        """True if the download should be queued now (not finished and not waiting out a retry delay)."""
        return self.state.is_due(download.id)

    def mark_processed(
        self,
        download: Download,
        success: bool = True,
        response: FileWithMetadataResponse | PreviewUploadResult | None = None,
        error: str | None = None,
    ):
        """Record the download as finished so it is never queued again."""
        uploaded = isinstance(response, FileWithMetadataResponse)
        self.state.mark_finished(
            download.id,
            {
                "download_info": f"{download.id} - {download.bid}",
                "success": success,
                "file_path": str(download.id),
                "object_id": str(response.object_id) if uploaded else None,
                "submission_id": str(response.submission_id) if uploaded else None,
                "error": error,
            },
        )

    def record_retry(self, download: Download, error: str) -> None:
        """Schedule another attempt after a transient failure."""
        state = self.state.record_transient_failure(download.id, error)
        logger.warning(
            "Cobalt Strike download %s failed (attempt %s); retrying later: %s", download.id, state["attempts"], error
        )

    async def upload_file(
        self,
        file_path: Path | str,
        metadata: FileMetadata,
        delete_after: bool = False,
    ) -> tuple[bool, str | None, FileWithMetadataResponse | PreviewUploadResult | None]:
        """Upload file with metadata to the API endpoint"""
        if not self.client:
            raise ValueError("NemesisClient is required")

        try:
            if not os.access(file_path, os.R_OK):
                raise PermissionError(f"No read permission for {file_path}")

            response = await self.client.post_file(str(file_path), metadata)

            if isinstance(response, (FileWithMetadataResponse, PreviewUploadResult)):
                return True, None, response
            elif response is None:
                return False, "Upload failed: No response from server", None
            else:
                return False, f"Upload failed: {response.detail}", None

        except PermissionError:
            return False, f"Permission denied: {file_path}", None
        except FileNotFoundError:
            return False, f"File not found: {file_path}", None
        except Exception as e:
            return False, f"Unexpected error with {file_path}: {str(e)}", None
        finally:
            if delete_after:
                try:
                    os.unlink(file_path)
                except Exception as e:
                    logger.error(f"Failed to delete temporary file {file_path} in upload_file finally block: {e}")

    async def process_cobaltstrike_download(self, download: Download, beacon: Beacon | None) -> None:
        """Download a file from Cobalt Strike and upload it to Nemesis.

        Success and permanent failures finish the download; transient failures schedule a retry.

        Args:
            download: Download object containing download information
            beacon: Beacon the download came from, or None if Cobalt Strike no longer lists it
        """
        logger.debug(f"Processing Cobalt Strike download {download.id}. Path: {download.path}")

        if self.is_processed(download):
            return

        if not is_safe_c2_id(download.id):
            logger.error(f"Skipping Cobalt Strike download with unsafe ID {download.id!r} (path: {download.path})")
            self.mark_processed(download, success=False, error="unsafe download ID")
            return

        size = getattr(download, "size", None)
        if self.max_file_size is not None and isinstance(size, int) and size > self.max_file_size:
            logger.warning(
                "Skipping Cobalt Strike download %s: %s bytes exceeds max_file_size %s",
                download.id,
                size,
                self.max_file_size,
            )
            self.mark_processed(download, success=False, error="file exceeds max_file_size")
            return

        downloaded_file_info: DownloadedFileInfo | None = None
        try:
            downloaded_file_info = await self._get_downloaded_file(download)
            if not downloaded_file_info.success or downloaded_file_info.file_path is None:
                raise TransientDownloadError(f"Cobalt Strike download {download.id} is not available yet")
            ensure_complete_size(downloaded_file_info.file_path, getattr(download, "size", None))

            # Use the beacon computer as the source identifier
            source = f"host://{beacon.computer}" if beacon and beacon.computer else None
            timestamp, expiration = collection_times(getattr(download, "timestamp", None), self.expiration_days)

            metadata = FileMetadata(
                agent_id=self.agent_id,
                source=source,
                project=self.project,
                timestamp=timestamp,
                expiration=expiration,
                path=remote_file_path(download.path, download.name, join_remote_path),
            )
            success, error, response = await self.upload_file(
                str(downloaded_file_info.file_path),
                metadata,
                delete_after=downloaded_file_info.delete_after,
            )

            if not (success and response):
                raise classify_upload_error(error)(f"Failed to upload {downloaded_file_info.file_path}: {error}")

            if isinstance(response, PreviewUploadResult):
                logger.info("Dry run preview complete for %s", downloaded_file_info.file_path)
            else:
                logger.info(
                    f"Successfully uploaded {downloaded_file_info.file_path} - "
                    f"Object ID: {response.object_id}, Submission ID: {response.submission_id}"
                )
            self.mark_processed(download, success=True, response=response)

        except asyncio.CancelledError:
            raise
        except Exception as e:
            if classify_download_error(e) is PermanentDownloadError:
                logger.error(f"Cobalt Strike download {download.id} failed permanently: {e}")
                self.mark_processed(download, success=False, error=str(e))
            else:
                self.record_retry(download, str(e) or type(e).__name__)
        finally:
            if downloaded_file_info is not None:
                self._cleanup_temp_file(downloaded_file_info.temp_file)

    async def _get_downloaded_file(self, download: Download) -> DownloadedFileInfo:
        """Get the download file from C2 API.

        Returns:
            FileInfo containing the downloaded file path

        Raises:
            PermanentDownloadError / TransientDownloadError, or the client's exception
        """
        # Use the API to download the file
        return await self._download_from_c2(download)

    async def _download_from_c2(self, download: Download) -> DownloadedFileInfo:
        """Download file from C2 server to a temporary location, removing it if the download fails.

        Returns:
            FileInfo containing temporary file path
        """
        if not self.cobalt_strike:
            raise ValueError("No CobaltStrikeClient configured for remote download")

        if not is_safe_c2_id(download.id):
            raise PermanentDownloadError(f"Refusing to download Cobalt Strike file with unsafe ID {download.id!r}")

        temp_fd, temp_path = tempfile.mkstemp(prefix=f"nemesis_{download.id}_")
        os.close(temp_fd)
        temp_file = Path(temp_path)

        logger.info(f"Downloading file from C2 to {temp_file}")
        try:
            success = await self.cobalt_strike.download_file(download.id, str(temp_file), max_bytes=self.max_file_size)
            if not success:
                raise TransientDownloadError(
                    f"Failed to download file from C2. Download ID: {download.id}. Download Path: {download.path}"
                )
        except BaseException:
            self._cleanup_temp_file(temp_file)
            raise

        return DownloadedFileInfo(temp_file, delete_after=True, success=True)

    def _cleanup_temp_file(self, temp_file: Path | None) -> None:
        """Clean up temporary file if it exists and hasn't been cleaned up already.
        Silently ignores if the file doesn't exist, as it may have been cleaned up
        by the upload_file method."""
        if temp_file:
            try:
                temp_file.unlink(missing_ok=True)
            except Exception as e:
                logger.warning(f"Note: Temporary file {temp_file} cleanup error: {e}")

    def close(self):
        """Close the LevelDB connection"""
        self.db.close()

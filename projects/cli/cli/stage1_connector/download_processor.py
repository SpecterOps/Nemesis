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
from cli.c2_ids import is_safe_c2_id, safe_child_path
from cli.c2_metadata import collection_times, join_remote_path
from cli.nemesis_client import PreviewUploadResult, UploadClient
from cli.stage1_connector.outflankc2_client import Download, Implant, OutflankC2Client
from common.models2.api import UNKNOWN_SOURCE, FileMetadata, FileWithMetadataResponse

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


class OutflankDownloadProcessor:
    """Processes and tracks downloads from Outflank C2, uploading them to Nemesis.

    This class handles the lifecycle of downloads from Outflank C2:
    - Retrieves files either from a local directory or directly from the C2 server's API
    - Tracks processed downloads to prevent duplicate processing
    - Uploads files to Nemesis

    The processor can work in two modes:
    1. Local directory mode: Monitors a specified directory for downloaded files
    2. API mode: Downloads files directly from the Outflank C2 server

    """

    def __init__(
        self,
        db_path: Path,
        nemesis: UploadClient,
        project: str,
        outflank_downloads_dir_path: Path | None = None,
        outflank: OutflankC2Client | None = None,
        *,
        agent_id: str = "stage1",
        max_file_size: int | None = None,
        expiration_days: int = 100,
    ):
        """Initialize with LevelDB path and optional components

        Args:
            db_path: Path to LevelDB database
            nemesis: Optional configured NemesisClient instance
            project: name of the project
            outflank_downloads_dir_path: Optional directory containing downloaded files (e.g. /opt/stage1/shared/downloads)
            outflank: Optional configured OutflankC2Client instance
            agent_id: Agent identifier sent with uploads
            max_file_size: Skip downloads larger than this many bytes
            expiration_days: Days after collection until Nemesis deletes the file
        """

        # Check that either outflank_downloads_dir_path exists or outflank client is configured
        if not outflank_downloads_dir_path and not outflank:
            raise ValueError("Either outflank_downloads_dir_path or outflank_client is required")
        if outflank_downloads_dir_path and outflank:
            raise ValueError("Only one of outflank_downloads_dir_path or outflank_client can be provided")

        if outflank_downloads_dir_path:
            logger.info(f"Using Outflank directory to obtain downloads: {outflank_downloads_dir_path}")
        else:
            logger.info("Using OutflankC2 API to obtain downloads")

        if outflank_downloads_dir_path and not outflank_downloads_dir_path.exists():
            raise FileNotFoundError(f"Directory does not exist: {outflank_downloads_dir_path}")

        if not nemesis:
            raise ValueError("NemesisClient is required")

        self.outflank_downloads_dir_path = outflank_downloads_dir_path
        self.project = project
        self.agent_id = agent_id
        self.max_file_size = max_file_size
        self.expiration_days = expiration_days
        self.client = nemesis
        self.outflank = outflank
        self.db = plyvel.DB(str(db_path), create_if_missing=True)
        self.state = DownloadStateStore(self.db)

    def is_processed(self, download: Download) -> bool:
        """True once the download is finished: uploaded, or failed permanently."""
        return self.state.is_finished(download.uid)

    def is_due(self, download: Download) -> bool:
        """True if the download should be queued now (not finished and not waiting out a retry delay)."""
        return self.state.is_due(download.uid)

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
            download.uid,
            {
                "download_info": f"{download.uid} - {download.implant_uid}",
                "success": success,
                "file_path": str(download.uid),
                "object_id": str(response.object_id) if uploaded else None,
                "submission_id": str(response.submission_id) if uploaded else None,
                "error": error,
            },
        )

    def record_retry(self, download: Download, error: str) -> None:
        """Schedule another attempt after a transient failure."""
        state = self.state.record_transient_failure(download.uid, error)
        logger.warning(
            "Outflank download %s failed (attempt %s); retrying later: %s", download.uid, state["attempts"], error
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

    async def process_outflank_download(self, download: Download, implant: Implant | None) -> None:
        """Fetch a download (local directory or C2 API) and upload it to Nemesis.

        Success and permanent failures finish the download; transient failures schedule a retry.

        Args:
            download: Download object containing download information
            implant: Implant the download came from, or None if Outflank no longer lists it
        """
        logger.debug(f"Processing Outflank download {download.uid}. Path: {download.path}")

        if self.is_processed(download):
            return

        if not is_safe_c2_id(download.uid):
            logger.error(f"Skipping Outflank download with unsafe UID {download.uid!r} (path: {download.path})")
            self.mark_processed(download, success=False, error="unsafe download UID")
            return

        size = getattr(download, "size", None)
        if self.max_file_size is not None and isinstance(size, int) and size > self.max_file_size:
            logger.warning(
                "Skipping Outflank download %s: %s bytes exceeds max_file_size %s",
                download.uid,
                size,
                self.max_file_size,
            )
            self.mark_processed(download, success=False, error="file exceeds max_file_size")
            return

        downloaded_file_info: DownloadedFileInfo | None = None
        try:
            downloaded_file_info = await self._get_downloaded_file(download)
            if not downloaded_file_info.success or downloaded_file_info.file_path is None:
                raise TransientDownloadError(f"Outflank download {download.uid} is not available yet")
            ensure_complete_size(downloaded_file_info.file_path, getattr(download, "size", None))

            # Use the implant hostname as the source identifier, falling back to the download's own record
            hostname = (implant.hostname if implant else None) or getattr(download, "implant_hostname", None)
            source = f"host://{hostname}" if hostname else UNKNOWN_SOURCE
            timestamp, expiration = collection_times(getattr(download, "timestamp", None), self.expiration_days)

            metadata = FileMetadata(
                agent_id=self.agent_id,
                source=source,
                project=self.project,
                timestamp=timestamp,
                expiration=expiration,
                path=remote_file_path(str(download.path), getattr(download, "name", None), join_remote_path),
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
                logger.error(f"Outflank download {download.uid} failed permanently: {e}")
                self.mark_processed(download, success=False, error=str(e))
            else:
                self.record_retry(download, str(e) or type(e).__name__)
        finally:
            if downloaded_file_info is not None:
                self._cleanup_temp_file(downloaded_file_info.temp_file)

    async def _get_downloaded_file(self, download: Download) -> DownloadedFileInfo:
        """Get the download file either from local directory or C2.

        Returns:
            FileInfo containing the file path and whether to delete it after upload

        Raises:
            PermanentDownloadError / TransientDownloadError, or the client's exception
        """
        # Check local directory first if configured
        if self.outflank_downloads_dir_path:
            file_path = safe_child_path(self.outflank_downloads_dir_path, download.uid)
            if file_path is None:
                raise PermanentDownloadError(
                    f"Refusing Outflank download UID {download.uid!r}: path escapes the downloads directory"
                )
            if not file_path.is_file():
                # Not written yet (or still being moved into place); try again later.
                raise TransientDownloadError(
                    f"Downloaded file not found locally yet. Local Path: {file_path}. "
                    f"Download path: {download.path}. Download UID: {download.uid}"
                )
            if self.max_file_size is not None and file_path.stat().st_size > self.max_file_size:
                raise PermanentDownloadError(
                    f"{file_path} is {file_path.stat().st_size} bytes; max_file_size is {self.max_file_size}"
                )

            return DownloadedFileInfo(file_path, delete_after=False, success=True)
        # Use the API to download the file
        else:
            return await self._download_from_c2(download)

    async def _download_from_c2(self, download: Download) -> DownloadedFileInfo:
        """Download file from C2 server to a temporary location, removing it if the download fails.

        Returns:
            FileInfo containing temporary file path
        """
        if not self.outflank:
            raise ValueError("No OutflankC2Client configured for remote download")

        if not is_safe_c2_id(download.uid):
            raise PermanentDownloadError(f"Refusing to download Outflank file with unsafe UID {download.uid!r}")

        temp_fd, temp_path = tempfile.mkstemp(prefix=f"nemesis_{download.uid}_")
        os.close(temp_fd)
        temp_file = Path(temp_path)

        logger.info(f"Downloading file from C2 to {temp_file}")
        try:
            success = await self.outflank.download_file(download.uid, str(temp_file), max_bytes=self.max_file_size)
            if not success:
                raise TransientDownloadError(
                    f"Failed to download file from C2. Download UID: {download.uid}. Download Path: {download.path}"
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

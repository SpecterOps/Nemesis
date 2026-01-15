import json
import logging
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Union

import plyvel
from cli.nemesis_client import NemesisClient
from cli.stage1_connector.outflankc2_client import Download, Implant, OutflankC2Client
from common.models.api import FileMetadata, FileWithMetadataResponse

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
        nemesis: NemesisClient,
        project: str,
        outflank_downloads_dir_path: Path | None = None,
        outflank: OutflankC2Client | None = None,
    ):
        """Initialize with LevelDB path and optional components

        Args:
            db_path: Path to LevelDB database
            nemesis: Optional configured NemesisClient instance
            project: name of the project
            outflank_downloads_dir_path: Optional directory containing downloaded files (e.g. /opt/stage1/shared/downloads)
            outflank: Optional configured OutflankC2Client instance
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
        self.client = nemesis
        self.outflank = outflank
        self.db = plyvel.DB(str(db_path), create_if_missing=True)

    def is_processed(self, download: Download) -> bool:
        """Check if download has been processed"""
        key = f"download:{download.uid}".encode()
        return self.db.get(key) is not None

    def mark_processed(
        self, download: Download, success: bool = True, response: FileWithMetadataResponse | None = None
    ):
        """Mark download as processed"""
        key = f"download:{download.uid}".encode()
        value = json.dumps(
            {
                "timestamp": datetime.now().isoformat(),
                "download_info": f"{download.uid} - {download.implant_uid}",
                "success": success,
                "file_path": str(download.uid),
                "object_id": str(response.object_id) if response else None,
                "submission_id": str(response.submission_id) if response else None,
            }
        ).encode()
        self.db.put(key, value)

    async def upload_file(
        self,
        file_path: Union[Path, str],
        metadata: FileMetadata,
        delete_after: bool = False,
    ) -> tuple[bool, str | None, FileWithMetadataResponse | None]:
        """Upload file with metadata to the API endpoint"""
        if not self.client:
            raise ValueError("NemesisClient is required")

        try:
            if not os.access(file_path, os.R_OK):
                raise PermissionError(f"No read permission for {file_path}")

            response = self.client.post_file(str(file_path), metadata)

            if isinstance(response, FileWithMetadataResponse):
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

    async def process_outflank_download(self, download: Download, implant: Implant) -> None:
        """Process a download by either retrieving from local directory or downloading from C2.

        Args:
            download: Download object containing download information
            implant: Implant object containing host information
        """
        logger.debug(
            f"Processing Outflank download {download.uid} from implant {implant.hostname}. Path: {download.path}"
        )

        # Get the file from the downloads directory or API
        downloaded_file_info = await self._get_downloaded_file(download)
        if not downloaded_file_info.success:
            self.mark_processed(download, success=False)
            return

        # Upload the file to Nemesis
        try:
            # Use the implant hostname as the source identifier
            source = f"host://{implant.hostname}" if implant.hostname else None

            metadata = FileMetadata(
                agent_id="stage1",
                source=source,
                project=self.project,
                timestamp=datetime.now(UTC),
                expiration=datetime.now(UTC).replace(year=datetime.now().year + 1),
                path=str(download.path),
            )
            success, error, response = await self.upload_file(
                str(downloaded_file_info.file_path),
                metadata,
                delete_after=downloaded_file_info.delete_after,
            )

            if success and response:
                logger.info(
                    f"Successfully uploaded {downloaded_file_info.file_path} - "
                    f"Object ID: {response.object_id}, Submission ID: {response.submission_id}"
                )
                self.mark_processed(download, success=True, response=response)
            else:
                logger.error(f"Failed to upload {downloaded_file_info.file_path}: {error}")
                self.mark_processed(download, success=False)

        except Exception as e:
            logger.error(f"Error in process_download: {e}")
            self.mark_processed(download, success=False)
        finally:
            self._cleanup_temp_file(downloaded_file_info.temp_file)

    async def _get_downloaded_file(self, download: Download) -> DownloadedFileInfo:
        """Get the download file either from local directory or C2.

        Returns:
            FileInfo containing file path, whether to delete after, and success status
        """
        # Check local directory first if configured
        if self.outflank_downloads_dir_path:
            file_path = self.outflank_downloads_dir_path / download.uid
            if not file_path.exists():
                logger.error(
                    f"Downloaded file not found locally. Local Path: {file_path}. Downloaded file path: {download.path}. Downlaod UID: {download.uid}"
                )
                return DownloadedFileInfo(file_path, delete_after=False, success=False)

            return DownloadedFileInfo(file_path, delete_after=False, success=True)
        # Use the API to download the file
        else:
            return await self._download_from_c2(download)

    async def _download_from_c2(self, download: Download) -> DownloadedFileInfo:
        """Download file from C2 server to temporary location.

        Returns:
            FileInfo containing temporary file path and success status
        """
        if not self.outflank:
            raise ValueError("No OutflankC2Client configured for remote download")

        temp_fd, temp_path = tempfile.mkstemp(prefix=f"nemesis_{download.uid}_")
        os.close(temp_fd)
        temp_file = Path(temp_path)

        logger.info(f"Downloading file from C2 to {temp_file}")
        success = await self.outflank.download_file(download.uid, str(temp_file))

        if not success:
            logger.error(
                "Failed to download file from C2. Download UID: {download.uid}. Download Path: {download.path}"
            )
            return DownloadedFileInfo(temp_file, delete_after=True, success=False)

        return DownloadedFileInfo(temp_file, delete_after=True, success=True)

    def _cleanup_temp_file(self, temp_file: Path | None) -> None:
        """Clean up temporary file if it exists and hasn't been cleaned up already.
        Silently ignores if the file doesn't exist, as it may have been cleaned up
        by the upload_file method."""
        if temp_file:
            try:
                temp_file.unlink(missing_ok=True)
            except Exception as e:
                logger.warn(f"Note: Temporary file {temp_file} cleanup error: {e}")

    def close(self):
        """Close the LevelDB connection"""
        self.db.close()

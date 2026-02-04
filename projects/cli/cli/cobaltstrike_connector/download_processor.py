import json
import logging
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Union

import plyvel
from cli.cobaltstrike_connector.cobaltstrike_client import Beacon, CobaltStrikeClient, Download
from cli.nemesis_client import NemesisClient
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
    - Tracks processed downloads to prevent duplicate processing
    - Uploads files to Nemesis

    """

    def __init__(
        self,
        db_path: Path,
        nemesis: NemesisClient,
        project: str,
        cobalt_strike: CobaltStrikeClient | None = None,
    ):
        """Initialize with LevelDB path and optional components

        Args:
            db_path: Path to LevelDB database
            nemesis: Configured NemesisClient instance
            project: Name of the project
            cobalt_strike: Configured CobaltStrikeClient instance
        """

        # Check that cobalt_strike client is configured
        if not cobalt_strike:
            raise ValueError("cobalt_strike is required")

        logger.info("Using Cobalt Strike API to obtain downloads")

        if not nemesis:
            raise ValueError("NemesisClient is required")

        self.project = project
        self.client = nemesis
        self.cobalt_strike = cobalt_strike
        self.db = plyvel.DB(str(db_path), create_if_missing=True)

    def is_processed(self, download: Download) -> bool:
        """Check if download has been processed"""
        key = f"download:{download.id}".encode()
        return self.db.get(key) is not None

    def mark_processed(
        self, download: Download, success: bool = True, response: FileWithMetadataResponse | None = None
    ):
        """Mark download as processed"""
        key = f"download:{download.id}".encode()
        value = json.dumps(
            {
                "timestamp": datetime.now().isoformat(),
                "download_info": f"{download.id} - {download.bid}",
                "success": success,
                "file_path": str(download.id),
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

    async def process_cobaltstrike_download(self, download: Download, beacon: Beacon) -> None:
        """Process a download by either retrieving from local directory or downloading from C2.

        Args:
            download: Download object containing download information
            beacon: Beacon object containing host information
        """
        logger.debug(
            f"Processing Cobalt Strike download {download.id} from beacon {beacon.computer}. Path: {download.path}"
        )

        # Get the file from the downloads directory or API
        downloaded_file_info = await self._get_downloaded_file(download)
        if not downloaded_file_info.success:
            self.mark_processed(download, success=False)
            return

        # Upload the file to Nemesis
        try:
            # Use the beacon computer as the source identifier
            source = f"host://{beacon.computer}" if beacon.computer else None

            metadata = FileMetadata(
                agent_id="Cobalt Strike",
                source=source,
                project=self.project,
                timestamp=datetime.now(UTC),
                expiration=datetime.now(UTC).replace(year=datetime.now().year + 1),
                path=f"{download.path}/{download.name}",
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
        """Get the download file from C2 API.

        Returns:
            FileInfo containing file path, whether to delete after, and success status
        """
        # Use the API to download the file
        return await self._download_from_c2(download)

    async def _download_from_c2(self, download: Download) -> DownloadedFileInfo:
        """Download file from C2 server to temporary location.

        Returns:
            FileInfo containing temporary file path and success status
        """
        if not self.cobalt_strike:
            raise ValueError("No CobaltStrikeClient configured for remote download")

        temp_fd, temp_path = tempfile.mkstemp(prefix=f"nemesis_{download.id}_")
        os.close(temp_fd)
        temp_file = Path(temp_path)

        logger.info(f"Downloading file from C2 to {temp_file}")
        success = await self.cobalt_strike.download_file(download.id, str(temp_file))

        if not success:
            logger.error(f"Failed to download file from C2. Download ID: {download.id}. Download Path: {download.path}")
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

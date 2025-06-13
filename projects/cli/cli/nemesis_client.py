import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, Optional, Union

import requests
from common.models2.api import (
    APIInfo,
    ErrorResponse,
    FileMetadata,
    FileWithMetadataResponse,
    HealthResponse,
    YaraReloadResponse,
)
from requests.auth import HTTPBasicAuth
from requests_toolbelt import MultipartEncoder

from cli.config import NemesisConfig

logger = logging.getLogger(__name__)


class NemesisClient:
    def __init__(self, cfg: NemesisConfig) -> None:
        """Initialize the Nemesis client.

        Args:
            config: Application configuration
        """
        self.cfg = cfg
        self.auth = HTTPBasicAuth(
            cfg.credential.username,
            cfg.credential.password,
        )

    def create_file_metadata(self, path: str, agent_id: str, project: str) -> FileMetadata:
        """Create standardized file metadata.

        Args:
            path: File path
            agent_id: Identifier for the agent
            project: Project name

        Returns:
            FileMetadata object with standard fields
        """
        now = datetime.now(UTC)
        return FileMetadata(
            agent_id=agent_id,
            project=project,
            timestamp=now,
            expiration=now.replace(year=now.year + 1),
            path=path,
        )

    def post_file(
        self,
        file: BinaryIO | str,
        metadata: FileMetadata,
    ) -> FileWithMetadataResponse | ErrorResponse:
        """Upload file to Nemesis with required metadata using streaming multipart/form-data.

        Args:
            file: Either a file path string or a binary stream containing the file data
            metadata: Required file metadata as FileMetadata object

        Returns:
            FileWithMetadataResponse if successful, ErrorResponse on error

        Raises:
            ValueError: If metadata is not provided
            FileNotFoundError: If file path doesn't exist
            PermissionError: If file path isn't readable
            requests.exceptions.RequestException: For network/API errors
        """
        if not metadata:
            raise ValueError("File metadata is required")

        file_stream = None
        need_cleanup = False

        try:
            # If given a path string, open it as a binary stream
            if isinstance(file, str):
                path = Path(file)
                if not path.exists():
                    raise FileNotFoundError(f"File not found: {file}")
                if not os.access(path, os.R_OK):
                    raise PermissionError(f"No read permission for {file}")
                file_stream = open(path, "rb")
                need_cleanup = True
            else:
                # Already a binary stream
                file_stream = file

            # Using MultipartEncoder so we can stream the upload w/o loading the entire file into memory
            encoder = MultipartEncoder(
                fields={
                    "file": ("file", file_stream, "application/octet-stream"),
                    "metadata": (None, metadata.model_dump_json(), "application/json"),
                }
            )

            # Make request with streaming data
            response = requests.post(
                f"{self.cfg.url}/api/files",
                data=encoder,
                headers={"Content-Type": encoder.content_type},
                auth=self.auth,
                verify=False,
                timeout=520,
            )

            if response.status_code != 200:
                return ErrorResponse(detail=f"Error uploading file to Nemesis: {response.status_code}")

            return FileWithMetadataResponse(**response.json())

        except (FileNotFoundError, PermissionError) as e:
            logger.error(f"File access error: {e}")
            return ErrorResponse(detail=str(e))
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error uploading file to Nemesis: {e}")
            return ErrorResponse(detail=f"Upload failed: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error uploading file to Nemesis: {e}")
            return ErrorResponse(detail=f"Unexpected error: {str(e)}")
        finally:
            # Only close the file stream if we opened it ourselves
            if need_cleanup and file_stream is not None:
                file_stream.close()

    def get_health(self) -> Optional[Union[HealthResponse, ErrorResponse]]:
        """Get API health status.

        Returns:
            HealthResponse if successful, ErrorResponse on error, None on exception
        """
        try:
            response = requests.get(f"{self.cfg.url}/api/healthz", auth=self.auth, verify=False)

            if response.status_code != 200:
                return ErrorResponse(detail=f"Error getting health status: {response.status_code}")

            return HealthResponse(**response.json())

        except Exception as e:
            logger.error(f"Error getting health status: {e}")
            return None

    def get_api_info(self) -> Optional[Union[APIInfo, ErrorResponse]]:
        """Get API information.

        Returns:
            APIInfo if successful, ErrorResponse on error, None on exception
        """
        try:
            response = requests.get(f"{self.cfg.url}/api/", auth=self.auth, verify=False)

            if response.status_code != 200:
                return ErrorResponse(detail=f"Error getting API info: {response.status_code}")

            return APIInfo(**response.json())

        except Exception as e:
            logger.error(f"Error getting API info: {e}")
            return None

    def reload_yara_rules(self) -> Optional[Union[YaraReloadResponse, ErrorResponse]]:
        """Reload Yara rules.

        Returns:
            YaraReloadResponse if successful, ErrorResponse on error, None on exception
        """
        try:
            response = requests.post(f"{self.cfg.url}/api/yara/reload", auth=self.auth, verify=False)

            if response.status_code != 200:
                return ErrorResponse(detail=f"Error reloading Yara rules: {response.status_code}")

            return YaraReloadResponse(**response.json())

        except Exception as e:
            logger.error(f"Error reloading Yara rules: {e}")
            return None

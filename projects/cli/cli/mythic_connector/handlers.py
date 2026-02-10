import base64
import os
import tempfile
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import urllib3
from cli.mythic_connector.config import Settings
from cli.mythic_connector.db import Database
from cli.mythic_connector.logger import get_logger

# from cli.mythic_connector.nemesis import NemesisClient
from cli.nemesis_client import NemesisClient
from common.models.api import FileMetadata, FileWithMetadataResponse
from mythic import mythic, mythic_classes

logger = get_logger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FileHandler:
    """Handles synchronization of downloaded files from Mythic to Nemesis.

    This class manages the processing of file downloads, including tracking
    which files have been processed and uploading them to Nemesis. It uses
    a subscription-based approach to receive new file downloads from Mythic
    in real-time and processes them sequentially.
    """

    def __init__(self, mythic: mythic_classes.Mythic, nemesis: NemesisClient, db: Database, config: Settings):
        """Initialize the file handler.

        Args:
            mythic: Authenticated Mythic client instance
            nemesis: Nemesis API client
            db: Database connection
            config: Application configuration
        """
        self.mythic = mythic
        self.nemesis = nemesis
        self.db = db
        self.cfg = config
        self._successful_files_count = 0
        self._total_files_count = 0

    def _convert_timestamp(self, timestamp: str, days_to_add: int = 0) -> str:
        """Convert timestamp to a standard format.

        Args:
            timestamp: Input timestamp string
            days_to_add: Optional number of days to add

        Returns:
            Formatted timestamp string
        """
        dt = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f")
        if days_to_add:
            dt += timedelta(days=days_to_add)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def _build_metadata(self, file_meta: dict[str, Any]) -> dict[str, Any]:
        """Build metadata dictionary for Nemesis.

        Args:
            file_meta: File metadata from Mythic

        Returns:
            Formatted metadata dictionary
        """
        return {
            "agent_id": file_meta["task"]["callback"]["agent_callback_id"],
            "agent_type": "mythic",
            "automated": True,
            "data_type": "file_data",
            "expiration": self._convert_timestamp(file_meta["timestamp"], self.cfg.nemesis.expiration_days),
            "project": file_meta["task"]["callback"]["operation"]["name"],
            "timestamp": self._convert_timestamp(file_meta["timestamp"]),
        }

    def _build_file_data(self, file_meta: dict[str, Any], file_size: int, nemesis_id: str) -> dict[str, Any]:
        """Build file data dictionary for Nemesis.

        Args:
            file_meta: File metadata from Mythic
            file_size: Size of the file in bytes
            nemesis_id: Nemesis object ID

        Returns:
            Formatted file data dictionary
        """
        return {
            "path": base64.b64decode(file_meta["full_remote_path_text"]).decode("utf-8").replace("\\", "/"),
            "size": file_size,
            "object_id": nemesis_id,
        }

    def _check_file_size(self, file_meta: dict[str, Any]) -> bool:
        """Check if the file size is within configured limits.

        Args:
            file_meta: File metadata from Mythic

        Returns:
            True if file size is acceptable, False otherwise
        """
        # try:
        #     chunk_size = int(file_meta["chunk_size"])
        #     chunks_received = int(file_meta["chunks_received"])
        #     estimated_size = chunk_size * chunks_received

        #     return estimated_size <= self.cfg.max_file_size
        # except (KeyError, ValueError, TypeError):
        #     # If we can't determine the size, err on the side of processing
        return True

    def _is_file_processed(self, agent_file_id: str) -> bool:
        cache_key = f"filemeta{agent_file_id}"
        return self.db.get(cache_key) is None

    def _mark_processed(self, agent_file_id: str) -> None:
        cache_key = f"filemeta{agent_file_id}"
        self.db.mset({cache_key: 1})

    async def download_file(self, mythic_file_id: str, download_callback: Callable[[str], Awaitable[Any]]) -> None:
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "wb") as temp_file:
                async for chunk in mythic.download_file_chunked(mythic=self.mythic, file_uuid=mythic_file_id):
                    temp_file.write(chunk)
                temp_file.flush()

            download_callback(path)
        finally:
            os.remove(path)

    async def handle_file(self, file_meta: dict[str, Any]) -> None:
        """Process a single file download from Mythic.

        This method handles the complete workflow of processing a file:
        1. Checks if the file has already been processed
        2. Validates the file size
        3. Downloads the file from Mythic
        4. Uploads the file to Nemesis
        5. Creates and uploads the associated metadata
        6. Updates the processing state in the database

        Args:
            file_meta: File metadata from Mythic
        """
        try:
            agent_file_id = file_meta["agent_file_id"]
            file_id = file_meta["id"]
            file_name = base64.b64decode(file_meta["filename_text"]).decode("utf-8")
            path = base64.b64decode(file_meta["full_remote_path_text"]).decode("utf-8")

            logger.debug(f"Processing file. ID: {file_id}. Name: {file_name}. Agent ID: {agent_file_id}")

            if not self._is_file_processed(agent_file_id):
                logger.debug(f"File {agent_file_id} already processed, skipping")
                return

            # Check file size before downloading
            if not self._check_file_size(file_meta):
                logger.warning(
                    f"Skipping uploading file '{file_name}' (UUID: {agent_file_id}). Exceeds Nemesis max size limit of {self.cfg.nemesis.max_file_size} bytes"
                )
                return

            # Download and process file
            # file_bytes = await mythic.download_file(mythic=self.mythic, file_uuid=agent_file_id)

            async def upload_to_nemesis(file_path: str) -> None:
                """Callback to upload the downloaded file to Nemesis."""

                self._total_files_count += 1
                # Use the host field as the source identifier
                source = f"host://{file_meta.get('host', 'unknown')}"

                metadata = FileMetadata(
                    agent_id="mythic",
                    source=source,
                    project=self.cfg.project,
                    timestamp=datetime.now(UTC),
                    expiration=datetime.now(UTC).replace(year=datetime.now().year + 1),
                    path=str(path),
                )

                response = self.nemesis.post_file(file_path, metadata)

                if isinstance(response, FileWithMetadataResponse):
                    self._mark_processed(agent_file_id)
                    self._successful_files_count += 1
                    logger.info(
                        f"Successfully processed file {agent_file_id} (Nemesis ID: {response.object_id}) - {self._successful_files_count}/{self._total_files_count} files processed"
                    )

                elif response is None:
                    logger.warning("Upload failed: No response from server")
                else:
                    logger.error(f"Upload failed: {response.detail}")

                # Update the last processed file ID in the DB
                last_file_id = self.db.get("last_file_id") or 0
                if file_id > last_file_id:
                    self.db.mset({"last_file_id": file_id})

            await self.download_file(agent_file_id, upload_to_nemesis)

        except Exception as e:
            logger.exception(f"Error processing file {file_meta.get('id')}: {str(e)}")

    async def subscribe(self) -> None:
        """Subscribe to file downloads from Mythic.

        This method establishes a real-time subscription to Mythic's file
        download stream and processes new files as they become available.
        It maintains the last processed file ID to ensure no files are
        missed during service restarts.

        The subscription query filters for:
        - Files downloaded from agents (is_download_from_agent)
        - Completed downloads (complete)
        - Non-screenshot files (is_screenshot)
        """

        # Define the GraphQL subscription
        subscription = """
        subscription NemesisFileSubscription {
            filemeta_stream(
                cursor: {initial_value: {id: %s}},
                batch_size: 5,
                where: {
                    is_download_from_agent: {_eq: true},
                    complete: {_eq: true},
                }
            ) {
                filename_text
                full_remote_path_text
                id
                host
                agent_file_id
                timestamp
                task {
                    callback {
                        agent_callback_id
                        operation {
                            name
                        }
                    }
                    id
                }
                tags {
                    tagtype {
                        name
                    }
                }
                chunk_size
                chunks_received
            }
        }
        """

        try:
            while True:
                # Get the last processed file ID or start from 0
                try:
                    start_id = self.db.get("last_file_id")
                    if start_id is None:
                        start_id = 0
                        self.db.mset({"last_file_id": 0})

                except Exception:
                    logger.warning("Failed to get last_file_id, starting from 0")
                    self.db.mset({"last_file_id": 0})
                    start_id = 0

                logger.info(f"Starting subscription for file data, start_id: {start_id}")

                async for data in mythic.subscribe_custom_query(
                    mythic=self.mythic,
                    query=(subscription % start_id),
                    timeout=-1,
                ):
                    # Process each file in the batch
                    for file_meta in data.get("filemeta_stream", []):
                        try:
                            await self.handle_file(file_meta)
                        except Exception as e:
                            logger.error(f"Failed to process file {file_meta.get('id')}: {str(e)}")
                            continue

                logger.info("Subscription ended. Restarting...")

        except Exception as e:
            logger.error(f"Subscription error: {str(e)}")
            # The outer loop in SyncService will handle reconnection
            raise


# class FileBrowserHandler:
#     """Handles synchronization of file browser data from Mythic to Nemesis.

#     This class manages the processing of file system information that Mythic agents
#     collect, including directory listings and file metadata. It batches related
#     information by agent ID to minimize API calls to Nemesis.
#     """

#     def __init__(self, mythic: mythic_classes.Mythic, nemesis: NemesisClient, db: Database, config: Settings):
#         """Initialize the file browser handler.

#         Args:
#             mythic: Authenticated Mythic client instance
#             nemesis: Nemesis API client
#             db: Database connection
#             config: Application configuration
#         """
#         self.mythic = mythic
#         self.nemesis = nemesis
#         self.db = db
#         self.config = config

#     def _convert_timestamp(self, timestamp: str, days_to_add: int = 0) -> str:
#         """Convert timestamp to a standard format.

#         Args:
#             timestamp: Input timestamp string
#             days_to_add: Optional number of days to add

#         Returns:
#             Formatted timestamp string
#         """
#         dt = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f")
#         if days_to_add:
#             dt += timedelta(days=days_to_add)
#         return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

#     def _convert_epoch_timestamp(self, epoch_ms: int) -> str:
#         """Convert epoch milliseconds to standard timestamp format.

#         Args:
#             epoch_ms: Timestamp in milliseconds since epoch

#         Returns:
#             Formatted timestamp string
#         """
#         return datetime.fromtimestamp(epoch_ms // 1000).strftime("%Y-%m-%dT%H:%M:%S.000Z")

#     def _build_metadata(self, file_data: dict[str, Any]) -> dict[str, Any]:
#         """Build metadata dictionary for Nemesis.

#         Args:
#             file_data: File system data from Mythic

#         Returns:
#             Formatted metadata dictionary
#         """
#         return {
#             "agent_id": file_data["task"]["callback"]["agent_callback_id"],
#             "agent_type": "mythic",
#             "automated": True,
#             "data_type": "file_information",
#             "expiration": self._convert_timestamp(file_data["timestamp"], self.config.nemesis.expiration_days),
#             "source": file_data["host"],
#             "project": file_data["task"]["callback"]["operation"]["name"],
#             "timestamp": self._convert_timestamp(file_data["timestamp"]),
#         }

#     def _build_file_data(self, file_data: dict[str, Any]) -> dict[str, Any]:
#         """Build file information dictionary for Nemesis.

#         Args:
#             file_data: File system data from Mythic

#         Returns:
#             Formatted file information dictionary
#         """
#         result = {
#             "path": file_data["full_path_text"].replace("\\", "/"),
#             "type": "folder" if file_data.get("can_have_children") else "file",
#         }

#         metadata = file_data.get("metadata", {})

#         # Add file size if available
#         if "size" in metadata:
#             result["size"] = metadata["size"]

#         # Handle timestamps
#         if "access_time" in metadata and metadata["access_time"]:
#             access_time = metadata["access_time"]
#             if isinstance(access_time, int):
#                 result["access_time"] = self._convert_epoch_timestamp(access_time)
#             else:
#                 result["access_time"] = self._convert_timestamp(access_time)

#         if "modify_time" in metadata and metadata["modify_time"]:
#             modify_time = metadata["modify_time"]
#             if isinstance(modify_time, int):
#                 result["modification_time"] = self._convert_epoch_timestamp(modify_time)
#             else:
#                 result["modification_time"] = self._convert_timestamp(modify_time)

#         # Handle Unix-style permissions
#         if (
#             "permissions" in metadata
#             and metadata["permissions"]
#             and len(metadata["permissions"]) > 0
#             and "permissions" in metadata["permissions"][0]
#             and metadata["permissions"][0]["permissions"]
#         ):
#             try:
#                 permission_data = json.loads(metadata["permissions"][0]["permissions"])
#                 if "user" in permission_data:
#                     result["owner"] = permission_data["user"]
#             except json.JSONDecodeError:
#                 logger.warning(f"Failed to parse permissions for {result['path']}")

#         return result

#     async def handle_batch(self, files: list[dict[str, Any]]) -> None:
#         """Process a batch of file system information.

#         This method groups file information by agent ID to minimize API calls
#         while maintaining data consistency.

#         Args:
#             files: List of file system entries from Mythic
#         """
#         # Group data by agent ID
#         grouped_data: dict[str, dict[str, Any]] = {}

#         for file_data in files:
#             mythic_id = file_data["id"]
#             cache_key = f"filebrowser{mythic_id}"

#             # Skip if already processed
#             if self.db.get(cache_key):
#                 continue

#             callback_id = file_data["task"]["callback"]["agent_callback_id"]

#             # Initialize group for new agent ID
#             if callback_id not in grouped_data:
#                 grouped_data[callback_id] = {"metadata": self._build_metadata(file_data), "data": []}

#             # Add file information to group
#             grouped_data[callback_id]["data"].append(self._build_file_data(file_data))

#             # Mark as processed and update last ID
#             self.db.mset({cache_key: 1})
#             last_id = self.db.get("last_filebrowser_id")
#             if last_id is None or mythic_id > last_id:
#                 self.db.mset({"last_filebrowser_id": mythic_id})

#         # Submit each group to Nemesis
#         for data in grouped_data.values():
#             resp = self.nemesis.post_data(data)
#             if resp:
#                 message_id = resp["object_id"]
#                 logger.info(f"Nemesis message_id for file listing data: {message_id}")

#     async def subscribe(self) -> None:
#         """Subscribe to file browser information from Mythic."""
#         try:
#             start_id = self.db.get("last_filebrowser_id") or 0
#         except Exception:
#             self.db.mset({"last_filebrowser_id": 0})
#             start_id = 0

#         subscription = (
#             """
#         subscription NemesisFileBrowserSubscription {
#             mythictree_stream(
#                 batch_size: 100,
#                 cursor: {initial_value: {id: %s}},
#                 where: {tree_type: {_eq: "file"}}
#             ) {
#                 id
#                 host
#                 full_path_text
#                 name_text
#                 parent_path_text
#                 timestamp
#                 can_have_children
#                 task {
#                     callback {
#                         agent_callback_id
#                         operation {
#                             name
#                         }
#                     }
#                     id
#                 }
#                 metadata
#             }
#         }
#         """  # noqa: UP031
#             % start_id
#         )

#         logger.info(f"Starting subscription for file browser information, start_id: {start_id}")

#         async for data in mythic.subscribe_custom_query(mythic=self.mythic, query=subscription):
#             await self.handle_batch(data["mythictree_stream"])

"""Mock StorageMinio implementation for standalone testing."""

import os
import shutil
import tempfile
import uuid


class MockStorageMinio:
    """Mock implementation of StorageMinio for testing without Minio.

    Provides the same interface as the real StorageMinio but stores files
    locally in a temporary directory.

    Usage:
        storage = MockStorageMinio()

        # Register a local file to be downloadable by object_id
        storage.register_file("uuid-1234", "/path/to/local/file.bin")

        # Download returns a temp file handle
        with storage.download("uuid-1234") as f:
            content = f.read()

        # Upload returns a UUID
        new_id = storage.upload(b"some bytes")
        new_id = storage.upload_file("/path/to/file")
    """

    def __init__(self, data_download_dir: str | None = None):
        """Initialize mock storage.

        Args:
            data_download_dir: Optional directory for temp files. If not provided,
                               uses system temp directory.
        """
        self._registered_files: dict[str, str] = {}  # object_id -> local_path
        self._uploaded_files: dict[str, bytes] = {}  # object_id -> bytes
        self._upload_paths: dict[str, str] = {}  # object_id -> original_path
        self.data_download_dir = data_download_dir or tempfile.gettempdir()
        self.bucket_name = "test-files"

    def register_file(self, object_id: str, local_path: str) -> None:
        """Register a local file to be accessible via object_id.

        Args:
            object_id: The UUID that will be used to reference this file
            local_path: Path to the actual file on disk
        """
        if not os.path.exists(local_path):
            raise FileNotFoundError(f"Cannot register non-existent file: {local_path}")
        self._registered_files[object_id] = local_path

    def download(self, file_uuid: str, delete: bool = True) -> tempfile._TemporaryFileWrapper:
        """Download a file by UUID, returning a temporary file handle.

        Args:
            file_uuid: The UUID of the file to download
            delete: Whether to auto-delete the temp file when closed

        Returns:
            A NamedTemporaryFile containing the file contents
        """
        # Check registered files first
        if file_uuid in self._registered_files:
            source_path = self._registered_files[file_uuid]
        elif file_uuid in self._uploaded_files:
            # Create temp file from uploaded bytes
            temp_file = tempfile.NamedTemporaryFile(
                dir=self.data_download_dir,
                delete=delete,
            )
            temp_file.write(self._uploaded_files[file_uuid])
            temp_file.flush()
            temp_file.seek(0)
            return temp_file
        elif file_uuid in self._upload_paths:
            source_path = self._upload_paths[file_uuid]
        else:
            raise FileNotFoundError(f"No file registered for UUID: {file_uuid}")

        # Copy the file to a temporary location
        temp_file = tempfile.NamedTemporaryFile(
            dir=self.data_download_dir,
            delete=delete,
        )
        shutil.copyfile(source_path, temp_file.name)
        return temp_file

    def download_bytes(self, file_uuid: str, offset: int = 0, length: int = 0) -> bytes:
        """Download raw bytes from a file.

        Args:
            file_uuid: The UUID of the file
            offset: Byte offset to start reading from
            length: Number of bytes to read (0 = all remaining)

        Returns:
            The requested bytes from the file
        """
        # Check uploaded bytes first
        if file_uuid in self._uploaded_files:
            data = self._uploaded_files[file_uuid]
            if length > 0:
                return data[offset : offset + length]
            return data[offset:]

        # Check registered files
        if file_uuid in self._registered_files:
            source_path = self._registered_files[file_uuid]
        elif file_uuid in self._upload_paths:
            source_path = self._upload_paths[file_uuid]
        else:
            raise FileNotFoundError(f"No file registered for UUID: {file_uuid}")

        with open(source_path, "rb") as f:
            if offset > 0:
                f.seek(offset)
            if length > 0:
                return f.read(length)
            return f.read()

    def download_stream(self, file_uuid: str, chunk_size: int = 1024 * 1024):
        """Stream a file in chunks.

        Args:
            file_uuid: The UUID of the file
            chunk_size: Size of chunks to yield

        Yields:
            Chunks of file data
        """
        if file_uuid in self._uploaded_files:
            data = self._uploaded_files[file_uuid]
            for i in range(0, len(data), chunk_size):
                yield data[i : i + chunk_size]
            return

        if file_uuid in self._registered_files:
            source_path = self._registered_files[file_uuid]
        elif file_uuid in self._upload_paths:
            source_path = self._upload_paths[file_uuid]
        else:
            raise FileNotFoundError(f"No file registered for UUID: {file_uuid}")

        with open(source_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk

    def upload_file(self, file_path: str) -> uuid.UUID:
        """Upload a file and return its UUID.

        Args:
            file_path: Path to the file to upload

        Returns:
            UUID assigned to the uploaded file
        """
        file_uuid = uuid.uuid4()
        self._upload_paths[str(file_uuid)] = file_path
        return file_uuid

    def upload(self, data: bytes) -> uuid.UUID:
        """Upload raw bytes and return their UUID.

        Args:
            data: Bytes to upload

        Returns:
            UUID assigned to the uploaded data
        """
        file_uuid = uuid.uuid4()
        self._uploaded_files[str(file_uuid)] = data
        return file_uuid

    def check_file_exists(self, object_name: str) -> bool:
        """Check if a file exists in storage.

        Args:
            object_name: The object ID to check

        Returns:
            True if the file exists, False otherwise
        """
        return (
            object_name in self._registered_files
            or object_name in self._uploaded_files
            or object_name in self._upload_paths
        )

    def get_object_stats(self, object_name: str) -> dict:
        """Get stats about an object (mock implementation).

        Args:
            object_name: The object ID

        Returns:
            Dict with basic stats (size)
        """
        if object_name in self._uploaded_files:
            return {"size": len(self._uploaded_files[object_name])}

        if object_name in self._registered_files:
            path = self._registered_files[object_name]
        elif object_name in self._upload_paths:
            path = self._upload_paths[object_name]
        else:
            raise FileNotFoundError(f"No file found for: {object_name}")

        return {"size": os.path.getsize(path)}

    def delete_object(self, object_id: str) -> bool:
        """Delete an object from mock storage.

        Args:
            object_id: The object to delete

        Returns:
            True if deleted, False if not found
        """
        deleted = False
        if object_id in self._registered_files:
            del self._registered_files[object_id]
            deleted = True
        if object_id in self._uploaded_files:
            del self._uploaded_files[object_id]
            deleted = True
        if object_id in self._upload_paths:
            del self._upload_paths[object_id]
            deleted = True
        return deleted

    def get_uploaded_files(self) -> dict[str, bytes]:
        """Get all files uploaded during testing (for assertions).

        Returns:
            Dict mapping object_id to bytes for in-memory uploads
        """
        return self._uploaded_files.copy()

    def get_uploaded_paths(self) -> dict[str, str]:
        """Get all file paths uploaded during testing (for assertions).

        Returns:
            Dict mapping object_id to original file path
        """
        return self._upload_paths.copy()

    def clear(self) -> None:
        """Clear all registered and uploaded files."""
        self._registered_files.clear()
        self._uploaded_files.clear()
        self._upload_paths.clear()

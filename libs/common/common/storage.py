import os
import tempfile
import uuid
from datetime import datetime
from io import BytesIO
from uuid import UUID

from dapr.clients import DaprClient
from fastapi import UploadFile
from minio import Minio
from minio.error import S3Error
from urllib3 import PoolManager, Retry

from .helpers import require_uuid
from .logger import get_logger

logger = get_logger(__name__)


def _key(object_id: UUID) -> str:
    """Object key in the bucket for a file/transform ID.

    Every caller passes a ``UUID``; a ``str`` here means an ID escaped validation somewhere upstream, so it is
    rejected rather than silently used as a key.
    """
    return str(require_uuid(object_id))


class StorageS3:
    def __init__(
        self,
        bucket_name: str = "files",
        data_download_dir: str = "/tmp/",
    ) -> None:
        endpoint = os.getenv("S3_ENDPOINT", "seaweedfs:8333")

        with DaprClient() as client:
            secret = client.get_secret(store_name="nemesis-secret-store", key="S3_ACCESS_KEY")
            access_key = secret.secret["S3_ACCESS_KEY"]

            secret = client.get_secret(store_name="nemesis-secret-store", key="S3_SECRET_KEY")
            secret_key = secret.secret["S3_SECRET_KEY"]

        self.minio_client = Minio(
            endpoint,
            access_key=access_key,
            secret_key=secret_key,
            secure=False,
            http_client=PoolManager(
                maxsize=30,
                retries=Retry(total=3, backoff_factor=0.2),
            ),
        )
        self.data_download_dir = data_download_dir
        # the bucket name must be lowercase
        self.bucket_name = bucket_name.lower()

    def download(self, file_uuid: UUID, delete: bool = True) -> tempfile._TemporaryFileWrapper:
        try:
            temp_file = tempfile.NamedTemporaryFile(dir=self.data_download_dir, delete=delete)

            logger.debug(
                "Downloading from storage",
                file_uuid=file_uuid,
                dest_path=temp_file.name,
            )

            try:
                self.minio_client.fget_object(self.bucket_name, _key(file_uuid), temp_file.name)
            except BaseException:
                logger.exception(message="Failed to download file")
                raise
            finally:
                logger.debug("Downloaded file", file_uuid=file_uuid)

            return temp_file
        except Exception:
            logger.exception(file_uuid=file_uuid, bucket_name=self.bucket_name)
            raise

    def download_bytes(self, file_uuid: UUID, offset: int = 0, length: int = 0) -> bytes:
        try:
            logger.debug("Starting file download from storage", file_uuid=file_uuid)

            try:
                # Get the data directly as bytes using get_object instead of fget_object
                response = self.minio_client.get_object(self.bucket_name, _key(file_uuid), offset, length)
                # Read all bytes from the response
                file_data = response.read()
                response.close()

                logger.debug("Successfully downloaded file", file_uuid=file_uuid)
                return file_data

            except BaseException:
                logger.exception(message="Failed to download file")
                raise

        except Exception:
            logger.exception(file_uuid=file_uuid, bucket_name=self.bucket_name)
            raise

    def download_stream(self, file_uuid: UUID, chunk_size: int = 1024 * 1024):
        """
        Stream a file from storage in chunks.

        Args:
            file_uuid (UUID): The UUID of the file to download
            chunk_size (int): Size of chunks to stream in bytes (default: 1MB)

        Yields:
            bytes: Chunks of file data

        Raises:
            Exception: If download fails
        """
        try:
            logger.debug("Starting file streaming from storage", file_uuid=file_uuid)

            try:
                # Get the data stream from MinIO
                response = self.minio_client.get_object(self.bucket_name, _key(file_uuid))

                # Stream the data in chunks
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk

                response.close()
                logger.debug("Successfully streamed file", file_uuid=file_uuid)

            except BaseException:
                logger.exception(message="Failed to stream file")
                raise

        except Exception:
            logger.exception(file_uuid=file_uuid, bucket_name=self.bucket_name)
            raise

    def get_object_stats(self, object_name: UUID):
        """Get states about the object."""
        try:
            return self.minio_client.stat_object(self.bucket_name, _key(object_name))
        except Exception:
            logger.exception("Error pulling object stats", object_name=object_name)
            raise

    def check_file_exists(self, object_name: UUID) -> bool:
        """Check if a file exists."""
        try:
            # Try to get the object stats - this will raise an exception if the object doesn't exist
            self.minio_client.stat_object(self.bucket_name, _key(object_name))
            return True
        except S3Error as err:
            # If the error code is 'NoSuchKey' or 'NoSuchBucket', the file doesn't exist
            if err.code in ["NoSuchKey", "NoSuchBucket"]:
                return False
            # For other errors, raise the exception
            raise

    def upload_uploadfile(self, file: UploadFile) -> UUID:
        # uploads an UploadFile post directly from FastAPI
        try:
            logger.debug(f"Uploading UploadFile {file.filename} to storage")

            # Get file size using SpooledTemporaryFile instead of async read
            file_size = 0
            file_content = file.file  # This is a SpooledTemporaryFile
            file_content.seek(0, 2)  # Seek to end
            file_size = file_content.tell()  # Get current position (file size)
            file_content.seek(0)  # Reset to beginning

            logger.debug(f"file_size: {file_size}")

            # UUID name for the uploaded file
            file_uuid = uuid.uuid4()

            # Upload directly using the file object
            self.minio_client.put_object(
                self.bucket_name,
                _key(file_uuid),
                file.file,  # Use file.file directly
                length=file_size,  # Provide the calculated size
            )
            logger.debug("Object upload completed", file_name=file.filename)

            return file_uuid

        except Exception:
            logger.exception(bucket_name=self.bucket_name)
            raise

    def upload_file(self, file_path: str) -> UUID:
        try:
            logger.debug("Uploading file to storage", file_path=file_path)
            file_uuid = uuid.uuid4()
            self.minio_client.fput_object(
                bucket_name=self.bucket_name,
                object_name=_key(file_uuid),
                file_path=file_path,
            )
            return file_uuid
        except Exception:
            logger.exception(file_path=file_path, bucket_name=self.bucket_name)
            raise

    def upload(self, data: bytes) -> UUID:
        try:
            logger.debug(f"Uploading {len(data)} bytes to storage")
            file_uuid = uuid.uuid4()
            self.minio_client.put_object(
                bucket_name=self.bucket_name,
                object_name=_key(file_uuid),
                data=BytesIO(data),
                length=len(data),
            )
            return file_uuid
        except Exception:
            logger.exception(bucket_name=self.bucket_name)
            raise

    def delete_object(self, object_id: UUID) -> bool:
        """Delete a single object from S3 storage.

        An object that is already gone (``NoSuchKey``) counts as deleted, so a cleanup interrupted after its storage
        deletes can be retried safely.

        Args:
            object_id (UUID): The ID of the object to delete

        Returns:
            bool: True if the object no longer exists, False if the delete failed
        """
        return self._delete_key(_key(object_id))

    def _delete_key(self, key: str) -> bool:
        """Delete one bucket key; an already-absent key (``NoSuchKey``) counts as deleted."""
        try:
            self.minio_client.remove_object(self.bucket_name, key)
            logger.debug("Deleted object from storage", object_id=key, bucket=self.bucket_name)
            return True
        except S3Error as err:
            if err.code == "NoSuchKey":
                logger.debug("Object already absent from storage", object_id=key, bucket=self.bucket_name)
                return True
            logger.exception(message="Failed to delete object from storage", object_id=key)
            return False
        except Exception:
            logger.exception(message="Failed to delete object from storage", object_id=key)
            return False

    def delete_objects_with_status(self, object_ids: list[UUID]) -> set[UUID]:
        """Delete multiple objects and return the IDs that no longer exist (deleted or already absent).

        Callers should only drop their own references (e.g. database rows) to the returned IDs; the rest failed and
        should be kept so a later run can retry them.
        """
        return {object_id for object_id in dict.fromkeys(object_ids) if self.delete_object(object_id)}

    def delete_objects(self, object_ids: list[UUID]) -> int:
        """Delete multiple objects from S3 storage.

        Args:
            object_ids (list[UUID]): List of object IDs to delete

        Returns:
            int: Count of objects that no longer exist (deleted or already absent)
        """
        return len(self.delete_objects_with_status(object_ids))

    def delete_objects_modified_before(self, cutoff: datetime) -> tuple[int, int]:
        """Delete every object in the bucket last modified before ``cutoff`` (an aware datetime).

        Objects are listed and deleted one at a time, so memory stays bounded however large the bucket is. Objects
        written after ``cutoff`` (e.g. uploads that arrive while a cleanup runs) are left alone.

        Returns:
            (deleted, failed) counts.
        """
        deleted = failed = 0
        for obj in self.minio_client.list_objects(self.bucket_name, recursive=True):
            if obj.object_name is None or obj.is_dir:
                continue
            if obj.last_modified is not None and obj.last_modified >= cutoff:
                continue
            # Raw bucket keys: an orphan may not even be named like a UUID
            if self._delete_key(obj.object_name):
                deleted += 1
            else:
                failed += 1
        return deleted, failed

    def delete_all_files(self) -> bool:
        """
        Deletes all of the files in a bucket and removes the bucket itself.
        """

        logger.debug("Deleting all files from bucket", bucket_name=self.bucket_name)

        try:
            files = self.minio_client.list_objects(self.bucket_name, recursive=True)
            for file in files:
                if file.object_name is not None:
                    self.minio_client.remove_object(self.bucket_name, file.object_name)
            self.minio_client.remove_bucket(self.bucket_name)
            return True
        except Exception:
            logger.exception(
                "Failed to delete files from bucket",
                bucket_name=self.bucket_name,
            )
            raise


# Backward-compatibility alias
StorageMinio = StorageS3

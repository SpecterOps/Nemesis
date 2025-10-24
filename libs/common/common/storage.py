import tempfile
import uuid
from io import BytesIO

from dapr.clients import DaprClient
from fastapi import UploadFile
from minio import Minio
from minio.error import S3Error
from urllib3 import PoolManager, Retry

from .logger import get_logger

logger = get_logger(__name__)


class StorageMinio:
    def __init__(
        self,
        bucket_name: str = "files",
        data_download_dir: str = "/tmp/",
    ) -> None:
        # endpoint = os.getenv("MINIO_ENDPOINT", "minio:9000"),
        endpoint = "minio:9000"

        with DaprClient() as client:
            secret = client.get_secret(store_name="nemesis-secret-store", key="MINIO_ROOT_USER")
            minio_root_user = secret.secret["MINIO_ROOT_USER"]

            secret = client.get_secret(store_name="nemesis-secret-store", key="MINIO_ROOT_PASSWORD")
            minio_root_password = secret.secret["MINIO_ROOT_PASSWORD"]

        self.minio_client = Minio(
            endpoint,
            access_key=f"{minio_root_user}",
            secret_key=f"{minio_root_password}",
            secure=False,
            http_client=PoolManager(
                maxsize=30,
                retries=Retry(total=3, backoff_factor=0.2),
            ),
        )
        self.data_download_dir = data_download_dir
        # the bucket name must be lowercase
        self.bucket_name = bucket_name.lower()

    def download(self, file_uuid: str, delete: bool = True) -> tempfile._TemporaryFileWrapper:
        try:
            temp_file = tempfile.NamedTemporaryFile(dir=self.data_download_dir, delete=delete)

            logger.debug(
                "Downloading from storage",
                file_uuid=file_uuid,
                dest_path=temp_file.name,
            )

            try:
                self.minio_client.fget_object(self.bucket_name, file_uuid, temp_file.name)
            except BaseException as e:
                logger.exception(e, message="Failed to download file")
                raise
            finally:
                logger.debug("Downloaded file", file_uuid=file_uuid)

            return temp_file
        except Exception as e:
            logger.exception(e, file_uuid=file_uuid, bucket_name=self.bucket_name)
            raise

    def download_bytes(self, file_uuid: str, offset: int = 0, length: int = 0) -> bytes:
        try:
            logger.debug("Starting file download from storage", file_uuid=file_uuid)

            try:
                # Get the data directly as bytes using get_object instead of fget_object
                response = self.minio_client.get_object(self.bucket_name, f"{file_uuid}", offset, length)
                # Read all bytes from the response
                file_data = response.read()
                response.close()

                logger.debug("Successfully downloaded file", file_uuid=file_uuid)
                return file_data

            except BaseException as e:
                logger.exception(e, message="Failed to download file")
                raise

        except Exception as e:
            logger.exception(e, file_uuid=file_uuid, bucket_name=self.bucket_name)
            raise

    def download_stream(self, file_uuid: str, chunk_size: int = 1024 * 1024):
        """
        Stream a file from storage in chunks.

        Args:
            file_uuid (str): The UUID of the file to download
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
                response = self.minio_client.get_object(self.bucket_name, f"{file_uuid}")

                # Stream the data in chunks
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk

                response.close()
                logger.debug("Successfully streamed file", file_uuid=file_uuid)

            except BaseException as e:
                logger.exception(e, message="Failed to stream file")
                raise

        except Exception as e:
            logger.exception(e, file_uuid=file_uuid, bucket_name=self.bucket_name)
            raise

    def get_object_stats(self, object_name):
        """Get states about the object."""
        try:
            return self.minio_client.stat_object(self.bucket_name, object_name)
        except Exception as e:
            logger.exception(e, "Error pulling object stats", object_name=object_name)
            raise

    def check_file_exists(self, object_name):
        """Check if a file exists."""
        try:
            # Try to get the object stats - this will raise an exception if the object doesn't exist
            self.minio_client.stat_object(self.bucket_name, object_name)
            return True
        except S3Error as err:
            # If the error code is 'NoSuchKey' or 'NoSuchBucket', the file doesn't exist
            if err.code in ["NoSuchKey", "NoSuchBucket"]:
                return False
            # For other errors, raise the exception
            raise

    def upload_uploadfile(self, file: UploadFile) -> uuid.UUID:
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
            file_uuid = f"{uuid.uuid4()}"

            # Upload directly using the file object
            self.minio_client.put_object(
                self.bucket_name,
                file_uuid,
                file.file,  # Use file.file directly
                length=file_size,  # Provide the calculated size
            )
            logger.debug("Object upload completed", file_name=file.filename)

            return file_uuid

        except Exception as e:
            logger.exception(e, bucket_name=self.bucket_name)
            raise

    def upload_file(self, file_path: str) -> uuid.UUID:
        try:
            logger.debug("Uploading file to storage", file_path=file_path)
            file_uuid = f"{uuid.uuid4()}"
            self.minio_client.fput_object(
                bucket_name=self.bucket_name,
                object_name=file_uuid,
                file_path=file_path,
            )
            return file_uuid
        except Exception as e:
            logger.exception(e, file_path=file_path, bucket_name=self.bucket_name)
            raise

    def upload(self, data: bytes) -> uuid.UUID:
        try:
            logger.debug(f"Uploading {len(data)} bytes to storage")
            file_uuid = f"{uuid.uuid4()}"
            self.minio_client.put_object(
                bucket_name=self.bucket_name,
                object_name=file_uuid,
                data=BytesIO(data),
                length=len(data),
            )
            return file_uuid
        except Exception as e:
            logger.exception(e, bucket_name=self.bucket_name)
            raise

    def delete_object(self, object_id: str) -> bool:
        """Delete a single object from Minio storage.

        Args:
            object_id (str): The ID of the object to delete

        Returns:
            bool: True if deletion was successful, False otherwise
        """
        try:
            self.minio_client.remove_object(self.bucket_name, object_id)
            logger.debug("Deleted object from Minio", object_id=object_id, bucket=self.bucket_name)
            return True
        except Exception as e:
            logger.exception(e, message="Failed to delete object from Minio", object_id=object_id)
            return False

    def delete_objects(self, object_ids: list[str]) -> int:
        """Delete multiple objects from Minio storage.

        Args:
            object_ids (List[str]): List of object IDs to delete

        Returns:
            int: Count of successfully deleted objects
        """
        success_count = 0
        for object_id in object_ids:
            if self.delete_object(object_id):
                success_count += 1
        return success_count

    def delete_all_files(self) -> bool:
        """
        Deletes all of the files in a bucket.

        For Minio, because we recreate the bucket with the expiration policy on
        bucket creation, we want to delete the bucket here as well so the next
        upload creates everything correctly.
        """

        logger.debug("Deleting all files from bucket", bucket_name=self.bucket_name)

        try:
            files = self.minio_client.list_objects(self.bucket_name, recursive=True)
            for file in files:
                self.minio_client.remove_object(self.bucket_name, file.object_name)
            self.minio_client.remove_bucket(self.bucket_name)
            return True
        except Exception as e:
            logger.exception(
                e,
                message="Failed to delete files from bucket",
                bucket_name=self.bucket_name,
            )
            raise

# Standard Libraries
import tempfile
import uuid
from types import TracebackType
from typing import Optional, Type

# 3rd Party Libraries
import structlog
from miniopy_async import Minio
from miniopy_async.commonconfig import ENABLED, Filter
from miniopy_async.lifecycleconfig import LifecycleConfig, Rule, Expiration
from nemesiscommon.storage import StorageInterface

logger = structlog.get_logger(module=__name__)


class StorageMinio(StorageInterface):
    data_download_dir: str
    assessment_id: str
    minio_client: Minio

    def __init__(
        self,
        assessment_id: str,
        data_download_dir: str,
        access_key: str,
        secret_key: str,
    ) -> None:
        self.minio_client = Minio("nemesis-minio:9000", access_key=access_key, secret_key=secret_key, secure=False)
        self.data_download_dir = data_download_dir
        # the bucket name must be lowercase
        self.assessment_id = assessment_id.lower()

    async def download(self, file_uuid: uuid.UUID, delete: bool = True) -> tempfile._TemporaryFileWrapper:
        temp_file = tempfile.NamedTemporaryFile(dir=self.data_download_dir, delete=delete)

        await logger.adebug("Downloading from storage", file_uuid=file_uuid, dest_path=temp_file.name)

        try:
            await self.minio_client.fget_object(self.assessment_id, f"{file_uuid}", temp_file.name)
        except BaseException as e:
            await logger.aexception(e, message="Failed to download file")
            raise
        finally:
            await logger.ainfo("Downloaded file", file_uuid=file_uuid)

        return temp_file

    async def upload(self, file_path: str, storage_expiration_days: int = 100) -> uuid.UUID:
        if not await self.minio_client.bucket_exists(self.assessment_id):
            await logger.ainfo("Creating Minio bucket", bucket=self.assessment_id)
            await self.minio_client.make_bucket(self.assessment_id)

            # since this is the only place that creates the bucket, we can set
            #   the auto-expiration policy here
            config = LifecycleConfig(
                [
                    Rule(
                        ENABLED,
                        rule_filter=Filter(prefix=""),
                        rule_id=f"expire-{storage_expiration_days}-days",
                        expiration=Expiration(days=365),
                    ),
                ],
            )
            await logger.ainfo(f"Setting Minio bucket files to expire in {storage_expiration_days} days", bucket=self.assessment_id)
            await self.minio_client.set_bucket_lifecycle(self.assessment_id, config)

        await logger.adebug("Uploading to storage", file_path=file_path)
        file_uuid = uuid.uuid4()
        await self.minio_client.fput_object(self.assessment_id, f"{file_uuid}", file_path)
        return file_uuid

    async def exists(self, file_name: str) -> bool:
        raise NotImplementedError

    async def delete_all_files(self) -> bool:
        """
        Deletes all of the files in a bucket.

        For Minio, because we recreate the bucket with the expiration policy on
        bucket creation, we want to delete the bucket here as well so the next
        upload creates everything correctly.
        """
        await logger.adebug("Deleting all files from bucket", bucket_name=self.assessment_id)

        try:
            files = await self.minio_client.list_objects(self.assessment_id, recursive=True)
            for file in files:
                await self.minio_client.remove_object(self.assessment_id, file.object_name)
            await self.minio_client.remove_bucket(self.assessment_id)
            return True
        except Exception as e:
            await logger.aexception(e, message="Failed to delete files from bucket", bucket_name=self.assessment_id)
            raise

    async def __aenter__(self):
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        pass

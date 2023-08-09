# Standard Libraries

# 3rd Party Libraries
import structlog
import uvicorn
from dotnet.services.dotnet import DotnetAPI
from dotnet.settings import DotnetSettings
from fastapi import FastAPI
from nemesiscommon.storage_s3 import StorageS3
from nemesiscommon.storage_minio import StorageMinio
from nemesiscommon.storage import StorageInterface
from prometheus_async.aio.web import start_http_server

logger = structlog.get_logger(module=__name__)


class App:
    cfg: DotnetSettings
    storage: StorageInterface

    def __init__(self) -> None:
        self.cfg = DotnetSettings()  # type: ignore

    async def start(self):
        await logger.ainfo("Application started")

        await logger.ainfo("Starting prometheus")
        await start_http_server(port=self.cfg.prometheus_port)

        if self.cfg.storage_provider.lower() == "s3":
            await logger.ainfo("Starting S3 storage backend")
            self.storage = StorageS3(
                assessment_id=self.cfg.assessment_id,
                data_download_dir=self.cfg.data_download_dir,
                aws_access_key_id=self.cfg.aws_access_key_id,
                aws_secret_access_key=self.cfg.aws_secret_access_key,
                aws_default_region=self.cfg.aws_default_region,
                aws_bucket_name=self.cfg.aws_bucket,
                aws_kms_key_alias=self.cfg.aws_kms_key_alias,
            )
        elif self.cfg.storage_provider.lower() == "minio":
            await logger.ainfo("Starting minio storage backend")
            self.storage = StorageMinio(
                assessment_id=self.cfg.assessment_id,
                data_download_dir=self.cfg.data_download_dir,
                access_key=self.cfg.minio_root_user,
                secret_key=self.cfg.minio_root_password,
            )
        else:
            await logger.aerror("Storage provider not supported", storage_provider=self.cfg.storage_provider)
            raise

        await logger.ainfo("Starting service")

        await self.start_dotnet()

        await logger.ainfo("Application shutting down")

    def custom_exception_handler(self, loop, context):
        # first, handle with default handler
        loop.default_exception_handler(context)
        e = context.get("exception")
        logger.exception("asyncio exception", e)
        loop.stop()

    async def start_dotnet(self) -> None:
        app = FastAPI()
        routes = DotnetAPI(self.cfg, self.storage)
        app.include_router(routes.router)
        config = uvicorn.Config(app, host="0.0.0.0", port=9800, log_level=self.cfg.log_level.lower(), loop="asyncio")
        server = uvicorn.Server(config)
        await server.serve()

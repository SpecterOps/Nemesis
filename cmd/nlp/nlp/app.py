# Standard Libraries
import asyncio
from urllib.parse import urlparse

# 3rd Party Libraries
import nemesiscommon.constants as constants
import nemesispb.nemesis_pb2 as pb
import structlog
import uvicorn
from fastapi import FastAPI
from nemesiscommon.messaging_rabbitmq import (NemesisRabbitMQConsumer,
                                              NemesisRabbitMQProducer)
from nemesiscommon.setupqueues import initRabbitMQ
from nemesiscommon.socketwaiter import SocketWaiter
from nemesiscommon.storage_s3 import StorageS3
from nemesiscommon.storage_minio import StorageMinio
from nemesiscommon.storage import StorageInterface
from nlp.services.indexing import IndexingService
from nlp.services.semantic_search import SemanticSearchAPI
from nlp.settings import NLPSettings
from prometheus_async.aio.web import MetricsHTTPServer, start_http_server

logger = structlog.get_logger(__name__)


class App:
    cfg: NLPSettings
    storage: StorageInterface
    metrics_server: MetricsHTTPServer

    def __init__(self, cfg: NLPSettings) -> None:
        self.cfg = cfg

    async def start(self) -> None:
        await logger.ainfo("Application started")

        await self.wait_for_services()
        await initRabbitMQ(self.cfg.rabbitmq_connection_uri)
        self.metrics_server = await start_http_server(port=self.cfg.prometheus_port)

        if self.cfg.storage_provider.lower() == "s3":
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
            self.storage = StorageMinio(
                assessment_id=self.cfg.assessment_id,
                data_download_dir=self.cfg.data_download_dir,
                access_key=self.cfg.minio_root_user,
                secret_key=self.cfg.minio_root_password,
            )
        else:
            await logger.aerror("Storage provider not supported", storage_provider=self.cfg.storage_provider)
            raise

        await logger.ainfo("Starting services")

        task_coroutines = [
            self.start_indexing_service(),
            self.start_semantic_search_api(),
        ]

        async with asyncio.TaskGroup() as tg:
            for c in task_coroutines:
                tg.create_task(c)

        await logger.ainfo("Application shutting down")

    async def stop(self):
        await logger.ainfo("Stopping application")
        pass

    async def wait_for_services(self) -> None:
        rabbitUri = urlparse(self.cfg.rabbitmq_connection_uri)
        elasticUri = urlparse(self.cfg.elasticsearch_url)

        if rabbitUri.hostname is None or elasticUri.hostname is None:
            raise Exception("Invalid connection URI")
        if rabbitUri.port is None or elasticUri.port is None:
            raise Exception("Invalid connection URI")

        SocketWaiter(rabbitUri.hostname, rabbitUri.port).wait()
        SocketWaiter(elasticUri.hostname, elasticUri.port).wait()
        await logger.ainfo("All services are online!")

    async def start_indexing_service(self) -> None:
        async with (
            await NemesisRabbitMQConsumer.create(
                self.cfg.rabbitmq_connection_uri, constants.Q_FILE_DATA_PLAINTEXT, pb.FileDataPlaintextMessage, "indexingservice", 1
            ) as plaintext_input_queue,
            await NemesisRabbitMQConsumer.create(
                self.cfg.rabbitmq_connection_uri, constants.Q_FILE_DATA_PLAINTEXT_CHUNK, pb.FileDataPlaintextChunkMessage, "indexingservice", 1
            ) as plaintext_chunk_input_queue,
            await NemesisRabbitMQProducer.create(
                self.cfg.rabbitmq_connection_uri,
                constants.Q_FILE_DATA_PLAINTEXT_CHUNK
            ) as plaintext_chunk_output_queue,
        ):
            service = IndexingService(  self.cfg,
                                        self.storage,
                                        plaintext_input_queue,
                                        plaintext_chunk_input_queue,
                                        plaintext_chunk_output_queue)
            await service.run()

    async def start_semantic_search_api(self) -> None:
        app = FastAPI()
        routes = SemanticSearchAPI(self.cfg)
        app.include_router(routes.router)
        server_config = uvicorn.Config(app, host="0.0.0.0", port=9803, log_level=self.cfg.log_level.lower())
        server = uvicorn.Server(server_config)
        await server.serve()

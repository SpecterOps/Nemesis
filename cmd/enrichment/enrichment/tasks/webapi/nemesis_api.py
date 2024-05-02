# Standard Libraries
import base64
import json
import os
import tempfile
import time
import urllib.parse
import uuid
from datetime import datetime
from enum import StrEnum
from typing import Dict, List, Optional

import aiofiles
# 3rd Party Libraries
import httpx
import nemesispb.nemesis_pb2 as pb
import streaming_form_data
import structlog
import uvicorn
from aio_pika import connect_robust
from elasticsearch import AsyncElasticsearch
from enrichment.cli.submit_to_nemesis.submit_to_nemesis import (
    map_unordered, return_args_and_exceptions)
from enrichment.lib.nemesis_db import NemesisDb
from enrichment.lib.registry import include_registry_value
from fastapi import APIRouter, FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse, Response
from google.protobuf.json_format import Parse
# from nemesiscommon.clearqueues import clearRabbitMQQueues
from nemesiscommon.constants import ALL_ES_INDICIES, NemesisQueue
from nemesiscommon.messaging import MessageQueueProducerInterface
from nemesiscommon.messaging_rabbitmq import RABBITMQ_QUEUE_BINDINGS
from nemesiscommon.services.alerter import AlerterInterface
from nemesiscommon.storage import StorageInterface
from nemesiscommon.tasking import TaskInterface
from prometheus_async import aio
from prometheus_client import Summary
from pydantic import BaseModel
from starlette.background import BackgroundTask
from starlette.requests import ClientDisconnect
from streaming_form_data import StreamingFormDataParser
from streaming_form_data.targets import FileTarget

logger = structlog.get_logger(module=__name__)

MAP = {
    "authentication_data": pb.AuthenticationDataIngestionMessage,
    "file_data": pb.FileDataIngestionMessage,
    "file_information": pb.FileInformationIngestionMessage,
    "network_address": pb.NetworkAddressIngestionMessage,
    "network_connection": pb.NetworkConnectionIngestionMessage,
    "path_list": pb.PathListIngestionMessage,
    "process_enriched": pb.ProcessEnrichedMessage,
    "process": pb.ProcessIngestionMessage,
    "raw_data": pb.RawDataIngestionMessage,
    "registry_value": pb.RegistryValueIngestionMessage,
    "route": pb.RouteDataIngestionMessage,
    "time": pb.TimeDataIngestionMessage,
    "service": pb.ServiceIngestionMessage,
    "cookie": pb.CookieIngestionMessage,
    "named_pipe": pb.NamedPipeIngestionMessage,
    "network_conection": pb.NetworkConnectionIngestionMessage,
    # DpapiBlobMessage
    # DpapiDomainBackupkeyMessage
    # DpapiMasterkeyMessage
    # ExtractedHashMessage
    # FileDataPlaintextMessage
    # ProcessMessage
    # ServiceEnrichedMessage
}


# # kills all the connections in a way we can't proceed
# async def delete_rabbit_mq_connections(connection_uri: str) -> None:
#     rabbit_mq_api_url_connections = connection_uri.replace("amqp", "http").replace(
#         ":5672", ":15672/rabbitmq/api/connections/username/nemesis"
#     )
#     transport = httpx.AsyncHTTPTransport(retries=5)
#     async with httpx.AsyncClient(transport=transport) as client:
#         try:
#             await client.delete(rabbit_mq_api_url_connections)
#         except Exception as e:
#             await logger.aerror("Error DELETEing RabbitMQ connections via the API", exception=e)


async def get_all_rabbit_mq_queues(rabbit_mq_api_url: str) -> List[str]:
    """Calls the RabbitMQ API to retrieve all current queue names."""
    rabbit_mq_api_url_queues = f"{rabbit_mq_api_url}queues"
    transport = httpx.AsyncHTTPTransport(retries=5)
    async with httpx.AsyncClient(transport=transport) as client:
        try:
            r = await client.get(rabbit_mq_api_url_queues)
            if r.status_code == 200:
                return [queue["name"] for queue in r.json()]
            else:
                await logger.aerror("Error retrieving RabbitMQ queues from the API", status=r.status_code)
                return []
        except Exception as e:
            await logger.aerror("Error retrieving RabbitMQ queues from the API", exception=e)
            return []


async def purge_rabbit_mq_queues(connection_uri: str) -> None:
    """Enumerates all queues with get_all_rabbit_mq_queues() and purges each."""
    await logger.ainfo("Purging all existing RabbitMQ queues")
    connection = await connect_robust(connection_uri)
    rabbit_mq_api_url = connection_uri.replace("amqp", "http").replace(":5672", ":15672/rabbitmq/api/")
    queue_names = await get_all_rabbit_mq_queues(rabbit_mq_api_url)

    async with connection:
        channel = await connection.channel()
        for queue_name in queue_names:
            queue = await channel.get_queue(queue_name)
            await logger.ainfo("Purging queue", queue=queue_name)
            await queue.purge()

    await logger.ainfo("Done purging RabbitMQ queues")


class NemesisApi(TaskInterface):
    storage: StorageInterface
    rabbitmq_connection_uri: str
    alerter: AlerterInterface
    db: NemesisDb
    es_client: AsyncElasticsearch
    http_client: httpx.AsyncClient
    queue_map: dict[NemesisQueue, MessageQueueProducerInterface]
    assessment_id: str
    log_level: str
    reprocessing_workers: int
    storage_expiration_days: int

    def __init__(
        self,
        storage: StorageInterface,
        rabbitmq_connection_uri: str,
        alerter: AlerterInterface,
        db: NemesisDb,
        es_client: AsyncElasticsearch,
        queue_map: dict[NemesisQueue, MessageQueueProducerInterface],
        assessment_id: str,
        log_level: str,
        reprocessing_workers: int,
        storage_expiration_days: int
    ) -> None:
        self.storage = storage
        self.rabbitmq_connection_uri = rabbitmq_connection_uri
        self.alerter = alerter
        self.db = db
        self.es_client = es_client
        self.queue_map = queue_map
        self.assessment_id = assessment_id
        self.log_level = log_level
        self.reprocessing_workers = reprocessing_workers
        self.storage_expiration_days = storage_expiration_days

    async def run(self) -> None:
        app = FastAPI(title="Nemesis API")
        routes = NemesisApiRoutes(
            self.storage,
            self.rabbitmq_connection_uri,
            self.alerter,
            self.db,
            self.es_client,
            self.queue_map,
            self.assessment_id,
            self.reprocessing_workers,
            self.storage_expiration_days,
        )

        app.include_router(routes.router)
        config = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=9910,
            log_level=self.log_level.lower(),
        )
        server = uvicorn.Server(config)
        await server.serve()


class DataReturn(BaseModel):
    object_id: str


class DownloadFileTypes(StrEnum):
    BMP = "bmp"
    JPG = "jpg"
    JPEG = "jpeg"
    ICO = "ico"
    PNG = "png"
    PDF = "pdf"
    SVG = "svg"
    TXT = "txt"


class DownloadAction(StrEnum):
    DOWNLOAD = "download"
    VIEW = "view"
    VIEW_RAW = "view_raw"


class NemesisApiRoutes():
    storage: StorageInterface
    rabbitmq_connection_uri: str
    alerter: AlerterInterface
    db: NemesisDb
    es_client: AsyncElasticsearch
    producers: Dict[NemesisQueue, MessageQueueProducerInterface]
    assessment_id: str
    reprocessing_workers: int
    storage_expiration_days: int

    def __init__(
        self,
        storage: StorageInterface,
        rabbitmq_connection_uri: str,
        alerter: AlerterInterface,
        db: NemesisDb,
        es_client: AsyncElasticsearch,
        queues: Dict[NemesisQueue, MessageQueueProducerInterface],
        assessment_id: str,
        reprocessing_workers: int,
        storage_expiration_days: int,
    ) -> None:
        super().__init__()
        self.storage = storage
        self.rabbitmq_connection_uri = rabbitmq_connection_uri
        self.alerter = alerter
        self.db = db
        self.es_client = es_client
        self.producers = queues
        self.assessment_id = assessment_id
        self.reprocessing_workers = reprocessing_workers
        self.storage_expiration_days = storage_expiration_days
        self.router = APIRouter()
        self.router.add_api_route("/", self.home, methods=["GET"])
        self.router.add_api_route("/ready", self.ready, methods=["GET"])
        self.router.add_api_route("/reset", self.reset, methods=["POST"])
        self.router.add_api_route("/reprocess", self.reprocess, methods=["POST"])
        self.router.add_api_route("/data", self.get_file, methods=["GET"])
        self.router.add_api_route("/data", self.post_data, methods=["POST"])
        self.router.add_api_route("/file", self.post_file, methods=["POST"])
        self.router.add_api_route("/download/{id}", self.download, methods=["GET"])

    async def home(self):
        return Response()

    async def ready(self):
        """
        Used for readiness probes.
        """
        return Response()

    async def reset(self):
        """When called, purges Postgres, Elastic, RabbitMQ, and datalake files."""
        await logger.ainfo("Clearing datastore!")

        # first purge all RabbitMQ queue messages
        await logger.ainfo("Purging RabbitMQ Queues.")
        await purge_rabbit_mq_queues(self.rabbitmq_connection_uri)

        # next clear the postgres database
        await logger.ainfo("Clearing the PostgreSQL database.")
        await self.db.clear_database()

        # then clear elasticsearch
        await logger.ainfo("Clearing Elasticsearch indexes")
        for ES_INDEX in ALL_ES_INDICIES:
            if await self.es_client.indices.exists(index=ES_INDEX):
                await logger.ainfo("Clearing Elastic index", index=ES_INDEX)
                await self.es_client.indices.delete(index=ES_INDEX)

        # and finally clear the files from the datalake
        await logger.ainfo("Deleting files in the datalake.")
        await self.storage.delete_all_files()

    async def reprocess(self):
        """When called, triggers the reprocessing of all existing data messages."""

        producers = self.producers

        async def reprocess_post_data(message_bytes) -> None:
            """
            Reprocesses raw /data POST message bytes.
            We don't have all the error handling of post_data since only
            successful messages are saved off.
            """
            nonlocal producers
            global logger

            body_string = message_bytes.decode("utf-8")
            json_data = json.loads(body_string)
            data_type = json_data["metadata"]["data_type"]
            obj = Parse(message_bytes, MAP[data_type]())
            if obj.metadata.data_type in producers:
                producer = producers[obj.metadata.data_type]
                await producer.Send(obj.SerializeToString())

        def exception_handler(e, args):
            logger.exception("Error reprocessing message bytes", args=args)

        # await self.alerter.alert("*Clearing datastore and triggering data reprocessing!*")
        await logger.ainfo("Clearing datastore and triggering data reprocessing!")

        # first purge all RabbitMQ queue messages
        await logger.ainfo("Purging RabbitMQ Queues.")
        await purge_rabbit_mq_queues(self.rabbitmq_connection_uri)

        # next clear the postgres database
        await logger.ainfo("Clearing the PostgreSQL database.")
        await self.db.clear_database()

        # then clear elasticsearch
        await logger.ainfo("Clearing Elasticsearch indexes")
        for ES_INDEX in ALL_ES_INDICIES:
            if await self.es_client.indices.exists(index=ES_INDEX):
                await logger.ainfo("Clearing Elastic index", index=ES_INDEX)
                await self.es_client.indices.delete(index=ES_INDEX)

        # finally pull all existed messages and submit each for reprocessing
        # old : async for message_bytes in self.db.get_api_data_messages():
        #           await self.reprocess_post_data(message_bytes)

        total_file_count = 0
        wrapped_reprocess_post_data = return_args_and_exceptions(reprocess_post_data, exception_handler)
        await logger.ainfo("Resubmitting all existing messages for processing")

        try:
            async for result in map_unordered(wrapped_reprocess_post_data, self.db.get_api_data_messages(), limit=self.reprocessing_workers):
                total_file_count += 1
        except Exception as e:
            await logger.awarn("Error reprocessing message", e=e)

        await logger.ainfo(f"Completed reprocessing {total_file_count} files /data POST messages")
        return Response()

    @aio.time(Summary("get_file", "GET file"))  # type: ignore
    async def get_file(self, storage_id: str) -> Response:
        file_uuid_str = base64.b64decode(storage_id).decode("utf-8")
        file_uuid = uuid.UUID(file_uuid_str)

        with await self.storage.download(file_uuid) as file:
            return FileResponse(file.name)

    @aio.time(Summary("data_post", "Data POST"))  # type: ignore
    async def post_data(self, request: Request) -> Dict[str, str]:
        # first parse the message as a JSON object so we can extract out the message data_type
        try:
            body_bytes = await request.body()
            body_string = body_bytes.decode("utf-8")
            json_data = json.loads(body_string)
        except:
            raise HTTPException(status_code=400, detail="Invalid message")

        if "metadata" not in json_data or "data_type" not in json_data["metadata"]:
            raise HTTPException(status_code=400, detail="Invalid metadata")

        data_type = json_data["metadata"]["data_type"]
        if data_type not in MAP:
            raise HTTPException(status_code=400, detail="Invalid metadata data_type")

        try:
            obj = Parse(body_bytes, MAP[data_type]())
        except:
            raise HTTPException(status_code=400, detail=f"Invalid {data_type} message")

        try:
            expiration_string = json_data["metadata"]["expiration"]
            expiration = datetime.strptime(expiration_string, "%Y-%m-%dT%H:%M:%S.000Z")
        except:
            raise HTTPException(status_code=400, detail=f"Invalid expiration value in metadata field")

        await logger.ainfo("Received data message", data_type=obj.metadata.data_type)

        # make sure we filter out registry values we're not currently supporting
        if data_type == "registry_value":
            i = 0
            while i < len(obj.data):
                # check if we want this registry value to be emitted to the pipeline
                tags = await include_registry_value(key=obj.data[i].key, value_name=obj.data[i].value_name, value_kind=obj.data[0].value_kind, value=obj.data[0].value)
                if tags:
                    obj.data[i].tags = tags
                    i += 1
                else:
                    del obj.data[i]

        id_ = str(uuid.uuid4())
        obj.metadata.message_id = id_

        # save off the raw POST message for possible replay later
        await self.db.add_api_data_message(id_, body_bytes, expiration)

        if obj.metadata.data_type in self.producers:
            producer = self.producers[obj.metadata.data_type]
            await producer.Send(obj.SerializeToString())

        return {"object_id": id_}

    @aio.time(Summary("post_file", "POST file"))  # type: ignore
    async def post_file(self, request: Request) -> Dict[str, str]:

        await logger.ainfo("Received file upload request")
        start = time.time()

        try:
            content_type = request.headers["content-type"]
            with tempfile.NamedTemporaryFile() as tmpfile:
                # handle raw binary file uploads
                if content_type == "application/octet-stream":
                    async with aiofiles.open(tmpfile.name, "wb") as f:
                        async for chunk in request.stream():
                            await f.write(chunk)
                # handle large file multi-part uploads
                # Ref - https://stackoverflow.com/a/73443824
                elif content_type.startswith("multipart/form-data"):
                    file_ = FileTarget(tmpfile.name)
                    parser = StreamingFormDataParser(headers=request.headers)
                    parser.register('file', file_)
                    async for chunk in request.stream():
                        parser.data_received(chunk)
                else:
                    raise HTTPException(status_code=422, detail=f"Content type '{content_type}' not allowed.")
                end = time.time()
                file_size = os.path.getsize(tmpfile.name)
                await logger.ainfo(f"File ({file_size} bytes) uploaded in {(end-start):.2f} seconds")
                # the first file that comes in will set the bucket file expiry policy (for now)
                file_uuid = await self.storage.upload(tmpfile.name, self.storage_expiration_days)
                return {"object_id": str(file_uuid)}
        except ClientDisconnect:
            await logger.awarning("Client Disconnected")
        except Exception as e:
            await logger.aerror(f"Exception in file upload: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"There was an error uploading the file: {e}")

    @aio.time(Summary("download", "Download file"))  # type: ignore
    async def download(self, id: uuid.UUID, name: Optional[str] = None, action: Optional[DownloadAction] = None) -> Response:
        content_type = "application/octet-stream"
        content_disposition: Optional[str] = None

        if name:
            filename = urllib.parse.quote(name)
            filetype = name.split(".")[-1].lower() if name else None
        else:
            filename = str(id)
            filetype = None

        if action is None or action == DownloadAction.DOWNLOAD:
            content_disposition = f'attachment; filename="{filename}"'
        else:
            content_disposition = f'inline; filename="{filename}"'

        if action == DownloadAction.VIEW_RAW:
            content_type = "text/plain"
        else:
            match filetype:
                case DownloadFileTypes.BMP:
                    content_type = "image/bmp"
                case DownloadFileTypes.ICO:
                    content_type = "image/vnd.microsoft.icon"
                case DownloadFileTypes.JPEG:
                    content_type = "image/jpeg"
                case DownloadFileTypes.JPG:
                    content_type = "image/jpeg"
                case DownloadFileTypes.PDF:
                    content_type = "application/pdf"
                case DownloadFileTypes.PNG:
                    content_type = "image/png"
                case DownloadFileTypes.SVG:
                    content_type = "image/svg+xml"
                case DownloadFileTypes.TXT:
                    content_type = "text/plain"
                case _:
                    content_type = "text/plain"

        headers = {
            "X-Content-Type-Options": "nosniff",
        }

        if content_disposition:
            headers["Content-Disposition"] = content_disposition

        try:
            await logger.ainfo("Received file download request", file_id=id)
            # download and signal we don't want to delete the file
            with await self.storage.download(id, False) as file:
                # set a background task to delete the file after serving
                #   ref - https://github.com/tiangolo/fastapi/issues/2152#issuecomment-889282903
                return FileResponse(file.name, background=BackgroundTask(os.remove, file.name), media_type=content_type, headers=headers)
        except Exception as e:
            await logger.aerror(message="Failed to download file", file_uuid=id, exception=e)
            raise HTTPException(status_code=404, detail="File not found")

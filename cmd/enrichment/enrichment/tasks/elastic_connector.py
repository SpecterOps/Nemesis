# Standard Libraries
import asyncio
import os
import urllib.parse
import uuid
from collections.abc import Iterable
from typing import Any, Coroutine, List

# 3rd Party Libraries
import nemesispb.nemesis_pb2 as pb
import structlog
from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk
from google.protobuf.json_format import MessageToDict
from nemesiscommon import constants
from nemesiscommon.constants import ElasticIndex
from nemesiscommon.messaging import MessageQueueConsumerInterface
from nemesiscommon.storage import StorageInterface
from nemesiscommon.tasking import TaskInterface
from prometheus_async import aio
from prometheus_client import Summary

logger = structlog.get_logger(module=__name__)


class ElasticConnector(TaskInterface):
    storage: StorageInterface
    es_client: AsyncElasticsearch
    public_kibana_url: str
    web_api_url: str

    # Queues
    auth_data_q: MessageQueueConsumerInterface
    extracted_hash_q: MessageQueueConsumerInterface
    file_data_enriched_q: MessageQueueConsumerInterface
    file_data_plaintext_q: MessageQueueConsumerInterface
    file_info_q: MessageQueueConsumerInterface
    host_info_q: MessageQueueConsumerInterface
    named_pipe_q: MessageQueueConsumerInterface
    network_connection_q: MessageQueueConsumerInterface
    process_enriched_q: MessageQueueConsumerInterface
    registry_value_q: MessageQueueConsumerInterface
    service_enriched_q: MessageQueueConsumerInterface
    tasks_set = set()
    es_submit_queue = asyncio.Queue()

    def __init__(
        self,
        storage: StorageInterface,
        es_client: AsyncElasticsearch,
        web_api_url: str,
        public_kibana_url: str,
        auth_data_q: MessageQueueConsumerInterface,
        extracted_hash_q: MessageQueueConsumerInterface,
        file_data_enriched_q: MessageQueueConsumerInterface,
        file_data_plaintext_q: MessageQueueConsumerInterface,
        file_data_sourcecode_q: MessageQueueConsumerInterface,
        file_info_q: MessageQueueConsumerInterface,
        host_info_q: MessageQueueConsumerInterface,
        named_pipe_q: MessageQueueConsumerInterface,
        network_connection_q: MessageQueueConsumerInterface,
        process_enriched_q: MessageQueueConsumerInterface,
        registry_value_q: MessageQueueConsumerInterface,
        service_enriched_q: MessageQueueConsumerInterface,
    ):
        self.storage = storage
        self.es_client = es_client
        self.web_api_url = web_api_url
        self.public_kibana_url = public_kibana_url

        self.auth_data_q = auth_data_q
        self.extracted_hash_q = extracted_hash_q
        self.file_data_enriched_q = file_data_enriched_q
        self.file_data_plaintext_q = file_data_plaintext_q
        self.file_data_sourcecode_q = file_data_sourcecode_q
        self.file_info_q = file_info_q
        self.host_info_q = host_info_q
        self.named_pipe_q = named_pipe_q
        self.network_connection_q = network_connection_q
        self.process_enriched_q = process_enriched_q
        self.registry_value_q = registry_value_q
        self.service_enriched_q = service_enriched_q

    async def create_task(self, func: Coroutine) -> None:
        task = asyncio.create_task(func)
        self.tasks_set.add(task)
        task.add_done_callback(self.tasks_set.discard)

    async def run(self) -> None:
        await logger.ainfo("Starting the ElasticConnector")

        tasks = [
            self.auth_data_q.Read(self.send_authentication_data),  # type: ignore
            self.extracted_hash_q.Read(self.send_extracted_hash),  # type: ignore
            self.file_data_enriched_q.Read(self.send_file_data_enriched),  # type: ignore
            self.file_data_plaintext_q.Read(self.send_file_data_plaintext),  # type: ignore
            self.file_data_sourcecode_q.Read(self.send_file_data_sourcecode),  # type: ignore
            self.file_info_q.Read(self.send_file_info),  # type: ignore
            self.host_info_q.Read(self.send_host_info),  # type: ignore
            self.named_pipe_q.Read(self.send_named_pipe),  # type: ignore
            self.network_connection_q.Read(self.send_network_connection),  # type: ignore
            self.process_enriched_q.Read(self.send_process_enriched),  # type: ignore
            self.registry_value_q.Read(self.send_registry_value),  # type: ignore
            self.service_enriched_q.Read(self.send_service_enriched),  # type: ignore
            self.consumer(),
        ]

        for task in tasks:
            await self.create_task(task)

        await asyncio.Future()

    async def send_authentication_data(self, q_msg: pb.AuthenticationDataIngestionMessage) -> None:
        await self.send_without_processing(q_msg, constants.ES_INDEX_AUTHENTICATION_DATA)

    async def send_extracted_hash(self, q_msg: pb.ExtractedHashMessage) -> None:
        await self.send_without_processing(q_msg, constants.ES_INDEX_EXTRACTED_HASH)

    async def send_file_info(self, q_msg: pb.FileInformationIngestionMessage) -> None:
        await self.send_without_processing(q_msg, constants.ES_INDEX_FILE_INFORMATION)

    async def send_host_info(self, q_msg: pb.HostInformationIngestionMessage) -> None:
        await self.send_without_processing(q_msg, constants.ES_INDEX_HOST_INFORMATION)

    async def send_file_data_enriched(self, q_msg: pb.FileDataEnrichedMessage) -> None:
        await self.process_file_data_enriched(q_msg)

    async def send_file_data_plaintext(self, q_msg: pb.FileDataPlaintextMessage) -> None:
        await self.process_file_data_plaintext(q_msg)

    async def send_file_data_sourcecode(self, q_msg: pb.FileDataSourcecodeMessage) -> None:
        await self.process_file_data_sourcecode(q_msg)

    async def send_process_enriched(self, q_msg: pb.ProcessEnrichedMessage) -> None:
        await self.send_without_processing(q_msg, constants.ES_INDEX_PROCESS_CATEGORY)

    async def send_service_enriched(self, q_msg: pb.ServiceEnrichedMessage) -> None:
        await self.send_without_processing(q_msg, constants.ES_INDEX_SERVICE_ENRICHED)

    async def send_registry_value(self, q_msg: pb.RegistryValueIngestionMessage) -> None:
        await self.send_without_processing(q_msg, constants.ES_INDEX_REGISTRY_VALUE)

    async def send_named_pipe(self, q_msg: pb.NamedPipeIngestionMessage) -> None:
        await self.send_without_processing(q_msg, constants.ES_INDEX_NAMED_PIPE)

    async def send_network_connection(self, q_msg: pb.NetworkConnectionIngestionMessage) -> None:
        await self.send_without_processing(q_msg, constants.ES_INDEX_NETWORK_CONNECTION)

    @aio.time(Summary("elastic_process_file_data_enriched", "Time spent processing a file_data_enriched topic"))  # type: ignore
    async def process_file_data_enriched(self, event: pb.FileDataEnrichedMessage):
        """
        Main function to process file_data_enriched events.
        """
        metadata = MessageToDict(event.metadata)

        for d in event.data:
            # grab the data entry for this iteration and merge it with the parent metadata
            dataDict = MessageToDict(d)
            dataDict["metadata"] = metadata
            object_id = d.object_id

            enc_file_name = urllib.parse.quote(d.name)
            dataDict["objectIdURL"] = f"{self.web_api_url}download/{object_id}?name={enc_file_name}"

            if "extractedPlaintext" in dataDict:
                plainext_object_id = dataDict["extractedPlaintext"]
                if "error" not in plainext_object_id:
                    dataDict[
                        "extractedPlaintextURL"
                    ] = f"{self.public_kibana_url}app/discover#/?_a=(filters:!((query:(match_phrase:(objectId:'{plainext_object_id}')))),index:'0e93c4fb-c291-4d22-84da-e49ec27b959a')&_g=(time:(from:now-1y%2Fd,to:now))"

            if "convertedPdf" in dataDict:
                pdf_object_id = dataDict["convertedPdf"]
                if "error" not in pdf_object_id:
                    dataDict["convertedPdfURL"] = f"{self.web_api_url}download/{pdf_object_id}?name={enc_file_name}.pdf"

            # handle the case of when the file is a PDF
            if dataDict["path"].endswith(".pdf"):
                object_id = dataDict["objectId"]
                dataDict["convertedPdfURL"] = f"{self.web_api_url}download/{object_id}?name={enc_file_name}.pdf"

            if "extractedSource" in dataDict:
                extracted_source_id = dataDict["extractedSource"]
                if "error" not in extracted_source_id:
                    dataDict[
                        "extractedSourceURL"
                    ] = f"{self.web_api_url}download/{extracted_source_id}?name={enc_file_name}.zip"

            await self.send_to_elastic(constants.ES_INDEX_FILE_DATA_ENRICHED, dataDict)

    @aio.time(Summary("elastic_process_file_data_plaintext", "Time spent processing a file_data_plaintext topic"))  # type: ignore
    async def process_file_data_plaintext(self, event: pb.FileDataPlaintextMessage):
        """
        Main function to process file_data_plaintext events.
        """
        metadata = MessageToDict(event.metadata)

        for d in event.data:
            # grab the data entry for this iteration and merge it with the parent metadata
            data = MessageToDict(d)
            data["metadata"] = metadata

            # TODO: Change this to lookup the object size before downloading. See https://stackoverflow.com/questions/5315603/how-do-i-get-the-file-key-size-in-boto-s3
            file_uuid = uuid.UUID(d.object_id)

            with await self.storage.download(file_uuid) as temp_file:
                if os.path.getsize(temp_file.name) > 104857600:
                    await logger.aerror("Nemesis object_id over 100MB limit")
                else:
                    # index the plaintext if we have it
                    with open(temp_file.name, "r") as f:
                        data["text"] = f.read()

                        object_id = data["objectId"]
                        data["objectIdURL"] = f"{self.web_api_url}download/{object_id}"
                        originating_object_id = data["originatingObjectId"]
                        data[
                            "originatingObjectURL"
                        ] = f"{self.public_kibana_url}app/discover#/?_a=(filters:!((query:(match_phrase:(objectId:'{originating_object_id}')))),index:'26360ae8-a518-4dac-b499-ef682d3f6bac')&_g=(time:(from:now-1y%2Fd,to:now))"

                        if "originatingObjectConvertedPdf" in data:
                            pdf_object_id = data["originatingObjectConvertedPdf"]
                            data[
                                "originatingObjectConvertedPdfUrl"
                            ] = f"{self.web_api_url}download/{pdf_object_id}?name=pdf.pdf"

                        await self.send_to_elastic(constants.ES_INDEX_FILE_DATA_PLAINTEXT, data)

    @aio.time(Summary("elastic_process_file_data_sourcecode", "Time spent processing a file_data_sourcecode topic"))  # type: ignore
    async def process_file_data_sourcecode(self, event: pb.FileDataSourcecodeMessage):
        """
        Main function to process file_data_sourcecode events.
        """
        metadata = MessageToDict(event.metadata)

        for d in event.data:
            # grab the data entry for this iteration and merge it with the parent metadata
            data = MessageToDict(d)
            data["metadata"] = metadata

            # TODO: Change this to lookup the object size before downloading. See https://stackoverflow.com/questions/5315603/how-do-i-get-the-file-key-size-in-boto-s3
            file_uuid = uuid.UUID(d.object_id)

            with await self.storage.download(file_uuid) as temp_file:
                if os.path.getsize(temp_file.name) > 104857600:
                    await logger.aerror("Nemesis object_id over 100MB limit")
                else:
                    # index the text of the source code file
                    with open(temp_file.name, "rb") as f:
                        data["text"] = f.read().decode(encoding="utf-8", errors="ignore")
                        object_id = data["objectId"]
                        data["downloadURL"] = f"{self.web_api_url}download/{object_id}"
                        data[
                            "fileObjectURL"
                        ] = f"{self.public_kibana_url}app/discover#/?_a=(filters:!((query:(match_phrase:(objectId:'{object_id}')))),index:'26360ae8-a518-4dac-b499-ef682d3f6bac')&_g=(time:(from:now-1y%2Fd,to:now))"
                        await self.send_to_elastic(constants.ES_INDEX_FILE_DATA_SOURCECODE, data)

    @aio.time(
        Summary(
            "elastic_send_without_processing", "Time spent submitting process_enriched messages to Elastic/Postgres"
        )
    )  # type: ignore
    async def send_without_processing(
        self,
        q_msg: pb.AuthenticationDataIngestionMessage
        | pb.FileInformationIngestionMessage
        | pb.HostInformationIngestionMessage
        | pb.ProcessEnrichedMessage
        | pb.RegistryValueIngestionMessage
        | pb.ServiceEnrichedMessage
        | pb.ExtractedHashMessage,
        index: ElasticIndex,
    ):
        metadata = MessageToDict(q_msg.metadata)

        # Check if q_msg.data is Iterable
        if isinstance(q_msg.data, Iterable):
            for d in q_msg.data:
                # grab the data entry for this iteration and merge it with the parent metadata
                data = MessageToDict(d)
                data["metadata"] = metadata
                await self.send_to_elastic(index, data)
        else:
            data = MessageToDict(q_msg.data)
            data["metadata"] = metadata
            await self.send_to_elastic(index, data)

    @aio.time(Summary("send_to_elastic", "Time spent submitting data directly to Elastic"))  # type: ignore
    async def send_to_elastic(self, index: ElasticIndex, data: dict[str, Any]):
        await logger.adebug("Submitting document to Elastic", index=index)

        # try:
        #     resp = await self.es_client.index(index=index, document=data)

        #     # TODO: Make this work. Problem is when under lots of pressure, too many tasks get created and either
        #     #       memory/CPU exhaustion occurs from too many tasks and/or Elastic/nginx-ingress can't consume events fast enough and occasionally errors
        #     # resp = await self.create_task(
        #     #     self.es_client.index(index=index, document=data)
        #     # )
        #     if resp and ("result" in resp) and (resp["result"] != "created"):
        #         await logger.aerror(
        #             "Submitting to elastic failed", index=index, response=resp["result"]
        #         )
        # except ConnectionTimeout:
        #     await logger.aerror("Connection to Elastic timed out", index=index)
        # except Exception as e:
        #     await logger.aerror("Error submitting to Elastic", index=index, error=e)

        data["_index"] = index
        await self.es_submit_queue.put(data)

    async def consumer(self):
        logger.info("Starting Elastic consumer")
        timeout = 1.0  # Timeout in seconds
        docs_to_process = []
        num_batched_documents = 50

        while True:
            try:
                # Wait for up to timeout seconds for items to be added to the queue
                item = await asyncio.wait_for(self.es_submit_queue.get(), timeout=timeout)

                docs_to_process.append(item)

                num_docs = len(docs_to_process)
                if num_docs == num_batched_documents:
                    await logger.adebug("Submitting documents to Elastic", doc_count=num_docs)
                    await self.create_task(self.send_in_bulk_to_es(docs_to_process))
                    docs_to_process = []

            except asyncio.TimeoutError:
                # Timeout occurred - process the items we have so far
                num_docs = len(docs_to_process)
                if num_docs > 0:
                    # Process what we have right now
                    await logger.adebug(
                        "ES submit queue timeout hit. Processing queued up documents",
                        doc_count=num_docs,
                    )
                    await self.create_task(self.send_in_bulk_to_es(docs_to_process))
                    docs_to_process = []

                continue

    async def send_in_bulk_to_es(self, items):
        # Use async_bulk() to submit the actions as a single API call
        errors: List[Any]
        num_successful, errors = await async_bulk(self.es_client, items)  # type: ignore # ignoring because stats_only is False, so a List will be returned

        if num_successful == len(items):
            # All items were submitted successfully
            pass
        else:
            await logger.awarning(
                "Not all items were submitted to Elastic",
                num_successful=num_successful,
                num_items=len(items),
            )

            # Handle the results
            for result in errors:
                await logger.aerror("Failed to submit message to elastic", message=result)

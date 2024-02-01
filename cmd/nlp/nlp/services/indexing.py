# Standard Libraries
import os
import re
import time
import uuid

# 3rd Party Libraries
import nemesispb.nemesis_pb2 as pb
import structlog
from langchain.text_splitter import (RecursiveCharacterTextSplitter,
                                     TokenTextSplitter)
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores.elasticsearch import ElasticsearchStore
from nemesiscommon.messaging import MessageQueueConsumerInterface
from nemesiscommon.messaging_rabbitmq import SingleQueueRabbitMQWorker
from nemesiscommon.storage import StorageInterface
from nlp.settings import NLPSettings
from prometheus_async import aio
from prometheus_client import Summary


logger = structlog.get_logger(module=__name__)


def split(list_a, chunk_size):
    for i in range(0, len(list_a), chunk_size):
        yield list_a[i:i + chunk_size]


class IndexingService(SingleQueueRabbitMQWorker):
    cfg: NLPSettings
    storage: StorageInterface
    embeddings: HuggingFaceEmbeddings
    vector_store: ElasticsearchStore
    text_splitter: RecursiveCharacterTextSplitter

    def __init__(self, inputQ: MessageQueueConsumerInterface, cfg: NLPSettings, storage: StorageInterface) -> None:
        super().__init__(inputQ)

        self.storage = storage
        self.cfg = cfg

        chunk_size = int(self.cfg.text_chunk_size)
        chunk_overlap = int(chunk_size/15)

        self.embeddings = HuggingFaceEmbeddings(model_name=self.cfg.embedding_model)

        self.vector_store = ElasticsearchStore(
            es_url=self.cfg.elasticsearch_url,
            es_user=self.cfg.elasticsearch_user,
            es_password=self.cfg.elasticsearch_password,
            index_name=self.cfg.elastic_index_name,
            embedding=self.embeddings
        )

        # significantly faster than straight HuggingFace tokenization
        self.text_splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(
            encoding_name="cl100k_base",
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap
        )


    @aio.time(Summary("process_plaintext_indexing", "Time spent processing/indexing a plaintext topic."))  # type: ignore
    async def process_message(self, event: pb.FileDataPlaintextMessage) -> None:
        """ """

        for data in event.data:
            object_id = uuid.UUID(data.object_id)
            originating_object_id = data.originating_object_id
            originating_object_path = data.originating_object_path
            originating_object_converted_pdf = data.originating_object_converted_pdf
            source = event.metadata.source

            try:
                with await self.storage.download(object_id) as file:
                    with open(file.name, 'r') as f:

                        text = f.read()

                        if text.strip():
                            # split the text using our default splitter
                            start = time.time()
                            docs = self.text_splitter.split_text(text)
                            end = time.time()
                            await logger.ainfo(f"{len(docs)} documents split in {(end - start):.2f} seconds", object_id=object_id)

                            start = time.time()
                            await logger.ainfo(f"Loading {len(docs)} documents into the vector store", object_id=object_id)
                            for batch in split(docs, 10):
                                metadata = [
                                    {
                                        "source": source,
                                        "object_id": object_id,
                                        "originating_object_id": originating_object_id,
                                        "originating_object_path": originating_object_path,
                                        "originating_object_pdf": originating_object_converted_pdf,
                                    }
                                ] * len(batch)
                                await self.vector_store.aadd_texts(batch, metadata)
                            end = time.time()
                            await logger.ainfo(f"{len(docs)} total documents loaded into the vector store in {(end - start):.2f} seconds", object_id=object_id)

            except Exception as e:
                await logger.aexception(e, message="exception in processing a plaintext file")

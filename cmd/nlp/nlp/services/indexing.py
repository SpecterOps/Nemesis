# Standard Libraries
import asyncio
import os
import re
import time
import uuid

import nemesiscommon.constants as constants
# 3rd Party Libraries
import nemesispb.nemesis_pb2 as pb
import numpy as np
import structlog
from elasticsearch import Elasticsearch
from langchain.text_splitter import (RecursiveCharacterTextSplitter,
                                     TokenTextSplitter)
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores.elasticsearch import ElasticsearchStore
from nemesiscommon.messaging import (MessageQueueConsumerInterface,
                                     MessageQueueProducerInterface)
from nemesiscommon.storage import StorageInterface
from nemesiscommon.tasking import TaskInterface
from nlp.settings import NLPSettings
from prometheus_async import aio
from prometheus_client import Summary

logger = structlog.get_logger(module=__name__)


def wait_for_elasticsearch(elasticsearch_url: str, elasticsearch_user: str, elasticsearch_password: str):
    """
    Wait for a connection to be established with Nemesis' Elasticsearch container,
    and return the es_client object when a connection is established.
    """

    while True:
        try:
            es_client = Elasticsearch(elasticsearch_url, basic_auth=(elasticsearch_user, elasticsearch_password), verify_certs=False)
            es_client.info()
            return es_client
        except Exception:
            print(
                "Encountered an exception while trying to connect to Elasticsearch %s, trying again in %s seconds...",
                elasticsearch_url,
                5,
            )
            time.sleep(5)
            continue


def split(list_a, chunk_size):
    for i in range(0, len(list_a), chunk_size):
        yield list_a[i:i + chunk_size]


class IndexingService(TaskInterface):
    cfg: NLPSettings
    storage: StorageInterface
    embeddings: HuggingFaceEmbeddings
    vector_store: ElasticsearchStore
    text_splitter: RecursiveCharacterTextSplitter

    # Queues
    plaintext_data_q_in: MessageQueueConsumerInterface
    plaintext_data_chunk_q_in: MessageQueueConsumerInterface
    plaintext_data_chunk_q_out: MessageQueueProducerInterface

    def __init__(
            self,
            cfg: NLPSettings,
            storage: StorageInterface,
            plaintext_data_q_in: MessageQueueConsumerInterface,
            plaintext_data_chunk_q_in: MessageQueueConsumerInterface,
            plaintext_data_chunk_q_out: MessageQueueProducerInterface,
        ) -> None:

        self.cfg = cfg
        self.storage = storage
        self.plaintext_data_q_in = plaintext_data_q_in
        self.plaintext_data_chunk_q_in = plaintext_data_chunk_q_in
        self.plaintext_data_chunk_q_out = plaintext_data_chunk_q_out

        if self.cfg.normalize_embeddings.lower() == "true":
            encode_kwargs={'normalize_embeddings': True}
        else:
            encode_kwargs={'normalize_embeddings': False}

        self.embeddings = HuggingFaceEmbeddings(
            model_name=self.cfg.embedding_model,
            encode_kwargs=encode_kwargs
        )

        self.vector_store = ElasticsearchStore(
            es_url=self.cfg.elasticsearch_url,
            es_user=self.cfg.elasticsearch_user,
            es_password=self.cfg.elasticsearch_password,
            index_name=self.cfg.elastic_index_name,
            embedding=self.embeddings
        )

        ## use the tokenizer from the actual model
        # self.chunk_size = int(self.embeddings.client.max_seq_length-2)
        self.chunk_size = int(self.cfg.text_chunk_size)
        self.chunk_overlap = int(self.chunk_size/15)
        self.text_splitter = TokenTextSplitter.from_huggingface_tokenizer(
            self.embeddings.client.tokenizer,
            chunk_size=self.chunk_size,
            chunk_overlap=self.chunk_overlap
        )

        self.es_client = wait_for_elasticsearch(self.cfg.elasticsearch_url, self.cfg.elasticsearch_user, self.cfg.elasticsearch_password)

    async def run(self) -> None:
        await logger.ainfo("Starting the NLP indexing service")
        await logger.ainfo(f"Embedding model: {self.cfg.embedding_model}, text chunk_size: {self.chunk_size}, chunk_overlap: {self.chunk_overlap}, normalizing embeddings: {self.cfg.normalize_embeddings}")

        await asyncio.gather(
            self.plaintext_data_q_in.Read(self.handle_plaintext),               # type: ignore
            self.plaintext_data_chunk_q_in.Read(self.handle_plaintext_chunk),   # type: ignore
        )

        await asyncio.Future()

    async def handle_plaintext(self, q_msg: pb.FileDataPlaintextMessage) -> None:
        await self.process_plaintext(q_msg)

    async def handle_plaintext_chunk(self, q_msg: pb.FileDataPlaintextChunkMessage) -> None:
        await self.process_plaintext_chunk(q_msg)

    async def process_plaintext(self, event: pb.FileDataPlaintextMessage) -> None:
        """
        Handles the initial tokenizing/splitting of a plaintext document and publishes the
        chunked documents to plaintext_data_chunk_q_out.
        """

        for data in event.data:
            object_id = data.object_id
            originating_object_id = data.originating_object_id
            originating_object_path = data.originating_object_path
            size = data.size

            if size > self.cfg.plaintext_size_limit:
                await logger.awarning(f"Plaintext object is over the plaintext_size_limit of {self.cfg.plaintext_size_limit}, not indexing embeddings", object_id=object_id)
            else:
                try:
                    with await self.storage.download(object_id) as file:
                        with open(file.name, 'r') as f:
                            text = f.read()
                            if text.strip():
                                start = time.time()
                                docs = self.text_splitter.split_text(text)
                                end = time.time()
                                await logger.ainfo(f"{len(docs)} documents split in {(end - start):.2f} seconds", object_id=object_id)

                                for doc in docs:
                                    file_data_plaintext_chunk_msg = pb.FileDataPlaintextChunkMessage()
                                    file_data_plaintext_chunk_msg.chunk_size = len(doc)
                                    file_data_plaintext_chunk_msg.text = doc
                                    file_data_plaintext_chunk_msg.plaintext_object_id = object_id
                                    file_data_plaintext_chunk_msg.originating_object_id = originating_object_id
                                    file_data_plaintext_chunk_msg.originating_object_path = originating_object_path
                                    # send the chunk onto the processing queue
                                    await self.plaintext_data_chunk_q_out.Send(file_data_plaintext_chunk_msg.SerializeToString())
                except Exception as e:
                    await logger.aexception(e, message="exception in processing a plaintext file", object_id=object_id)

    async def process_plaintext_chunk(self, event: pb.FileDataPlaintextChunkMessage) -> None:
        """Ingests extracted plaintext chunks into the vector store."""

        metadata = [
            {
                "plaintext_object_id": event.plaintext_object_id,
                "chunk_size": event.chunk_size,
                "originating_object_id": event.originating_object_id,
                "originating_object_path": event.originating_object_path,
            }
        ]
        await self.vector_store.aadd_texts([event.text], metadata)

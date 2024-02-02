# Standard Libraries
import os
import re
import time
import uuid
import asyncio

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
import nemesiscommon.constants as constants
from nlp.settings import NLPSettings
from prometheus_async import aio
from prometheus_client import Summary
from elasticsearch import Elasticsearch
import numpy as np

logger = structlog.get_logger(module=__name__)


def split(list_a, chunk_size):
    for i in range(0, len(list_a), chunk_size):
        yield list_a[i:i + chunk_size]


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

        self.es_client = wait_for_elasticsearch(self.cfg.elasticsearch_url, self.cfg.elasticsearch_user, self.cfg.elasticsearch_password)


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
                                metadata = []

                                for b in batch:
                                    metadata.append(
                                        {
                                            "source": source,
                                            "object_id": object_id,
                                            "chunk_len": len(b),
                                            "originating_object_id": originating_object_id,
                                            "originating_object_path": originating_object_path,
                                            "originating_object_pdf": originating_object_converted_pdf,
                                        }
                                    )
                                await self.vector_store.aadd_texts(batch, metadata)
                            end = time.time()
                            await logger.ainfo(f"{len(docs)} total documents loaded into the vector store in {(end - start):.2f} seconds", object_id=object_id)

            except Exception as e:
                await logger.aexception(e, message="exception in processing a plaintext file")

            # make sure the main doc has been indexed
            plaintext_hits = 0
            retries = 5
            plaintext_id = -1

            while plaintext_hits == 0 and retries > 0:
                try:
                    plaintext_output = self.es_client.search(
                        index=constants.ES_INDEX_FILE_DATA_PLAINTEXT,
                        query={"term": {"objectId.keyword": object_id}},
                        source_includes=["objectId"]
                    )
                    plaintext_hits = plaintext_output["hits"]["total"]["value"]
                    if plaintext_hits == 0:
                        await asyncio.sleep(3)
                        retries = retries - 1
                    else:
                        plaintext_id = plaintext_output["hits"]["hits"][0]["_id"]
                        break
                except Exception as e:
                    await asyncio.sleep(3)
                    await logger.ainfo(f"Error: {e}")

            try:
                if plaintext_hits == 0:
                    await logger.ainfo(f"_Plaintext document not indexed in Elastic")
                elif plaintext_hits > 0:
                    vector_output = self.es_client.search(
                        index=self.cfg.elastic_index_name,
                        query={"term": {"metadata.object_id.keyword": object_id}},
                        source_includes=["vector", "metadata.chunk_len"]
                    )
                    vector_hits = vector_output["hits"]["total"]["value"]
                    if plaintext_id == -1:
                        await logger.ainfo(f"_id not retried for indexed plaintext document in Elastic")
                    if vector_hits > 0:
                        # average all the embeddings for this document and save the vector to the original plaintext document
                        vectors = [h["_source"]["vector"] for h in vector_output["hits"]["hits"]]
                        chunk_lens = [h["_source"]["metadata"]["chunk_len"] for h in vector_output["hits"]["hits"]]
                        chunk_embeddings = np.average(vectors, axis=0, weights=chunk_lens)
                        # chunk_embeddings = chunk_embeddings / np.linalg.norm(chunk_embeddings) # normalizes length to 1, don't think this is needed...
                        avg_embedding = chunk_embeddings.tolist()

                        # make sure the vector field is set to a dense vector first
                        mapping = {
                            "properties": {
                                "vector": {
                                    "type": "dense_vector",
                                    "dims": len(avg_embedding),
                                    "index": True,
                                    "similarity": "cosine"
                                }
                            }
                        }
                        output = self.es_client.indices.put_mapping(index=constants.ES_INDEX_FILE_DATA_PLAINTEXT, body=mapping)

                        # then add the vector in
                        self.es_client.update(index=constants.ES_INDEX_FILE_DATA_PLAINTEXT, id=plaintext_id, body={"doc": {"vector": avg_embedding}})

            except Exception as e:
                await logger.ainfo(f"Error: {e}")

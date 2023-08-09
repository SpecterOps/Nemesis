# Standard Libraries
import os
import re
import time
import uuid

# 3rd Party Libraries
import nemesispb.nemesis_pb2 as pb
import structlog
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.vectorstores import ElasticVectorSearch
from nemesiscommon.messaging import MessageQueueConsumerInterface
from nemesiscommon.messaging_rabbitmq import SingleQueueRabbitMQWorker
from nemesiscommon.storage import StorageInterface
from nlp.settings import NLPSettings
from prometheus_async import aio
from prometheus_client import Summary

logger = structlog.get_logger(module=__name__)


class IndexingService(SingleQueueRabbitMQWorker):
    cfg: NLPSettings
    storage: StorageInterface
    embeddings: HuggingFaceEmbeddings
    vector_store: ElasticVectorSearch
    text_splitter: RecursiveCharacterTextSplitter

    def __init__(self, inputQ: MessageQueueConsumerInterface, cfg: NLPSettings, storage: StorageInterface) -> None:
        super().__init__(inputQ)

        self.storage = storage
        self.cfg = cfg

        self.embeddings = HuggingFaceEmbeddings(model_name=self.cfg.embedding_model)
        self.vector_store = ElasticVectorSearch(embedding=self.embeddings, elasticsearch_url=self.cfg.elastic_connection_uri, index_name=self.cfg.elastic_index_name)

        # significantly faster than HuggingFace tokenization
        self.text_splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(chunk_size=500, chunk_overlap=0)

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
                print(f"object_id: {object_id}")
                with await self.storage.download(object_id) as file:
                    with open(file.name, 'r') as f:
                        # combine all repeated whitespace into single spaces
                        text = f.read()
                        text_processed = re.sub(r"\s+", " ", text)

                        # split the text using our default splitter
                        docs = self.text_splitter.split_text(text_processed)
                        total_words = len(text_processed.split())

                        if total_words > 0:
                            # construct the metadata dict for each split text
                            metadata = [
                                {
                                    "source": source,
                                    "object_id": object_id,
                                    "originating_object_id": originating_object_id,
                                    "originating_object_path": originating_object_path,
                                    "originating_object_pdf": originating_object_converted_pdf,
                                }
                            ] * len(docs)

                            await logger.ainfo(f"Loading {len(docs)} documents ({total_words} total words) into the vector store", object_id=object_id)

                            # load the documents into the vector store asynchronously
                            #   vector_store.aadd_texts() not yet implemented
                            start = time.time()
                            self.vector_store.add_texts(docs, metadata)
                            end = time.time()
                            await logger.ainfo(f"Documents loaded in {(end - start):.2f} seconds", object_id=object_id)

            except Exception as e:
                await logger.aexception(e, message="exception in processing a plaintext file")

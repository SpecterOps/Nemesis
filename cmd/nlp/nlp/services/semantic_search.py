# Standard Libraries
import re
import time
from typing import List

# 3rd Party Libraries
import structlog
from fastapi.responses import Response
from fastapi import APIRouter
from langchain.text_splitter import (RecursiveCharacterTextSplitter,
                                     TokenTextSplitter)
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores.elasticsearch import ElasticsearchStore
from nlp.settings import NLPSettings
from prometheus_async import aio
from prometheus_client import Summary
from pydantic import BaseModel

logger = structlog.get_logger(module=__name__)


class IndexingRequest(BaseModel):
    text: str
    object_id: str
    originating_object_id: str
    originating_object_path: str


class SemanticSearchRequest(BaseModel):
    search_phrase: str
    num_results: int


class SemanticSearchResult(BaseModel):
    text: str
    score: float
    source: str
    object_id: str
    originating_object_id: str
    originating_object_path: str
    originating_object_pdf: str


class SemanticSearchResults(BaseModel):
    results: List[SemanticSearchResult]


class SemanticSearchAPI():
    cfg: NLPSettings
    embeddings: HuggingFaceEmbeddings
    vector_store: ElasticsearchStore
    text_splitter: RecursiveCharacterTextSplitter

    def __init__(self, cfg: NLPSettings) -> None:
        super().__init__()

        self.cfg = cfg

        chunk_size = int(self.cfg.text_chunk_size)
        chunk_overlap = int(chunk_size/15)
        logger.info(f"semantic_search text chunk_size: {chunk_size}, chunk_overlap: {chunk_overlap}")

        self.embeddings = HuggingFaceEmbeddings(model_name=cfg.embedding_model)

        self.vector_store = ElasticsearchStore(
            es_url=self.cfg.elasticsearch_url,
            es_user=self.cfg.elasticsearch_user,
            es_password=self.cfg.elasticsearch_password,
            index_name=self.cfg.elastic_index_name,
            embedding=self.embeddings
        )

        # significantly faster than HuggingFace tokenization
        # self.text_splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
        self.text_splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(
            encoding_name="cl100k_base",
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap
        )

        self.router = APIRouter()
        self.router.add_api_route("/", self.home, methods=["GET"])
        self.router.add_api_route("/ready", self.ready, methods=["GET"])
        self.router.add_api_route("/semantic_search", self.semantic_search, methods=["POST"])
        self.router.add_api_route("/indexing", self.indexing, methods=["POST"])


    async def home(self):
        return Response()

    async def ready(self):
        """
        Used for readiness probes.
        """
        return Response()

    @aio.time(Summary("semantic_search", "Semantic search over indexed documents"))  # type: ignore
    async def semantic_search(self, request: SemanticSearchRequest):
        try:
            if not self.vector_store.client.indices.exists(index=self.cfg.elastic_index_name):
                return {"error": f"index_not_found_exception"}

            results = self.vector_store.similarity_search_with_score(request.search_phrase, k=request.num_results)

            search_results = SemanticSearchResults(results=[])

            for document, score in results:
                metadata = document.metadata
                search_result = SemanticSearchResult(
                    text=document.page_content,
                    score=score,
                    source=metadata["source"],
                    object_id=metadata["object_id"],
                    originating_object_id=metadata["originating_object_id"],
                    originating_object_path=metadata["originating_object_path"],
                    originating_object_pdf=metadata["originating_object_pdf"]
                )
                search_results.results.append(search_result)

            return search_results

        except Exception as e:
            await logger.aexception(e, message="exception in processing a semantic search request")
            return {"error": f"{e}"}

    @aio.time(Summary("indexing_request", "Indexing of document text"))  # type: ignore
    async def indexing(self, request: IndexingRequest):
        try:
            if request.text.strip():
                # split the text using our default splitter
                docs = self.text_splitter.split_text(request.text)

                # construct the metadata dict for each split text
                metadata = [
                    {
                        "object_id": request.object_id,
                        "originating_object_id": request.originating_object_id,
                        "originating_object_path": request.originating_object_path,
                    }
                ] * len(docs)

                await logger.ainfo(f"Loading {len(docs)} documents into the vector store", object_id=request.object_id)

                # load the documents into the vector store asynchronously
                start = time.time()
                await self.vector_store.add_texts(docs, metadata)
                end = time.time()
                await logger.ainfo(f"{len(docs)} documents loaded in {(end - start):.2f} seconds", object_id=request.object_id)

        except Exception as e:
            await logger.aexception(e, message="exception in processing a indexing request")
            return {"error": f"{e}"}

# Standard Libraries
import re
import time
from typing import List

# 3rd Party Libraries
import structlog
from fastapi import APIRouter
from fastapi.responses import Response
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores.elasticsearch import ElasticsearchStore
from nlp.settings import NLPSettings
from prometheus_async import aio
from prometheus_client import Summary
from pydantic import BaseModel

logger = structlog.get_logger(module=__name__)


class SemanticSearchRequest(BaseModel):
    search_phrase: str
    num_results: int


class SemanticSearchResult(BaseModel):
    text: str
    score: float
    plaintext_object_id: str
    originating_object_id: str
    originating_object_path: str


class SemanticSearchResults(BaseModel):
    results: List[SemanticSearchResult]


class SemanticSearchAPI():
    cfg: NLPSettings
    embeddings: HuggingFaceEmbeddings
    vector_store: ElasticsearchStore

    def __init__(self, cfg: NLPSettings) -> None:
        super().__init__()

        self.cfg = cfg

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

        self.router = APIRouter()
        self.router.add_api_route("/", self.home, methods=["GET"])
        self.router.add_api_route("/ready", self.ready, methods=["GET"])
        self.router.add_api_route("/semantic_search", self.semantic_search, methods=["POST"])


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
                plaintext_object_id = metadata["plaintext_object_id"] if "plaintext_object_id" in metadata else ""
                originating_object_id = metadata["originating_object_id"] if "originating_object_id" in metadata else ""
                originating_object_path = metadata["originating_object_path"] if "originating_object_path" in metadata else ""
                search_result = SemanticSearchResult(
                    text=document.page_content,
                    score=score,
                    plaintext_object_id=plaintext_object_id,
                    originating_object_id=originating_object_id,
                    originating_object_path=originating_object_path,
                )
                search_results.results.append(search_result)

            return search_results

        except Exception as e:
            await logger.aexception(e, message="exception in processing a semantic search request")
            return {"error": f"{e}"}

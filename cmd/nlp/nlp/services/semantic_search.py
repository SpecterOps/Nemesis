# Standard Libraries
import re
import time
from typing import List, Optional

# 3rd Party Libraries
import structlog
from elasticsearch import Elasticsearch
from fastapi import APIRouter
from fastapi.responses import Response
from langchain_community.embeddings import HuggingFaceEmbeddings
from nlp.settings import NLPSettings
from prometheus_async import aio
from prometheus_client import Summary
from pydantic import BaseModel

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


class SemanticSearchRequest(BaseModel):
    search_phrase: str
    file_path_include: Optional[str]
    file_path_exclude: Optional[str]
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

        self.es_client = wait_for_elasticsearch(
            self.cfg.elasticsearch_url,
            self.cfg.elasticsearch_user,
            self.cfg.elasticsearch_password
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
            if not self.es_client.indices.exists(index=self.cfg.elastic_index_name):
                return {"error": f"index_not_found_exception"}

            # doing all this manually as langchain's ElasticsearchIndex doesn't let us do the
            #   complex filtering queries that we want

            search_embeddings = self.embeddings.embed_query(request.search_phrase)

            filter = {"bool": {}}
            request_dict = request.dict()
            if "file_path_include" in request_dict and request_dict["file_path_include"]:
                file_path_include = request.file_path_include.replace("\\", "/")
                filter["bool"]["must"] = [{"wildcard": {"metadata.originating_object_path.keyword": {"value": file_path_include, "case_insensitive": True}}}]
            if "file_path_exclude" in request_dict and request_dict["file_path_exclude"]:
                file_path_exclude = request.file_path_exclude.replace("\\", "/")
                filter["bool"]["must_not"] = [{"wildcard": {"metadata.originating_object_path.keyword": {"value": file_path_exclude, "case_insensitive": True}}}]

            if not filter["bool"]:
                filter = {"match_all": {}}

            query = {
                "script_score": {
                    "query": filter,
                    "script": {
                        "source": "cosineSimilarity(params.query_vector, 'vector') + 1.0",
                        "params": {"query_vector": search_embeddings},
                    },
                }
            }

            response = self.es_client.search(index=self.cfg.elastic_index_name, query=query, size=request.num_results)

            search_results = SemanticSearchResults(results=[])

            for hit in response["hits"]["hits"]:
                metadata = hit["_source"]["metadata"]
                text = hit["_source"]["text"]
                score = hit["_score"]
                plaintext_object_id = metadata["plaintext_object_id"] if "plaintext_object_id" in metadata else ""
                originating_object_id = metadata["originating_object_id"] if "originating_object_id" in metadata else ""
                originating_object_path = metadata["originating_object_path"] if "originating_object_path" in metadata else ""

                search_result = SemanticSearchResult(
                    text=text,
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

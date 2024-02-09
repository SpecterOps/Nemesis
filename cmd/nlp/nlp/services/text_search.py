# Standard Libraries
import re
import time
from typing import List, Dict, Optional

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

class TextSearchRequest(BaseModel):
    search_phrase: str
    knn_candidates: Optional[int] = 100
    file_path_include: Optional[str]
    file_path_exclude: Optional[str]
    num_results: int

class TextSearchResult(BaseModel):
    id: str
    text: str
    score: float
    plaintext_object_id: str
    originating_object_id: str
    originating_object_path: str

class TextSearchResults(BaseModel):
    results: List[TextSearchResult]

class TextSearchAPI():
    cfg: NLPSettings
    embeddings: HuggingFaceEmbeddings

    def __init__(self, cfg: NLPSettings) -> None:
        super().__init__()

        self.cfg = cfg

        # by default should normally be false since we're using Cosine similarity
        #   that only considers vector direction and not magnitude, so we shouldn't
        #   worry about normalizing the vectors
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
        self.router.add_api_route("/fuzzy_search", self.fuzzy_search, methods=["POST"])
        self.router.add_api_route("/hybrid_search", self.hybrid_search, methods=["POST"])

    async def home(self):
        return Response()

    async def ready(self):
        """
        Used for readiness probes.
        """
        return Response()

    async def handle_elastic_results(self, response: dict):
        """Helper that transforms Elastic search results"""

        search_results = TextSearchResults(results=[])

        for hit in response["hits"]["hits"]:
            id = hit["_id"]
            metadata = hit["_source"]["metadata"]
            text = hit["_source"]["text"]
            score = hit["_score"]
            plaintext_object_id = metadata["plaintext_object_id"] if "plaintext_object_id" in metadata else ""
            originating_object_id = metadata["originating_object_id"] if "originating_object_id" in metadata else ""
            originating_object_path = metadata["originating_object_path"] if "originating_object_path" in metadata else ""
            search_result = TextSearchResult(
                id=id,
                text=text,
                score=score,
                plaintext_object_id=plaintext_object_id,
                originating_object_id=originating_object_id,
                originating_object_path=originating_object_path,
            )
            search_results.results.append(search_result)

        return search_results

    async def get_fuzzy_search_query(self, request: TextSearchRequest) -> str:
        """Helper that builds the appropriate fuzzy search match query."""

        query = {
            "bool": {
                "must": [
                    {
                        "multi_match": {
                            "query": request.search_phrase,
                            "fields": ["text", "metadata.originating_object_path"]
                        }
                    }
                ]
            }
        }

        request_dict = request.dict()
        if "file_path_include" in request_dict and request_dict["file_path_include"]:
            file_path_include = request.file_path_include.replace("\\", "/")
            query["bool"]["must"].append({"wildcard": {"metadata.originating_object_path.keyword": {"value": file_path_include, "case_insensitive": True}}})
        if "file_path_exclude" in request_dict and request_dict["file_path_exclude"]:
            file_path_exclude = request.file_path_exclude.replace("\\", "/")
            query["bool"]["must_not"] = [{"wildcard": {"metadata.originating_object_path.keyword": {"value": file_path_exclude, "case_insensitive": True}}}]

        return query

    async def get_semantic_search_query(self, request: TextSearchRequest) -> str:
        """Helper that builds the appropriate semantic search match query."""

        # generate embeddings for this query
        search_embeddings = self.embeddings.embed_query(request.search_phrase)

        filter = {"bool": {}}
        request_dict = request.dict()
        if "file_path_include" in request_dict and request_dict["file_path_include"]:
            file_path_include = request.file_path_include.replace("\\", "/")
            filter["bool"]["must"] = [{"wildcard": {"metadata.originating_object_path.keyword": {"value": file_path_include, "case_insensitive": True}}}]
        if "file_path_exclude" in request_dict and request_dict["file_path_exclude"]:
            file_path_exclude = request.file_path_exclude.replace("\\", "/")
            filter["bool"]["must_not"] = [{"wildcard": {"metadata.originating_object_path.keyword": {"value": file_path_exclude, "case_insensitive": True}}}]

        if filter["bool"]:
            query = {
                "field": "vector",
                "query_vector": search_embeddings,
                "k": request.num_results,
                "num_candidates": request.knn_candidates,
                "filter": {
                    filter
                }
            }
        else:
            query = {
                "field": "vector",
                "query_vector": search_embeddings,
                "k": request.num_results,
                "num_candidates": request.knn_candidates,
            }

        return query

    @aio.time(Summary("fuzzy_search", "Fuzzy text over indexed documents"))  # type: ignore
    async def fuzzy_search(self, request: TextSearchRequest):
        """Performs a fuzzy/BM25 text search for the query."""
        try:
            if not self.es_client.indices.exists(index=self.cfg.elastic_index_name):
                return {"error": f"index_not_found_exception"}

            query = await self.get_fuzzy_search_query(request)

            response = self.es_client.search(
                index=self.cfg.elastic_index_name,
                query=query,
                size=request.num_results
            )
            return await self.handle_elastic_results(response)

        except Exception as e:
            await logger.aexception(e, message="Exception in processing a fuzzy_search request")
            return {"error": f"{e}"}

    @aio.time(Summary("semantic_search", "Semantic search over indexed document vectors"))  # type: ignore
    async def semantic_search(self, request: TextSearchRequest):
        """Performs a KNN semantic vector search for the query."""
        try:
            if not self.es_client.indices.exists(index=self.cfg.elastic_index_name):
                return {"error": f"index_not_found_exception"}

            query = await self.get_semantic_search_query(request)

            response = self.es_client.search(
                index=self.cfg.elastic_index_name,
                knn=query,
                size=request.num_results
            )
            return await self.handle_elastic_results(response)

        except Exception as e:
            await logger.aexception(e, message="Exception in processing a semantic_search request")
            return {"error": f"{e}"}

    @aio.time(Summary("hybrid_search", "Hybrid fuzzy/vector text over indexed documents"))  # type: ignore
    async def hybrid_search(self, request: TextSearchRequest):
        """
        Performs a fuzzy/BM25 text search and a KNN semantic vector search for the query,
        rebalanced via Reciprocal Rank Fusion.
        """

        # get our fuzzy and semantic results
        fuzzy_results = await self.fuzzy_search(request)
        semantic_results = await self.semantic_search(request)

        # make sure we didn't get any error messages
        if isinstance(fuzzy_results, dict):
            return fuzzy_results
        if isinstance(semantic_results, dict):
            return semantic_results

        # double check that everything is sorted
        fuzzy_results = sorted(fuzzy_results.results, key=lambda x: x.score, reverse=True)
        semantic_results = sorted(semantic_results.results, key=lambda x: x.score, reverse=True)

        search_results = {
            "fuzzy_results": fuzzy_results,
            "semantic_results": semantic_results,
        }

        # return num_results of the reranked results
        return await self.reciprocal_rank_fusion(search_results, num_results=request.num_results)

    async def reciprocal_rank_fusion(self, search_results, num_results=20, k=60) -> TextSearchResults:
        """
        Combines two ranked lists of the same length, fuses the rankings based solely on the
        order of documents (w/ overlap) in each list.

        *sigh* let's do this ourselves because it's a paid feature in Elasticsearch
        """

        fused_scores = {}

        fuzzy_results = search_results["fuzzy_results"]
        semantic_results = search_results["semantic_results"]

        # get the set of unique documents
        unique_docs_dict = {}
        for results in (fuzzy_results, semantic_results):
            for result in results:
                id = result.id
                if id not in unique_docs_dict:
                    unique_docs_dict[id] = result
        unique_docs = unique_docs_dict.values()

        # get rankings for each document in each set
        fuzzy_result_ranks = [(rank, result.id) for (rank, result) in enumerate(sorted(fuzzy_results, key=lambda x: x.score, reverse=True), 1)]
        semantic_result_rank = [(rank, result.id) for (rank, result) in enumerate(sorted(semantic_results, key=lambda x: x.score, reverse=True), 1)]

        # get the fused ranking scores
        for result_rank in (fuzzy_result_ranks, semantic_result_rank):
            for (rank, id) in result_rank:
                fused_scores[id] = fused_scores.get(id, 0) + 1 / (k + rank)

        # rerank the unique docs based on the fused score
        combined_results_sorted = list(sorted(unique_docs, key=lambda x: fused_scores[x.id], reverse=True))

        # save a scaled score to each document
        for result in combined_results_sorted:
            result.score = round(fused_scores[result.id] * 30 * 100, 3)

        # only return up to num_results
        return TextSearchResults(results=combined_results_sorted[:num_results])

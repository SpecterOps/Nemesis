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

def min_max_scale(x: float, a: float = 0.0, b: float= 10.0):
    """
    Helper to scale our hybrid results for display.

    a = minimum display value
    b = maximum display value

    Min ~= 1/(100+60) (max RRF ranking for 10 results)
    Max ~= 1/(1+40) + 1/(1+60) (max RRF ranking)

    """
    min = 0.00625
    max = 0.0407
    return a + ((x - min)*(b-a))/(max - min)

class TextSearchRequest(BaseModel):
    search_phrase: str
    use_reranker: Optional[bool] = False
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
        self.router.add_api_route("/semantic_search", self.handle_semantic_search, methods=["POST"])
        self.router.add_api_route("/fuzzy_search", self.handle_fuzzy_search, methods=["POST"])
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

        # search both the text itself and the originating file path
        query = {
            "bool": {
                "must": [
                    {
                        "multi_match": {
                            "query": request.search_phrase,
                            "fields": ["text", "metadata.originating_object_path"],
                            "fuzziness": "AUTO"
                        }
                    }
                ],
                "must_not": []
            }
        }

        # check if we need to add a file filter
        request_dict = request.dict()
        if "file_path_include" in request_dict and request_dict["file_path_include"]:
            file_path_include = request.file_path_include.replace("\\", "/")
            for file_path_include_part in file_path_include.split("|"):
                query["bool"]["must"].append({"wildcard": {"metadata.originating_object_path.keyword": {"value": file_path_include_part, "case_insensitive": True}}})
        if "file_path_exclude" in request_dict and request_dict["file_path_exclude"]:
            file_path_exclude = request.file_path_exclude.replace("\\", "/")
            for file_path_exclude_part in file_path_exclude.split("|"):
                query["bool"]["must_not"].append({"wildcard": {"metadata.originating_object_path.keyword": {"value": file_path_exclude_part, "case_insensitive": True}}})

        return query

    async def get_semantic_search_query(self, request: TextSearchRequest, k: int = -1) -> str:
        """Helper that builds the appropriate semantic search match query."""

        k = request.num_results if k == -1 else k

        # generate embeddings for this query
        search_embeddings = self.embeddings.embed_query(request.search_phrase)

        # check if we need to add a file filter
        filter = {"bool": {}}
        request_dict = request.dict()
        if "file_path_include" in request_dict and request_dict["file_path_include"]:
            filter["bool"]["must"] = []
            file_path_include = request.file_path_include.replace("\\", "/")
            for file_path_include_part in file_path_include.split("|"):
                filter["bool"]["must"].append({"wildcard": {"metadata.originating_object_path.keyword": {"value": file_path_include_part, "case_insensitive": True}}})
        if "file_path_exclude" in request_dict and request_dict["file_path_exclude"]:
            filter["bool"]["must_not"] = []
            file_path_exclude = request.file_path_exclude.replace("\\", "/")
            for file_path_exclude_part in file_path_exclude.split("|"):
                filter["bool"]["must_not"].append({"wildcard": {"metadata.originating_object_path.keyword": {"value": file_path_exclude_part, "case_insensitive": True}}})

        if filter["bool"]:
            query = {
                "field": "vector",
                "query_vector": search_embeddings,
                "k": k,
                "num_candidates": k,
                "filter": filter
            }
        else:
            query = {
                "field": "vector",
                "query_vector": search_embeddings,
                "k": k,
                "num_candidates": k,
            }

        return query

    async def handle_fuzzy_search(self, request: TextSearchRequest):
        return await self.fuzzy_search(request)

    @aio.time(Summary("fuzzy_search", "Fuzzy text over indexed documents"))  # type: ignore
    async def fuzzy_search(self, request: TextSearchRequest, search_candidates: int = -1):
        """Performs a fuzzy/BM25 text search for the query."""
        try:
            if not self.es_client.indices.exists(index=self.cfg.elastic_index_name):
                return {"error": f"index_not_found_exception"}

            query = await self.get_fuzzy_search_query(request)

            size = request.num_results if search_candidates == -1 else search_candidates

            response = self.es_client.search(
                index=self.cfg.elastic_index_name,
                query=query,
                size=size
            )
            return await self.handle_elastic_results(response)

        except Exception as e:
            await logger.aexception(e, message="Exception in processing a fuzzy_search request")
            return {"error": f"{e}"}

    async def handle_semantic_search(self, request: TextSearchRequest):
        return await self.semantic_search(request)

    @aio.time(Summary("semantic_search", "Semantic search over indexed document vectors"))  # type: ignore
    async def semantic_search(self, request: TextSearchRequest, search_candidates: int = -1):
        """Performs a KNN semantic vector search for the query."""
        try:
            if not self.es_client.indices.exists(index=self.cfg.elastic_index_name):
                return {"error": f"index_not_found_exception"}

            query = await self.get_semantic_search_query(request, search_candidates)

            size = request.num_results if search_candidates == -1 else search_candidates

            response = self.es_client.search(
                index=self.cfg.elastic_index_name,
                knn=query,
                size=size
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
        # cast a 3x net for the initial queries that will be reduced with RRF
        start = time.time()
        fuzzy_results = await self.fuzzy_search(request, 3 * request.num_results)
        end = time.time()
        await logger.ainfo(f"RRF/hybrid fuzzy search completed in {(end - start):.2f} seconds for query: '{request.search_phrase}'")
        # make sure we didn't get any error messages
        if isinstance(fuzzy_results, dict):
            return fuzzy_results

        start = time.time()
        semantic_results = await self.semantic_search(request, 3 * request.num_results)
        end = time.time()
        await logger.ainfo(f"RRF/hybrid semantic search completed in {(end - start):.2f} seconds for query: '{request.search_phrase}'")
        # make sure we didn't get any error messages
        if isinstance(semantic_results, dict):
            return semantic_results

        # double check that everything is sorted
        fuzzy_results = sorted(fuzzy_results.results, key=lambda x: x.score, reverse=True)
        semantic_results = sorted(semantic_results.results, key=lambda x: x.score, reverse=True)

        search_results = {
            "fuzzy_results": fuzzy_results,
            "semantic_results": semantic_results,
        }

        # rerank the results using RRF
        return await self.reciprocal_rank_fusion(search_results, num_results=request.num_results)

    async def reciprocal_rank_fusion(self, search_results, num_results=20, k_fuzzy=40, k_semantic=60) -> TextSearchResults:
        """
        Combines two ranked lists of the same length, fuses the rankings based solely on the
        order of documents (w/ overlap) in each list.

        Weights fuzzy results ~40% more heavily than semantic search results.

        Ref - https://plg.uwaterloo.ca/~gvcormac/cormacksigir09-rrf.pdf

        *sigh* let's do this ourselves because it's a paid feature in Elasticsearch
        """

        fused_scores = {}

        fuzzy_results = search_results["fuzzy_results"]
        semantic_results = search_results["semantic_results"]

        # get the maximum BM25 search score for scaling our hybrid search results
        if not fuzzy_results or len(fuzzy_results) == 0:
            max_fuzzy_score = 10.0
        else:
            max_fuzzy_score = max(fuzzy_results, key=lambda x: x.score).score

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

        # get the fused ranking scores, weighting fuzzy text ~40% more heavily than semantic results
        for (rank, id) in fuzzy_result_ranks:
            fused_scores[id] = fused_scores.get(id, 0) + 1 / (k_fuzzy + rank)
        for (rank, id) in semantic_result_rank:
            fused_scores[id] = fused_scores.get(id, 0) + 1 / (k_semantic + rank)

        # rerank the unique docs based on the fused score
        combined_results_sorted = list(sorted(unique_docs, key=lambda x: fused_scores[x.id], reverse=True))

        # save a scaled score (for display) to each document
        #   the RRF scores are scaled to [0 - max fuzzy/BM25 score]
        for result in combined_results_sorted:
            result.score = round(min_max_scale(fused_scores[result.id], 0, max_fuzzy_score), 3)

        # only return up to num_results
        return TextSearchResults(results=combined_results_sorted[:num_results])

# Standard Libraries
import re
import time
from typing import List

# 3rd Party Libraries
import structlog
from fastapi.responses import Response
from fastapi_class.decorators import get, post
from fastapi_class.routable import Routable
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.vectorstores import ElasticVectorSearch
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


class SemanticSearchAPI(Routable):
    cfg: NLPSettings
    embeddings: HuggingFaceEmbeddings
    vector_store: ElasticVectorSearch
    text_splitter: RecursiveCharacterTextSplitter

    def __init__(self, cfg: NLPSettings) -> None:
        super().__init__()
        self.cfg = cfg
        embeddings = HuggingFaceEmbeddings(model_name=cfg.embedding_model)
        self.vector_store = ElasticVectorSearch(
            embedding=embeddings, elasticsearch_url=cfg.elastic_connection_uri, index_name=cfg.elastic_index_name
        )
        # significantly faster than HuggingFace tokenization
        self.text_splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(chunk_size=500, chunk_overlap=0)

    @get("/")
    async def home(self):
        return Response()

    @get("/ready")
    async def ready(self):
        """
        Used for readiness probes.
        """
        return Response()

    @aio.time(Summary("semantic_search", "Semantic search over indexed documents"))  # type: ignore
    @post("/semantic_search")
    async def semantic_search(self, request: SemanticSearchRequest):
        try:
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
    @post("/indexing")
    async def indexing(self, request: IndexingRequest):
        try:
            # combine all whitespace into single spaces
            text_processed = re.sub(r"\s+", " ", request.text)

            # split the text using our default splitter
            docs = self.text_splitter.split_text(text_processed)
            total_words = len(text_processed.split())

            # construct the metadata dict for each split text
            metadata = [
                {
                    "object_id": request.object_id,
                    "originating_object_id": request.originating_object_id,
                    "originating_object_path": request.originating_object_path,
                }
            ] * len(docs)

            await logger.ainfo(
                f"Loading {len(docs)} documents ({total_words} total words) into the vector store", object_id=request.object_id
            )

            # load the documents into the vector store asynchronously
            #   vector_store.aadd_texts() not yet implemented
            start = time.time()
            self.vector_store.add_texts(docs, metadata)
            end = time.time()
            await logger.ainfo(f"Documents loaded in {(end - start):.2f} seconds", object_id=request.object_id)

        except Exception as e:
            await logger.aexception(e, message="exception in processing a indexing request")
            return {"error": f"{e}"}

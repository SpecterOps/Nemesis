# Standard Libraries
import math
from typing import List, Dict, Optional

# 3rd Party Libraries
import structlog
from fastapi import APIRouter
from fastapi.responses import Response
from llm.settings import LLMSettings
from prometheus_async import aio
from prometheus_client import Summary
from pydantic import BaseModel
import rigging as rg
from litellm import get_max_tokens, encode, decode, acompletion

logger = structlog.get_logger(module=__name__)


class SummarizeRequest(BaseModel):
    text: str

class SummarizeResult(BaseModel):
    summary: str

class FileListingRequest(BaseModel):
    text: str

class FileListingResponse(BaseModel):
    category: str

class TextSummary(rg.Model):
    content: str

class FileListingCategory(rg.Model):
    content: str


class LLMApi():
    cfg: LLMSettings

    def __init__(self, cfg: LLMSettings) -> None:
        super().__init__()

        self.cfg = cfg

        self.router = APIRouter()
        self.router.add_api_route("/", self.home, methods=["GET"])
        self.router.add_api_route("/ready", self.ready, methods=["GET"])
        self.router.add_api_route("/summarize_text", self.handle_summarize_text, methods=["POST"])
        self.router.add_api_route("/categorize_file_listing", self.handle_file_listing, methods=["POST"])

    async def home(self):
        return Response()

    async def ready(self):
        """
        Used for readiness probes.
        """
        return Response()

    async def get_text_to_token_limit(self, text: str) -> str:
        """
        Takes a model and max token limit (minus 100 to give some room) and return up to those max tokens.
        """
        document_tokens = encode(model=self.cfg.llm_connection_string, text=text)
        return decode(model=self.cfg.llm_connection_string, tokens=document_tokens[0:(self.cfg.llm_model_max_tokens-100)])

    async def get_text_chunks(self, text: str) -> List[str]:
        """
        Given a model and a number of chunks, chunk everything up evenly to chunks
        under the model_max_tokens limit.

        Adapted from https://github.com/VectifyAI/LargeDocumentSummarization/blob/8a2551ce2abd0e82ef06600d084b43d7efdc2530/chunker.py
        By Vectify AI, no license
        """

        document_tokens = encode(model=self.cfg.llm_connection_string, text=text)
        document_size = len(document_tokens)

        # total chunk number
        K = math.ceil(document_size / self.cfg.llm_model_max_tokens)
        # average integer chunk size
        average_chunk_size = math.ceil(document_size / K)

        # number of chunks with average_chunk_size - 1
        shorter_chunk_number = K * average_chunk_size - document_size
        # number of chunks with average_chunk_size
        standard_chunk_number = K - shorter_chunk_number

        chunks = []
        chunk_start = 0
        for i in range(0, K):
            if i < standard_chunk_number:
                chunk_end = chunk_start + average_chunk_size
            else:
                chunk_end = chunk_start + average_chunk_size - 1
            chunk = document_tokens[chunk_start:chunk_end]
            chunks.append(decode(model=self.cfg.llm_connection_string, tokens=chunk))
            chunk_start = chunk_end

        await logger.ainfo(f"[get_text_chunks] get_text_chunks len(chunks): {len(chunks)}")

        return chunks

    async def get_chunk_summary(self, text: str) -> str:
        """
        Summarize a chunk of text with the passed model connection string.
        """

        if text == "":
            return ""

        chat = (
            rg.get_generator(self.cfg.llm_connection_string)
            .chat([
                {"role": "system", "content": "You are an expert in text summarization."},
                {"role": "user", "content": f"Summarize the following text chunk. Output your summary between {TextSummary.xml_tags()} tags.\n\n{text}"},
            ]).until_parsed_as(TextSummary)
            .run()
        )
        summary = chat.last.try_parse(TextSummary)

        if summary:
            return summary.content
        else:
            return ""

    async def get_summary_of_chunk_summaries(self, chunks: List[str]) -> str:
        """
        Take a number of chunk summaries and produce a meta-summary.

        Adapted from https://github.com/VectifyAI/LargeDocumentSummarization/blob/8a2551ce2abd0e82ef06600d084b43d7efdc2530/utils.py
            By Vectify AI, no license
        """
        if len(chunks) == 0:
            return ""
        elif len(chunks) == 1:
            return chunks[0]
        else:
            all_chunks = "\n\n".join(chunks)

            chat = (
                rg.get_generator(self.cfg.llm_connection_string)
                .chat([
                    {"role": "system", "content": "You are an expert in text summarization."},
                    {"role": "user", "content": f"You are given a list of summaries, each summary summarizes a chunk of a document in sequence. Combine a list of summaries into one global summary of the document. Output your summary between {TextSummary.xml_tags()} tags.\n\n{all_chunks}"},
                ]).until_parsed_as(TextSummary)
                .run()
            )
            summary = chat.last.try_parse(TextSummary)
            if summary:
                return summary.content
            else:
                return ""

    @aio.time(Summary("get_text_summary", "Summarizing text via a LLM"))  # type: ignore
    async def get_text_summary(self, text: str) -> str:
        """
        Summarizes the input text with the LiteLLM model defined in self.cfg.llm_connection_string

        If the text is under self.cfg.llm_model_max_tokens, the text is summarized with get_chunk_summary() and returned.

        If the input text is over self.cfg.llm_model_max_tokens, the text is chunked evenly with get_text_chunks(),
        each chunk is summarized with get_chunk_summary(), and the summaries are summarized with get_summary_of_chunk_summaries().
        """

        await logger.ainfo(f"[get_text_summary] llm_connection_string: {self.cfg.llm_connection_string}")

        if not self.cfg.llm_connection_string:
            return ""

        # chunk up our text
        chunks = await self.get_text_chunks(text)

        await logger.ainfo(f"[get_text_summary] len(chunks): {len(chunks)}")

        if chunks and len(chunks) == 1:
            # if our text is under llm_model_max_tokens, just return the chunk summary
            return await self.get_chunk_summary(chunks[0])
        else:
            # if our text is over llm_model_max_tokens, summarize chunks then summarize the summaries
            chunk_summaries = []
            for chunk in chunks:
                summary = await self.get_chunk_summary(chunk)
                if summary:
                    chunk_summaries.append(summary)

            await logger.ainfo(f"[get_text_summary] len(chunk_summaries): {len(chunk_summaries)}")

            if len(chunk_summaries) == 0:
                return ""
            elif len(chunk_summaries) == 1:
                return chunk_summaries[0]
            else:
                return self.get_summary_of_chunk_summaries(chunk_summaries)

    async def handle_summarize_text(self, request: SummarizeRequest):
        await logger.ainfo(f"[handle_summarize_text] request: {request}")
        summary = await self.get_text_summary(request.text)
        return SummarizeResult(summary=summary)

    @aio.time(Summary("get_file_listing_category", "Categorizing a process listing via a LLM"))  # type: ignore
    async def get_file_listing_category(self, text: str) -> str:
        """
        Takes a file listing and returns a predefined category.
        """

        categories = [
            "information_technology",
            "information_security",
            "operations",
            "accounting_finance",
            "research_and_development",
            "marketing_sales",
            "management",
            "human_resources",
            "sensitive_secret",
            "other"
        ]

        if not self.cfg.llm_connection_string:
            return ""

        # get the first ()`model_max_tokens` - 100) tokens from the listing so we
        #   don't overflow the context window
        listing_text = self.get_text_to_token_limit(text)

        all_categories = ",".join(categories)

        chat = (
            rg.get_generator(self.cfg.llm_connection_string)
            .chat([
                {"role": "system", "content": "You are a IT systems expert."},
                {"role": "user", "content": f"You are given file listing that you will classify as one of the following categories: {all_categories} . Output the selected category between {FileListingCategory.xml_tags()} tags.\n\n{listing_text}"},
            ]).until_parsed_as(FileListingCategory)
            .run()
        )
        category = chat.last.try_parse(FileListingCategory)
        if category:
            return category.content
        else:
            return ""

    async def handle_file_listing(self, request: FileListingRequest):
        category = await self.get_file_listing_category(request.text)
        return FileListingResponse(category=category)

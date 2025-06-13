# enrichment_modules/text_summarizer/analyzer.py
import asyncio
import json
import logging
import os
import tempfile
from typing import Annotated, Optional

import psycopg
import rigging as rg
import structlog
from common.models import EnrichmentResult, Transform
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from dapr.clients import DaprClient
from pydantic import StringConstraints

from file_enrichment_modules.module_loader import EnrichmentModule

logger = structlog.get_logger(module=__name__)

str_strip = Annotated[str, StringConstraints(strip_whitespace=True)]


class Summary(rg.Model):
    content: str_strip


class TextSummarizer(EnrichmentModule):
    def __init__(self):
        super().__init__("text_summarizer")
        self.storage = StorageMinio()

        logging.getLogger("litellm").setLevel(logging.INFO)  # not working how it should...

        # Check if rigging generator config is available
        self.rigging_generator = os.getenv("RIGGING_GENERATOR_SUMMARY")
        if not self.rigging_generator:
            logger.info("RIGGING_GENERATOR_SUMMARY environment variable not set - text summarization disabled")

        with DaprClient() as client:
            secret = client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_STRING")
            self.postgres_connection_string = secret.secret["POSTGRES_CONNECTION_STRING"]

    def _has_extracted_text_transform(self, object_id: str) -> tuple[bool, Optional[str]]:
        """
        Check if file has an extracted_text transform.
        Returns a tuple of (has_transform, transform_object_id)
        """
        try:
            with psycopg.connect(self.postgres_connection_string) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT transform_object_id
                        FROM transforms
                        WHERE object_id = %s AND type = 'extracted_text'
                        LIMIT 1
                        """,
                        (object_id,),
                    )
                    result = cur.fetchone()
                    if result:
                        return True, str(result[0])
                    return False, None
        except Exception as e:
            logger.error(f"Error checking for extracted_text transform: {e}")
            return False, None

    def should_process(self, object_id: str) -> bool:
        """Determine if this module should run."""
        if not self.rigging_generator:
            return False

        file_enriched = get_file_enriched(object_id)

        # Process if file is plaintext or has extracted_text transform
        has_transform, _ = self._has_extracted_text_transform(object_id)
        return file_enriched.is_plaintext or has_transform

    def _get_text_content(self, object_id: str) -> tuple[Optional[str], Optional[str]]:
        """
        Get plaintext content from file or extracted text transform.
        Returns a tuple of (content, source_object_id)
        """
        try:
            # Check if file is plaintext first
            file_enriched = get_file_enriched(object_id)

            if file_enriched.is_plaintext:
                try:
                    file_bytes = self.storage.download_bytes(object_id)
                    return file_bytes.decode("utf-8", errors="replace"), object_id
                except Exception as e:
                    logger.warning(f"Failed to decode plaintext file content: {e}")

            # If not plaintext or decode failed, look for extracted_text transform
            has_transform, transform_object_id = self._has_extracted_text_transform(object_id)
            if has_transform and transform_object_id:
                try:
                    transform_bytes = self.storage.download_bytes(transform_object_id)
                    return transform_bytes.decode("utf-8", errors="replace"), transform_object_id
                except Exception as e:
                    logger.error(f"Failed to get extracted text transform content: {e}")

            return None, None

        except Exception as e:
            logger.error(f"Error getting text content: {e}")
            return None, None

    async def _generate_summary(self, text_content: str) -> str:
        """Async function to generate summary using rigging."""
        max_retries = 3
        attempt = 0

        while attempt < max_retries:
            try:
                generator = rg.get_generator(self.rigging_generator)

                response = await generator.chat(
                    [
                        {
                            "role": "system",
                            "content": """You are a document summarization assistant. Create a concise but thorough
                        summary of the provided text. Focus on key points and main ideas. Include section headers
                        to organize the summary. Use markdown formatting.""",
                        },
                        {
                            "role": "user",
                            "content": f"Please summarize this text, outputing the summary between {Summary.xml_start_tag()}{Summary.xml_end_tag()} tags:\n\n{text_content}",
                        },
                    ]
                ).run()

                summary = response.last.try_parse(Summary)
                logger.info("Successfully generated summary")
                return summary.content

            except Exception as e:
                # Try to check if it's error 529 - need to handle different exception types
                error_str = str(e).lower()

                # Look for indications of a 529 error in the error message or response
                if "529" in error_str or "too many requests" in error_str or "rate limit" in error_str:
                    attempt += 1
                    if attempt < max_retries:
                        wait_time = 15
                        logger.warning(
                            f"Received what appears to be a rate limit error, waiting {wait_time} seconds before retry (attempt {attempt}/{max_retries})"
                        )
                        await asyncio.sleep(wait_time)
                    else:
                        logger.error("Max retries reached after apparent rate limit errors")
                        raise
                else:
                    # For any other error, log and re-raise immediately
                    logger.exception(e, message="Error generating summary")

    def _get_original_file_id(self, transform_object_id: str) -> Optional[str]:
        """
        Find the original file ID for an extracted text transform by checking
        which file has this transform_object_id in its transforms.
        """
        try:
            with psycopg.connect(self.postgres_connection_string) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT object_id
                        FROM transforms
                        WHERE transform_object_id = %s AND type = 'extracted_text'
                        LIMIT 1
                        """,
                        (transform_object_id,),
                    )
                    result = cur.fetchone()
                    if result:
                        return str(result[0])
            return None
        except Exception as e:
            logger.exception(e, message="Error finding original file for transform")
            return None

    def process(self, object_id: str) -> EnrichmentResult | None:
        """Process text content and generate summary using LLM."""
        try:
            # First, check if this is an extracted text file or a regular file
            # If it's an extracted_text transform, we need to find its original file
            original_file_id = None

            # Check if current object is already a transform (extracted_text)
            with psycopg.connect(self.postgres_connection_string) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT object_id FROM transforms
                        WHERE transform_object_id = %s AND type = 'extracted_text'
                        """,
                        (object_id,),
                    )
                    result = cur.fetchone()
                    if result:
                        # This means we're processing an extracted_text file directly
                        # We should use the original file ID for our transform
                        original_file_id = str(result[0])
                        logger.info(f"Processing extracted_text file. Original file is: {original_file_id}")

            # Get the text content to summarize
            text_content, source_object_id = self._get_text_content(object_id)
            if not text_content or not source_object_id:
                logger.error("No text content found to summarize")
                return None

            # Create the summary
            summary = asyncio.run(self._generate_summary(text_content))

            # Store the summary as a file
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_summary:
                tmp_summary.write(summary)
                tmp_summary.flush()
                summary_id = self.storage.upload_file(tmp_summary.name)

            # IMPORTANT CHANGE: Use the original_file_id (if found) for attaching the transform
            # This ensures the summary is attached to the original file, not the extracted text
            target_file_id = original_file_id if original_file_id else object_id

            # Create transform object
            summary_transform = Transform(
                type="text_summary",
                object_id=f"{summary_id}",
                metadata={
                    "file_name": "text_summary.md",
                    "display_type_in_dashboard": "markdown",
                    "display_title": "Text Summary",
                    "default_display": True,
                },
            )

            # Create the result with the transform
            enrichment_result = EnrichmentResult(
                module_name=self.name, dependencies=self.dependencies, transforms=[summary_transform]
            )

            # Override the object_id in the result to use the original file
            # This is a key fix - we're changing where the transform gets attached
            if original_file_id:
                logger.info(f"Attaching summary transform to original file: {original_file_id}")

                metadata = summary_transform.metadata or {}

                self._add_transform_to_file(original_file_id, "text_summary", f"{summary_id}", metadata)

                # Return None since we manually added the transform
                # This prevents the transform from being added to the extracted text file
                return None

            return enrichment_result

        except Exception as e:
            logger.exception(e, message="Error generating text summary")
            return None

    def _add_transform_to_file(self, object_id: str, transform_type: str, transform_object_id: str, metadata: dict):
        """Manually add a transform to a file in the database."""
        try:
            with psycopg.connect(self.postgres_connection_string) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO transforms (object_id, type, transform_object_id, metadata)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (
                            object_id,
                            transform_type,
                            transform_object_id,
                            json.dumps(metadata) if metadata else None,
                        ),
                    )
                conn.commit()
                logger.info(f"Added transform {transform_type} to file {object_id}")
        except Exception as e:
            logger.exception(e, message=f"Error adding transform to file {object_id}")


def create_enrichment_module() -> EnrichmentModule:
    return TextSummarizer()

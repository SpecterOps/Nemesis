# enrichment_modules/llm_credential_analysis/analyzer.py
import asyncio
import json
import logging
import os
import tempfile
from typing import Optional

import psycopg
import rigging as rg
import structlog
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from dapr.clients import DaprClient

from file_enrichment_modules.module_loader import EnrichmentModule

logger = structlog.get_logger(module=__name__)


class Credentials(rg.Model):
    content: str


def credentials_to_markdown(credentials: str) -> str:
    """Format extracted credentials as markdown report."""
    if not credentials or credentials.strip().lower() == "none":
        return "## LLM Credential Analysis\n\nNo credentials found in this document."

    lines = credentials.strip().split("\n")
    markdown = "## LLM Credential Analysis\n\n"
    markdown += "### Detected Credentials\n\n"

    for line in lines:
        if line.strip():
            markdown += f"- `{line.strip()}`\n"

    return markdown


class CredentialExtractor(EnrichmentModule):
    def __init__(self):
        super().__init__("llm_credential_analysis")
        self.storage = StorageMinio()

        logging.getLogger("litellm").setLevel(logging.INFO)  # not working how it should...

        # Check if rigging generator config is available
        self.rigging_generator = os.getenv("RIGGING_GENERATOR_CREDENTIALS")
        if not self.rigging_generator:
            logger.info("RIGGING_GENERATOR_CREDENTIALS environment variable not set - credential analysis disabled")

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
        print(f"file_enriched: {file_enriched}")

        # Process if file is plaintext or has extracted_text transform
        has_transform, _ = self._has_extracted_text_transform(object_id)
        print(f"has_transform: {has_transform}")
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

    async def _extract_credentials(self, text_content: str) -> str:
        """Async function to extract credentials with an LLM using rigging."""
        max_retries = 3
        attempt = 0

        while attempt < max_retries:
            try:
                generator = rg.get_generator(self.rigging_generator)

                response = await generator.chat(
                    [
                        {
                            "role": "system",
                            "content": "You are a cybersecurity expert extremely proficient at identifying credentials and passwords.",
                        },
                        {
                            "role": "user",
                            "content": f"If the following document contains any credentials or passwords, output each credential/password between on a separate line with no other details or explanation, and have the all the lines output between {Credentials.xml_start_tag()}{Credentials.xml_end_tag()} tags. If the document contains no credentials or passwords, output 'none' without the quotes, not wrapped in any tags.\n\nDocument:\n\n{text_content}\n\n",
                        },
                    ]
                ).run()

                print(f"last: {response.last}")

                credentials = response.last.try_parse(Credentials)
                if credentials:
                    return credentials.content
                else:
                    return ""

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
                    logger.exception(e, message="Error extracting credentials")

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
        """Process text content and extract credentials using LLM."""
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

            # Get the text content to extract credentials from
            text_content, source_object_id = self._get_text_content(object_id)
            if not text_content or not source_object_id:
                logger.error("No text content found to analyze")
                return None

            # See if there are any credentials to extract
            credentials = asyncio.run(self._extract_credentials(text_content))

            # Create a markdown report
            markdown_report = credentials_to_markdown(credentials)

            # Store the analysis as a file
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_credentials:
                tmp_credentials.write(markdown_report)
                tmp_credentials.flush()
                credentials_id = self.storage.upload_file(tmp_credentials.name)

            # IMPORTANT CHANGE: Use the original_file_id (if found) for attaching the transform
            # This ensures the analysis is attached to the original file, not the extracted text
            target_file_id = original_file_id if original_file_id else object_id

            # Create transform object
            credential_transform = Transform(
                type="llm_extracted_credentials",
                object_id=f"{credentials_id}",
                metadata={
                    "file_name": "extracted_credentials.md",
                    "display_type_in_dashboard": "markdown",
                    "display_title": "LLM-Extracted Credentials",
                    "default_display": True,
                },
            )

            # Create a finding if credentials were found
            findings = []
            if credentials and credentials.strip().lower() != "none":
                # Create display data for the finding
                display_data = FileObject(
                    type="finding_summary",
                    metadata={"summary": markdown_report},
                )

                # Create the finding
                finding = Finding(
                    category=FindingCategory.CREDENTIAL,
                    finding_name="llm_extracted_credentials",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=target_file_id,
                    severity=8,
                    raw_data={"credentials": credentials},
                    data=[display_data],
                )

                findings.append(finding)

            # Create the result with the transform and findings
            enrichment_result = EnrichmentResult(
                module_name=self.name,
                dependencies=self.dependencies,
                transforms=[credential_transform],
                findings=findings if findings else None,
            )

            # Override the object_id in the result to use the original file
            # This is a key fix - we're changing where the transform gets attached
            if original_file_id:
                logger.info(f"Attaching credential transform to original file: {original_file_id}")

                metadata = credential_transform.metadata or {}

                self._add_transform_to_file(
                    original_file_id, "llm_extracted_credentials", f"{credentials_id}", metadata
                )

                # If we have findings, add them manually too
                if findings:
                    for finding in findings:
                        self._add_finding_to_file(finding)

                # Return None since we manually added the transform
                # This prevents the transform from being added to the extracted text file
                return None

            return enrichment_result

        except Exception as e:
            logger.exception(e, message="Error extracting credentials from document")
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

    def _add_finding_to_file(self, finding: Finding):
        """Manually add a finding to the database."""
        try:
            with psycopg.connect(self.postgres_connection_string) as conn:
                with conn.cursor() as cur:
                    # Insert the finding
                    # Note: This is a simplified version - adjust to match your actual database schema
                    cur.execute(
                        """
                        INSERT INTO findings (
                            category, finding_name, origin_type, origin_name,
                            object_id, severity, raw_data, data
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            finding.category.value,
                            finding.finding_name,
                            finding.origin_type.value,
                            finding.origin_name,
                            finding.object_id,
                            finding.severity,
                            json.dumps(finding.raw_data) if finding.raw_data else None,
                            json.dumps([d.model_dump_json() for d in finding.data]) if finding.data else None,
                        ),
                    )
                conn.commit()
                logger.info(f"Added finding {finding.finding_name} to file {finding.object_id}")
        except Exception as e:
            logger.exception(e, message=f"Error adding finding to file {finding.object_id}")


def create_enrichment_module() -> EnrichmentModule:
    return CredentialExtractor()

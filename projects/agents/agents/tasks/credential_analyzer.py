"""Credential analysis agent using Pydantic AI."""

import json
import tempfile

import psycopg
import structlog
from common.models import FileObject, FindingCategory, FindingOrigin
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext
from pydantic_ai import Agent
from pydantic_ai.settings import ModelSettings

from agents.base_agent import BaseAgent
from agents.model_manager import ModelManager
from agents.prompt_manager import PromptManager
from agents.schemas import CredentialAnalysisResponse, CredentialWithContext

logger = structlog.get_logger(__name__)


def credentials_to_markdown(credentials: list[CredentialWithContext]) -> str:
    """Format extracted credentials as markdown report."""
    if not credentials:
        return "## LLM Credential Analysis\n\nNo credentials found in this document."

    markdown = "## LLM Credential Analysis\n\n"
    markdown += "### Detected Credentials\n\n"

    for i, cred in enumerate(credentials, 1):
        markdown += f"#### Credential {i}\n\n"
        markdown += f"**Credential:** `{cred.credential}`\n\n"
        markdown += f"**Context:**\n```\n{cred.context}\n```\n\n"

    return markdown


class CredentialAnalyzer(BaseAgent):
    """Agent for extracting credentials from text using LLM."""

    def __init__(self):
        super().__init__()
        self.prompt_manager = PromptManager()
        self.name = "Credential Analyzer"
        self.description = "Extracts credentials and passwords from text content using LLM analysis"
        self.agent_type = "llm_based"
        self.has_prompt = True
        self.llm_temperature = 0.2
        self.system_prompt = """You are a cybersecurity expert extremely proficient at identifying credentials and passwords.

Analyze the following document and extract any credentials or passwords you find. For each credential found, provide:
1. The credential itself (password, API key, token, etc.)
2. The surrounding textual context (2-3 lines before and after the credential to show where it was found)

Return your findings as a structured list. If no credentials are found, return an empty list."""
        self.storage = StorageMinio()

        from dapr.clients import DaprClient

        with DaprClient() as client:
            secret = client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_URL")
            self.postgres_connection_url = secret.secret["POSTGRES_CONNECTION_URL"]

    def _get_text_content(self, object_id: str) -> str:
        """Get text content from file or extracted_text transform."""
        try:
            file_enriched = get_file_enriched(object_id)

            if file_enriched.is_plaintext:
                try:
                    file_bytes = self.storage.download_bytes(object_id)
                    return file_bytes.decode("utf-8", errors="replace")
                except Exception as e:
                    logger.warning(f"Failed to decode plaintext file content: {e}")

            # Look for extracted_text transform
            with psycopg.connect(self.postgres_connection_url) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT transform_object_id
                        FROM transforms
                        WHERE object_id = %s AND type = 'extracted_text'
                        LIMIT 1
                        """,
                        (object_id,)
                    )
                    result = cur.fetchone()
                    transform_object_id = result[0] if result else None
            if transform_object_id:
                transform_object_id = str(transform_object_id)
                try:
                    transform_bytes = self.storage.download_bytes(transform_object_id)
                    return transform_bytes.decode("utf-8", errors="replace")
                except Exception as e:
                    logger.error(f"Failed to get extracted text transform content: {e}")

            return ""

        except Exception as e:
            logger.error(f"Error getting text content: {e}")
            return ""

    def get_prompt(self) -> str:
        """Get the credential analysis prompt from database or use default."""
        try:
            # Try to get prompt from database
            prompt_data = self.prompt_manager.get_prompt(self.name)

            if prompt_data:
                return prompt_data["prompt"]
            else:
                # No prompt in database, try to save default
                logger.info("No prompt found in database, initializing with default", agent_name=self.name)
                success = self.prompt_manager.save_prompt(self.name, self.system_prompt, self.description)
                if success:
                    logger.info("Default prompt saved to database", agent_name=self.name)
                else:
                    # This is expected during startup when event loop is running
                    logger.debug(
                        "Could not save default prompt to database (likely during startup)", agent_name=self.name
                    )

                return self.system_prompt

        except Exception as e:
            logger.warning("Error managing prompt, using default", agent_name=self.name, error=str(e))
            return self.system_prompt

    def execute(self, ctx: WorkflowActivityContext, activity_input: dict) -> dict:
        """Analyze credentials in the given file."""
        object_id = activity_input.get("object_id", "")

        logger.debug("credential_analysis activity started", object_id=object_id)

        model = ModelManager.get_model()

        if not model:
            logger.warning("No model available from ModelManager")
            return {"success": False, "error": "AI model not available for credential analysis"}

        try:
            # Get text content
            text_content = self._get_text_content(object_id)
            if not text_content:
                return {"success": False, "error": "No text content found to analyze"}

            # Get the current prompt from database or default
            current_prompt = self.get_prompt()

            agent = Agent(
                model=model,
                system_prompt=current_prompt,
                output_type=CredentialAnalysisResponse,
                instrument=ModelManager.is_instrumentation_enabled(),
                retries=3,
                model_settings=ModelSettings(temperature=self.llm_temperature),
            )

            prompt = f"""Document:

{text_content}"""

            result = agent.run_sync(prompt)
            logger.debug(
                "Credential LLM analysis completed",
                object_id=object_id,
                total_tokens=result.usage().total_tokens,
                request_tokens=result.usage().request_tokens,
                response_tokens=result.usage().response_tokens,
            )

            credentials = result.output.credentials

            # Create markdown report
            markdown_report = credentials_to_markdown(credentials)

            # Store the analysis as a file
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_credentials:
                tmp_credentials.write(markdown_report)
                tmp_credentials.flush()
                credentials_id = self.storage.upload_file(tmp_credentials.name)

            # Add transform to database
            with psycopg.connect(self.postgres_connection_url) as conn:
                with conn.cursor() as cur:
                    metadata = {
                        "file_name": "extracted_credentials.md",
                        "display_type_in_dashboard": "markdown",
                        "display_title": "LLM-Extracted Credentials",
                        "default_display": True,
                    }

                    cur.execute(
                        """
                        INSERT INTO transforms (object_id, type, transform_object_id, metadata)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (object_id, "llm_extracted_credentials", credentials_id, json.dumps(metadata))
                    )

                    # Create finding if credentials were found
                    if credentials:
                        display_data = FileObject(
                            type="finding_summary",
                            metadata={"summary": markdown_report},
                        )

                        cur.execute(
                            """
                            INSERT INTO findings (
                                category, finding_name, origin_type, origin_name,
                                object_id, severity, raw_data, data
                            )
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            (
                                FindingCategory.CREDENTIAL.value,
                                "llm_extracted_credentials",
                                FindingOrigin.ENRICHMENT_MODULE.value,
                                "credential_analyzer",
                                object_id,
                                8,
                                json.dumps({"credentials": [cred.model_dump() for cred in credentials]}),
                                json.dumps([display_data.model_dump()])
                            )
                        )
                conn.commit()

            logger.debug("Credential analysis completed", object_id=object_id)
            return {
                "success": True,
                "credentials_found": bool(credentials),
                "transform_id": credentials_id,
            }

        except Exception as e:
            logger.error("Credential analysis failed", object_id=object_id, error=str(e))
            return {"success": False, "error": str(e)}


def analyze_credentials(ctx: WorkflowActivityContext, activity_input: dict) -> dict:
    """Wrapper function to maintain compatibility with existing workflow calls."""
    agent = CredentialAnalyzer()
    return agent.execute(ctx, activity_input)

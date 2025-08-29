"""Text summarization agent using Pydantic AI."""

import json
import tempfile

import psycopg
import structlog
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext
from pydantic_ai import Agent
from pydantic_ai.settings import ModelSettings

from agents.base_agent import BaseAgent
from agents.model_manager import ModelManager
from agents.prompt_manager import PromptManager
from agents.schemas import SummaryResponse

logger = structlog.get_logger(__name__)


class TextSummarizer(BaseAgent):
    """Agent for summarizing text content using LLM."""

    def __init__(self):
        super().__init__()
        self.prompt_manager = PromptManager()
        self.name = "Text Summarizer"
        self.description = "Creates concise summaries of text content using LLM analysis"
        self.agent_type = "llm_based"
        self.has_prompt = True
        self.llm_temperature = 0.3
        self.system_prompt = """You are a document summarization assistant. Create a concise but thorough summary of the provided text. Focus on key points and main ideas. Include section headers to organize the summary. Use markdown formatting."""
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
        """Get the text summarization prompt from database or use default."""
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
                    logger.debug("Could not save default prompt to database (likely during startup)", agent_name=self.name)

                return self.system_prompt

        except Exception as e:
            logger.warning("Error managing prompt, using default", agent_name=self.name, error=str(e))
            return self.system_prompt

    def execute(self, ctx: WorkflowActivityContext, activity_input: dict) -> dict:
        """Summarize text content in the given file."""
        object_id = activity_input.get("object_id", "")

        logger.debug("text_summarization activity started", object_id=object_id)

        model = ModelManager.get_model()

        if not model:
            logger.warning("No model available from ModelManager")
            return {"success": False, "error": "AI model not available for text summarization"}

        try:
            # Get text content
            text_content = self._get_text_content(object_id)
            if not text_content:
                return {"success": False, "error": "No text content found to summarize"}

            # Get the current prompt from database or default
            current_prompt = self.get_prompt()

            agent = Agent(
                model=model,
                system_prompt=current_prompt,
                output_type=SummaryResponse,
                instrument=ModelManager.is_instrumentation_enabled(),
                retries=3,
                model_settings=ModelSettings(temperature=self.llm_temperature),
            )

            prompt = f"Please summarize this text:\n\n{text_content}"

            result = agent.run_sync(prompt)
            logger.debug(
                "Text summarization LLM analysis completed",
                object_id=object_id,
                total_tokens=result.usage().total_tokens,
                request_tokens=result.usage().request_tokens,
                response_tokens=result.usage().response_tokens,
            )

            summary = result.output.summary

            # Store the summary as a file
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_summary:
                tmp_summary.write(summary)
                tmp_summary.flush()
                summary_id = self.storage.upload_file(tmp_summary.name)

            # Add transform to database
            with psycopg.connect(self.postgres_connection_url) as conn:
                with conn.cursor() as cur:
                    metadata = {
                        "file_name": "text_summary.md",
                        "display_type_in_dashboard": "markdown",
                        "display_title": "Text Summary",
                        "default_display": True,
                    }

                    cur.execute(
                        """
                        INSERT INTO transforms (object_id, type, transform_object_id, metadata)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (object_id, "text_summary", summary_id, json.dumps(metadata))
                    )
                conn.commit()

            logger.debug("Text summarization completed", object_id=object_id)
            return {"success": True, "transform_id": summary_id}

        except Exception as e:
            logger.error("Text summarization failed", object_id=object_id, error=str(e))
            return {"success": False, "error": str(e)}


def summarize_text(ctx: WorkflowActivityContext, activity_input: dict) -> dict:
    """Wrapper function to maintain compatibility with existing workflow calls."""
    agent = TextSummarizer()
    return agent.execute(ctx, activity_input)

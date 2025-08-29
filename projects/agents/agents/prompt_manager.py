"""Manager for agent prompts stored in the database."""

from typing import Any

import psycopg
import structlog
from dapr.clients import DaprClient

logger = structlog.get_logger(__name__)


class PromptManager:
    """Manager for loading and saving agent prompts to/from the database."""

    _instance = None
    _postgres_connection_string = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def initialize(cls):
        """Initialize the PromptManager with PostgreSQL connection."""
        if cls._initialized:
            return

        try:
            with DaprClient() as client:
                secret = client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_URL")
                cls._postgres_connection_string = secret.secret["POSTGRES_CONNECTION_URL"]

                if not cls._postgres_connection_string or cls._postgres_connection_string.strip() == "":
                    logger.warning("Retrieved empty or whitespace-only POSTGRES_CONNECTION_URL from secret store")
                    cls._postgres_connection_string = None
                else:
                    logger.debug("PromptManager initialized with PostgreSQL credentials")

                cls._initialized = True
        except Exception as e:
            logger.warning("Failed to initialize PromptManager", error=str(e))
            cls._postgres_connection_string = None

    @classmethod
    def is_available(cls) -> bool:
        """Check if PromptManager is available for use."""
        return cls._initialized and cls._postgres_connection_string is not None

    def _get_connection(self):
        """Get a database connection."""
        if not self.is_available():
            raise RuntimeError("PromptManager not initialized or PostgreSQL connection string unavailable")
        return psycopg.connect(self._postgres_connection_string)

    def get_prompt(self, agent_name: str) -> dict[str, Any] | None:
        """Get agent prompt from database.

        Args:
            agent_name: Name of the agent (e.g., "validate")

        Returns:
            Dict with 'prompt', 'description', and 'enabled' keys, or None if not found
        """
        if not self.is_available():
            logger.debug("PromptManager not available, cannot get prompt", agent_name=agent_name)
            return None

        query = """
            SELECT name, description, prompt, enabled
            FROM agent_prompts
            WHERE name = %s AND enabled = true
        """

        try:
            with self._get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(query, (agent_name,))
                    row = cur.fetchone()

                    if row:
                        logger.debug("Retrieved prompt from database", agent_name=agent_name)
                        return {
                            "prompt": row[2],
                            "description": row[1],
                            "enabled": row[3],
                        }
                    else:
                        logger.debug("No enabled prompt found in database", agent_name=agent_name)
                        return None

        except Exception as e:
            logger.warning("Failed to get prompt from database", agent_name=agent_name, error=str(e))
            return None

    def save_prompt(self, agent_name: str, prompt: str, description: str | None = None) -> bool:
        """Save agent prompt to database.

        Args:
            agent_name: Name of the agent (e.g., "validate")
            prompt: The prompt text
            description: Optional description of what the agent does

        Returns:
            True if saved successfully, False otherwise
        """
        if not self.is_available():
            logger.debug("PromptManager not available, cannot save prompt", agent_name=agent_name)
            return False

        query = """
            INSERT INTO agent_prompts (name, prompt, description, enabled)
            VALUES (%s, %s, %s, true)
            ON CONFLICT (name)
            DO UPDATE SET
                prompt = EXCLUDED.prompt,
                description = EXCLUDED.description,
                updated_at = CURRENT_TIMESTAMP
        """

        try:
            with self._get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(query, (agent_name, prompt, description))

            logger.info("Saved prompt to database", agent_name=agent_name)
            return True

        except Exception as e:
            logger.error("Failed to save prompt to database", agent_name=agent_name, error=str(e))
            return False

"""Centralized model management for all agent activities."""

import structlog
from agents.helpers import create_rate_limit_client
from agents.logger import setup_phoenix_llm_tracing
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

logger = structlog.get_logger(__name__)


class ModelManager:
    """Singleton manager for LLM model instances used across all activities."""

    _model: OpenAIChatModel | None = None
    _token: str | None = None
    _model_name: str | None = None
    _base_url: str = "http://litellm:4000/"
    _instrumentation_enabled: bool = False

    @classmethod
    def initialize(cls, token: str, model_name: str = "default") -> None:
        """
        Initialize the model manager with LiteLLM credentials.
        Called once during application startup in lifespan().

        Args:
            token: LiteLLM API token
            model_name: Name of the model to use (default: "default")
        """
        cls._token = token
        cls._model_name = model_name
        cls._model = None  # Reset model to force recreation with new config

        # Setup Phoenix tracing for LLM calls if enabled
        cls._instrumentation_enabled = setup_phoenix_llm_tracing()

        logger.info(f"ModelManager initialized with model: {model_name}", phoenix_enabled=cls._instrumentation_enabled)

    @classmethod
    def get_model(cls) -> OpenAIChatModel | None:
        """
        Get the shared model instance, creating it if necessary.

        Returns:
            OpenAIChatModel instance or None if not initialized
        """
        if not cls._token or not cls._model_name:
            logger.warning("ModelManager not initialized - no token available")
            return None

        if not cls._model:
            try:
                cls._model = OpenAIChatModel(
                    model_name=cls._model_name,
                    provider=OpenAIProvider(
                        base_url=cls._base_url, api_key=cls._token, http_client=create_rate_limit_client()
                    ),
                )
                logger.info(f"Created model instance: {cls._model_name}")
            except Exception as e:
                logger.error(f"Failed to create model: {e}")
                return None

        return cls._model

    @classmethod
    def is_available(cls) -> bool:
        """Check if a model is available for use."""
        return cls._token is not None

    @classmethod
    def is_instrumentation_enabled(cls) -> bool:
        """Check if Phoenix LLM instrumentation is enabled."""
        return cls._instrumentation_enabled

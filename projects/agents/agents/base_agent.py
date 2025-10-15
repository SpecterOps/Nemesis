"""Base class for all agents."""

from abc import ABC, abstractmethod

from common.logger import get_logger
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext

logger = get_logger(__name__)


class BaseAgent(ABC):
    """Base class for all agents in the system."""

    def __init__(self):
        """Initialize the agent."""
        # These should be set by subclasses
        self.name: str = ""
        self.description: str = ""
        self.agent_type: str = "unknown"  # "llm_based" or "rule_based"
        self.has_prompt: bool = False
        self.enabled: bool = True

    @abstractmethod
    def execute(self, ctx: WorkflowActivityContext, activity_input: dict) -> dict:
        """
        Execute the agent's main logic.

        Args:
            ctx: Workflow activity context
            activity_input: Input data for the agent

        Returns:
            Dict containing the agent's result
        """
        pass

    def get_prompt(self) -> str | None:
        """
        Get the agent's prompt (for LLM-based agents).

        Returns:
            The prompt string if this agent uses prompts, None otherwise
        """
        return None

    def initialize_prompt(self):
        """
        Initialize the agent's prompt in database if needed.
        This is called during service startup for agents that have prompts.
        """
        if self.has_prompt:
            # Try to get/initialize prompt
            prompt = self.get_prompt()
            if prompt:
                logger.debug(f"Prompt initialized for agent {self.name}")

    def get_metadata(self) -> dict:
        """
        Get agent metadata for discovery.

        Returns:
            Dict containing agent metadata
        """
        return {
            "name": self.name,
            "description": self.description,
            "has_prompt": self.has_prompt,
            "enabled": self.enabled,
            "type": self.agent_type,
        }

    @classmethod
    def get_agent_class_name(cls) -> str:
        """Get the class name for registration purposes."""
        return cls.__name__

    def __str__(self):
        return f"{self.__class__.__name__}(name='{self.name}', type='{self.agent_type}')"

    def __repr__(self):
        return self.__str__()

"""Agent manager for dynamic loading and registration of agents."""

import importlib
import inspect
from pathlib import Path

from agents.base_agent import BaseAgent
from common.logger import get_logger

logger = get_logger(__name__)


class AgentManager:
    """Manages dynamic loading and registration of agents."""

    def __init__(self):
        self.agents: dict[str, type[BaseAgent]] = {}
        self.agent_instances: dict[str, BaseAgent] = {}
        self.tasks_dir = Path(__file__).parent / "tasks"

    def discover_agents(self) -> dict[str, type[BaseAgent]]:
        """Dynamically discover and load all agent classes from the tasks directory."""
        discovered_agents = {}

        for py_file in self.tasks_dir.glob("*.py"):
            if py_file.name.startswith("__"):
                continue

            module_name = py_file.stem
            try:
                # Import the module
                module = importlib.import_module(f"agents.tasks.{module_name}")

                # Find classes that inherit from BaseAgent
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if obj != BaseAgent and issubclass(obj, BaseAgent) and obj.__module__ == module.__name__:
                        agent_key = module_name
                        discovered_agents[agent_key] = obj
                        logger.debug(
                            "Discovered agent class",
                            module=module_name,
                            class_name=name,
                            agent_key=agent_key,
                        )
                        break

            except Exception as e:
                logger.warning(
                    "Failed to load agent module",
                    module=module_name,
                    error=str(e),
                )

        return discovered_agents

    def load_agents(self) -> None:
        """Load all discovered agents and initialize their prompts."""
        self.agents = self.discover_agents()
        logger.info("Loaded agents", count=len(self.agents), agents=list(self.agents.keys()))

        # Initialize prompts for agents that have them
        self.initialize_agent_prompts()

    def get_agent_instance(self, agent_key: str) -> BaseAgent:
        """Get or create an agent instance."""
        if agent_key not in self.agent_instances:
            if agent_key not in self.agents:
                raise ValueError(f"Agent '{agent_key}' not found")

            agent_class = self.agents[agent_key]
            self.agent_instances[agent_key] = agent_class()
            logger.debug("Created agent instance", agent_key=agent_key)

        return self.agent_instances[agent_key]

    def get_agent_metadata(self) -> list[dict]:
        """Get metadata for all loaded agents."""
        metadata = []

        for agent_key, agent_class in self.agents.items():
            try:
                # Create temporary instance to get metadata
                instance = agent_class()
                metadata.append(
                    {
                        "name": getattr(instance, "name", agent_key),
                        "description": getattr(instance, "description", f"Agent: {agent_key}"),
                        "agent_type": getattr(instance, "agent_type", "unknown"),
                        "has_prompt": getattr(instance, "has_prompt", False),
                        "enabled": True,
                    }
                )
            except Exception as e:
                logger.warning(
                    "Failed to get metadata for agent",
                    agent_key=agent_key,
                    error=str(e),
                )
                # Add basic metadata even if instance creation fails
                metadata.append(
                    {
                        "name": agent_key,
                        "description": f"Agent: {agent_key}",
                        "agent_type": "unknown",
                        "has_prompt": False,
                        "enabled": True,
                    }
                )

        return metadata

    def get_wrapper_function(self, agent_key: str):
        """Get the wrapper function for an agent to maintain compatibility."""

        def wrapper_function(ctx, activity_input: dict) -> dict:
            agent = self.get_agent_instance(agent_key)
            return agent.execute(ctx, activity_input)

        wrapper_function.__name__ = f"{agent_key}_wrapper"
        return wrapper_function

    def register_activities(self, workflow_runtime):
        """Register all agent activities with the workflow runtime."""
        for agent_key in self.agents.keys():
            wrapper_func = self.get_wrapper_function(agent_key)
            workflow_runtime.activity(wrapper_func)
            logger.debug("Registered activity", agent_key=agent_key, function_name=wrapper_func.__name__)

    def initialize_agent_prompts(self):
        """Initialize agent prompts in the database for agents that have prompts."""
        from agents.prompt_manager import PromptManager

        prompt_manager = PromptManager()

        for agent_key in self.agents.keys():
            try:
                agent = self.get_agent_instance(agent_key)
                if hasattr(agent, "has_prompt") and agent.has_prompt:
                    if hasattr(agent, "system_prompt"):
                        success = prompt_manager.save_prompt(
                            agent.name, agent.system_prompt, agent.description
                        )
                        if success:
                            logger.debug("Initialized prompt for agent", agent_key=agent_key)
                        else:
                            logger.warning("Failed to save prompt for agent", agent_key=agent_key)
            except Exception as e:
                logger.warning(
                    "Failed to initialize prompt for agent",
                    agent_key=agent_key,
                    error=str(e),
                )


# Global instance
agent_manager = AgentManager()

"""Validation agent for security findings using Pydantic AI."""

import structlog
from agents.base_agent import BaseAgent
from agents.logger import set_agent_metadata
from agents.model_manager import ModelManager
from agents.prompt_manager import PromptManager
from agents.schemas import TriageCategory, ValidateResponse
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext
from pydantic_ai import Agent
from pydantic_ai.settings import ModelSettings

logger = structlog.get_logger(__name__)


class ValidationAgent(BaseAgent):
    """Agent for validating security findings."""

    def __init__(self):
        super().__init__()
        self.prompt_manager = PromptManager()
        self.name = "Finding Validator"
        self.description = (
            "Validates security findings by triaging them as true positives, false positives, or needing review"
        )
        self.agent_type = "llm_based"
        self.has_prompt = True
        self.llm_temperature = 0.2  # Low temperature for validation tasks
        self.system_prompt = """
You are a cybersecurity expert triaging security findings.
You are an expert information security analyst skilled at triaging security findings.

Classify each finding as exactly one of:
- "true_positive": genuine security issue (not from test/mock data)
- "false_positive": incorrect match or test/sample/mock data (look for placeholders) or incorrect regex match
- "needs_review": insufficient information to decide

Consider file path, contents, and context. You need to be VERY sure for a true_positive.
If this is a true_positive, also return a short sentence of context of what an attacker could do
with this information (i.e., the risk). If it's not a true_positive omit this context.
"""

    def get_prompt(self) -> str:
        """Get the validation prompt from database or use default."""
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
        """Validate a security finding."""
        file_path = activity_input.get("file_path", "")
        object_id = activity_input.get("object_id", "")
        finding_id = activity_input.get("finding_id", "")
        summary = activity_input.get("summary", "")

        logger.debug("validate_finding activity started", file_path=file_path)

        model = ModelManager.get_model()

        if not model:
            logger.warning("No model available from ModelManager")
            return {
                "decision": TriageCategory.NOT_TRIAGED,
                "explanation": "AI model not available for validation",
                "confidence": 0.0,
            }

        try:
            # Set metadata for this agent run - this will be picked up by our custom processor
            set_agent_metadata(
                agent_name="security_finding_validator",
                file_path=file_path,
                object_id=object_id,
                finding_id=finding_id,
                finding_type="finding_validation",
                tags=["validation"],
            )

            # Get the current prompt from database or default
            current_prompt = self.get_prompt()

            agent = Agent(
                model=model,
                system_prompt=current_prompt,
                output_type=ValidateResponse,
                instrument=ModelManager.is_instrumentation_enabled(),
                retries=3,
                model_settings=ModelSettings(temperature=self.llm_temperature),
            )

            prompt = f"""Please triage the following security finding:

**File Path:** {file_path}
**Finding Summary:**
{summary}"""

            result = agent.run_sync(prompt)
            logger.debug(
                "Finding LLM validation completed",
                file_path=file_path,
                total_tokens=result.usage().total_tokens,
                request_tokens=result.usage().request_tokens,
                response_tokens=result.usage().response_tokens,
            )

            response = {
                "decision": result.output.decision,
                "explanation": result.output.explanation,
                "confidence": result.output.confidence,
            }

            # Only include true_positive_context if it exists
            if result.output.true_positive_context:
                response["true_positive_context"] = result.output.true_positive_context

            return response

        except Exception as e:
            logger.error("Validation failed", file_path=file_path, error=str(e))
            return {
                "decision": TriageCategory.NOT_TRIAGED,
                "explanation": f"Validation error: {str(e)}",
                "confidence": 0.0,
            }


def validate_finding(ctx: WorkflowActivityContext, activity_input: dict) -> dict:
    """Wrapper function to maintain compatibility with existing workflow calls."""
    agent = ValidationAgent()
    return agent.execute(ctx, activity_input)

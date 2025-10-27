"""JWT analysis agent for validating JWT findings."""

import structlog
from agents.base_agent import BaseAgent
from agents.logger import set_agent_metadata
from agents.schemas import JWTAnalysis, TriageCategory
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext

logger = structlog.get_logger(__name__)


class JWTAgent(BaseAgent):
    """Agent for analyzing JWT findings."""

    def __init__(self):
        super().__init__()
        self.name = "JWT Analyzer"
        self.description = "Rule-based JWT analysis that checks expiry status and identifies sample data"
        self.agent_type = "rule_based"
        self.has_prompt = False

    def analyze_jwt_finding(self, summary: str, file_path: str) -> JWTAnalysis | None:
        """
        Analyze JWT findings without LLM - based on expiry status and patterns.
        This is a non-LLM task that can run independently.

        Args:
            summary: The finding summary text
            file_path: Path of the file containing the JWT

        Returns:
            JWTAnalysis object with decision, or None if not a JWT finding
        """

        # Check if this is actually a JWT finding
        if "JSON Web Token" not in summary:
            return None

        logger.debug("Analyzing JWT finding from file", file_path=file_path)

        # Check for expiry status in the summary
        has_expired_true = "**Expired**: True" in summary
        has_expired_false = "**Expired**: False" in summary

        # Check for sample/test data indicators
        is_sample_data = any(
            indicator in file_path.lower()
            for indicator in ["test", "sample", "example", "demo", "mock", "fixture", "spec"]
        )

        # Determine if there's conflicting information
        has_expiry_conflict = has_expired_true and has_expired_false

        # Make triage decision based on rules
        if has_expiry_conflict:
            # Conflicting expiry info - might be multiple JWTs or parsing issue
            decision = TriageCategory.TRUE_POSITIVE
            explanation = "Conflicting expiry information found"
            is_expired = False  # Conservative assumption
        elif has_expired_true and not has_expired_false:
            # Clearly expired JWT - usually false positive
            decision = TriageCategory.FALSE_POSITIVE
            explanation = "JWT is expired"
            is_expired = True
        elif has_expired_false and not has_expired_true:
            # Valid (non-expired) JWT - potential security issue
            decision = TriageCategory.TRUE_POSITIVE if not is_sample_data else TriageCategory.FALSE_POSITIVE
            explanation = "JWT is not expired"
            is_expired = False
        else:
            # No clear expiry information
            decision = TriageCategory.NEEDS_REVIEW
            explanation = "No expiry information found"
            is_expired = False

        # Override decision if clearly sample data
        if is_sample_data and decision == TriageCategory.TRUE_POSITIVE:
            decision = TriageCategory.FALSE_POSITIVE

        result = JWTAnalysis(
            is_expired=is_expired,
            has_expiry_conflict=has_expiry_conflict,
            is_sample_data=is_sample_data,
            decision=decision,
            explanation=explanation,
        )

        logger.debug(
            "JWT analysis complete",
            decision=result.decision,
            expired=is_expired,
            conflict=has_expiry_conflict,
            sample=is_sample_data,
        )

        return result

    def execute(self, ctx: WorkflowActivityContext, activity_input: dict) -> dict:
        """Analyze a JWT finding."""
        file_path = activity_input.get("file_path", "")
        object_id = activity_input.get("object_id", "")
        finding_id = activity_input.get("finding_id", "")
        summary = activity_input.get("summary", "")

        logger.debug("validate_jwt_finding activity started", file_path=file_path)

        try:
            # Set metadata for this agent run
            set_agent_metadata(
                agent_name="jwt_analyzer",
                file_path=file_path,
                object_id=object_id,
                finding_id=finding_id,
                finding_type="jwt_analysis",
                tags=["jwt", "rule_based"],
            )

            result = self.analyze_jwt_finding(summary, file_path)

            if result is None:
                # Not a JWT finding, return needs_review
                return {
                    "is_expired": False,
                    "has_expiry_conflict": False,
                    "is_sample_data": False,
                    "decision": TriageCategory.NEEDS_REVIEW,
                }

            return {
                "is_expired": result.is_expired,
                "has_expiry_conflict": result.has_expiry_conflict,
                "is_sample_data": result.is_sample_data,
                "decision": result.decision,
                "explanation": result.explanation,
            }

        except Exception as e:
            logger.error("JWT analysis failed", file_path=file_path, error=str(e))
            return {
                "is_expired": False,
                "has_expiry_conflict": False,
                "is_sample_data": False,
                "decision": TriageCategory.NOT_TRIAGED,
            }


def validate_jwt_finding(ctx: WorkflowActivityContext, activity_input: dict) -> dict:
    """Wrapper function to maintain compatibility with existing workflow calls."""
    agent = JWTAgent()
    return agent.execute(ctx, activity_input)

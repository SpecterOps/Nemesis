"""Reporting agent for generating LLM-based risk assessments and synthesis reports."""

import json

import structlog
from agents.base_agent import BaseAgent
from agents.logger import set_agent_metadata
from agents.model_manager import ModelManager
from agents.prompt_manager import PromptManager
from agents.schemas import ReportSynthesisResponse
from common.db import get_postgres_connection_str
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext
from pydantic_ai import Agent
from pydantic_ai.settings import ModelSettings

logger = structlog.get_logger(__name__)


class ReportingAgent(BaseAgent):
    """Agent for generating LLM-based risk assessments and synthesis reports."""

    def __init__(self):
        super().__init__()
        self.prompt_manager = PromptManager(get_postgres_connection_str())
        self.name = "Report Generator"
        self.description = "Generates comprehensive risk assessment reports based on compromise data"
        self.agent_type = "llm_based"
        self.has_prompt = True
        self.llm_temperature = 0.3
        self.system_prompt = """You are a cybersecurity analyst specializing in compromise assessment and risk exposure analysis.
You will receive statistical data about files and security findings from a compromised host or system.

Your task is to analyze the data and answer: "If this host/system was compromised, what could an
attacker have had access to and what would the risk/impact be?.

Focus on:
1. Verified findings (marked as true_positive by analysts or AI triage)
2. Decrypted credentials and their potential impact
3. Sensitive data exposure (PII, credentials, proprietary info)
4. Attack surface based on file types and applications discovered

DO NOT provide:
- Remediation steps or recommendations
- Comparison against security baselines
- Compliance assessments
- Temporal analysis or timeline-based patterns

In some cases we may be analyzing a disk image for a host - in those cases:
- Registry hives (SYSTEM, SECURITY, SAM) existing is expected and NORMAL - this is NOT a high-risk finding by itself
- Focus on EXTRACTED CREDENTIALS that enable access to OTHER systems or accounts:
  * Successfully cracked/decrypted user passwords (not just hashed passwords existing)
  * Kerberos tickets that grant access to additional hosts
  * Decrypted browser credentials for external services (high value hosts)
  * SSH keys, API tokens, cloud service credentials
  * Credentials in application config files or documents
- DPAPI masterkeys being decrypted only matters if they were used to decrypt sensitive credentials
- Focus on findings that enable lateral movement or access beyond this single host

Provide your analysis in markdown format with these sections.

IMPORTANT: Do NOT include a top-level title (# heading) in your response.
Start directly with the section headings below:

## Executive Summary
1 paragraph summarizing the overall risk exposure and key concerns.

## Risk Level Assessment
Classify as High, Medium, or Low with clear justification based on the data.

## Critical Findings
List the most important security findings that represent the highest risk.

## Credential/Sensitive Data Exposure Analysis
Analyze what credentials were found, which are decrypted, and the potential impact
as well as PII, sensitive documents, and other data that could be exploited.

## Attack Surface Analysis
Based on file types and applications, what attack surface exists and what could be targeted.

Be concise, factual, and focus on risk impact rather than detection methods."""

        self.postgres_connection_url = get_postgres_connection_str()

    def get_prompt(self) -> str:
        """Get the reporting prompt from database or use default."""
        try:
            prompt_data = self.prompt_manager.get_prompt(self.name)

            if prompt_data:
                return prompt_data["prompt"]
            else:
                logger.info("No prompt found in database, initializing with default", agent_name=self.name)
                success = self.prompt_manager.save_prompt(self.name, self.system_prompt, self.description)
                if success:
                    logger.info("Default prompt saved to database", agent_name=self.name)
                else:
                    logger.debug(
                        "Could not save default prompt to database (likely during startup)", agent_name=self.name
                    )

                return self.system_prompt

        except Exception as e:
            logger.warning("Error managing prompt, using default", agent_name=self.name, error=str(e))
            return self.system_prompt

    def execute(self, ctx: WorkflowActivityContext, activity_input: dict) -> dict:
        """Generate risk assessment report based on provided statistics."""
        report_data = activity_input.get("report_data", {})
        report_type = activity_input.get("report_type", "source")
        source_name = activity_input.get("source_name", "Unknown")

        logger.debug("reporting_agent started", report_type=report_type, source_name=source_name)

        model = ModelManager.get_model()

        if not model:
            logger.warning("No model available from ModelManager")
            return {"success": False, "error": "AI model not available for report synthesis"}

        try:
            # Set metadata for this agent run
            set_agent_metadata(
                agent_name="report_generator",
                report_type=report_type,
                source_name=source_name,
                tags=["reporting", "risk_assessment"],
            )

            # Get the current prompt from database or default
            current_prompt = self.get_prompt()

            agent = Agent(
                model=model,
                system_prompt=current_prompt,
                output_type=ReportSynthesisResponse,
                instrument=ModelManager.is_instrumentation_enabled(),
                retries=3,
                model_settings=ModelSettings(temperature=self.llm_temperature),
            )

            # Build the analysis prompt with the report data
            if report_type == "source":
                analysis_prompt = self._build_source_prompt(source_name, report_data)
            else:
                analysis_prompt = self._build_system_prompt(report_data)

            # Estimate token count (rough estimate: 4 chars per token)
            estimated_tokens = len(analysis_prompt) // 4
            max_tokens = activity_input.get("max_tokens", 150000)

            if estimated_tokens > max_tokens:
                logger.warning(
                    "Report data exceeds token limit, truncating",
                    estimated_tokens=estimated_tokens,
                    max_tokens=max_tokens,
                )
                # Truncate the prompt to fit within token limit
                analysis_prompt = analysis_prompt[: max_tokens * 4]

            result = agent.run_sync(analysis_prompt)

            logger.debug(
                "Report synthesis completed",
                report_type=report_type,
                source_name=source_name,
                total_tokens=result.usage().total_tokens,
                request_tokens=result.usage().request_tokens,
                response_tokens=result.usage().response_tokens,
            )

            synthesis = result.output

            return {
                "success": True,
                "risk_level": synthesis.risk_level,
                "executive_summary": synthesis.executive_summary,
                "critical_findings": synthesis.critical_findings,
                "credential_exposure": synthesis.credential_exposure,
                "sensitive_data_exposure": synthesis.sensitive_data_exposure,
                "attack_surface": synthesis.attack_surface,
                "full_report_markdown": synthesis.full_report_markdown,
                "token_usage": result.usage().total_tokens,
            }

        except Exception as e:
            logger.error("Report synthesis failed", report_type=report_type, source_name=source_name, error=str(e))
            return {"success": False, "error": str(e)}

    def _build_source_prompt(self, source_name: str, report_data: dict) -> str:
        """Build analysis prompt for a source-specific report."""
        prompt = f"""# Risk Assessment Request for Source: {source_name}

Please analyze the following data and provide a comprehensive risk assessment.

## Summary Statistics
{json.dumps(report_data.get('summary', {}), indent=2)}

## Risk Indicators
{json.dumps(report_data.get('risk_indicators', {}), indent=2)}

## Findings Analysis
{json.dumps(report_data.get('findings_detail', {}), indent=2)}

## Top Verified Findings
"""
        # Add top findings with details
        top_findings = report_data.get("top_findings", [])
        if top_findings:
            for i, finding in enumerate(top_findings[:10], 1):
                prompt += f"\n{i}. **{finding.get('finding_name', 'Unknown')}** (Severity: {finding.get('severity', 'N/A')})\n"
                prompt += f"   - Category: {finding.get('category', 'N/A')}\n"
                prompt += f"   - Triage: {finding.get('triage_state', 'untriaged')}\n"
                prompt += f"   - File: {finding.get('file_path', 'N/A')}\n"
        else:
            prompt += "\nNo findings available.\n"

        prompt += "\n\nBased on this data, provide your risk assessment focusing on what an attacker could access and the potential impact."

        return prompt

    def _build_system_prompt(self, report_data: dict) -> str:
        """Build analysis prompt for a system-wide report."""
        prompt = """# System-Wide Risk Assessment Request

Please analyze the following system-wide data and provide a comprehensive risk assessment.

## Overall Summary
"""
        prompt += json.dumps(report_data.get("summary", {}), indent=2)

        prompt += "\n\n## Findings Breakdown\n"
        prompt += f"By Category: {json.dumps(report_data.get('findings_by_category', {}), indent=2)}\n"
        prompt += f"By Severity: {json.dumps(report_data.get('findings_by_severity', {}), indent=2)}\n"

        prompt += "\n\n## Source Summary\n"
        sources = report_data.get("sources", [])
        if sources:
            prompt += f"Total Sources: {len(sources)}\n\n"
            for source in sources[:20]:  # Top 20 sources
                prompt += f"- **{source.get('source', 'Unknown')}**: {source.get('file_count', 0)} files, {source.get('finding_count', 0)} findings ({source.get('verified_findings', 0)} verified)\n"
        else:
            prompt += "No sources available.\n"

        prompt += "\n\nBased on this system-wide data, provide your risk assessment focusing on overall exposure and impact."

        return prompt


def generate_report(ctx: WorkflowActivityContext, activity_input: dict) -> dict:
    """Wrapper function to maintain compatibility with existing workflow calls."""
    agent = ReportingAgent()
    return agent.execute(ctx, activity_input)

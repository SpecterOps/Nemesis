"""Publish findings and alerts activity."""

import asyncio
import json
import os

import aiohttp
import common.helpers as helpers
from common.logger import get_logger
from common.models import Alert
from common.queues import ALERTING_NEW_ALERT_TOPIC, ALERTING_PUBSUB
from common.state_helpers import get_file_enriched_async
from common.workflows.setup import workflow_activity
from dapr.aio.clients import DaprClient
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext

from .. import global_vars
from ..tracing import get_trace_injector

logger = get_logger(__name__)

# Categories that are excluded from LLM triage (always alert immediately)
LLM_EXCLUDED_CATEGORIES = ["extracted_hash", "yara_match", "extracted_data"]


# Check if LLM is enabled (agents service is available)
async def check_llm_enabled():
    """Check if the agents service is available (LLM functionality enabled).

    Retries up to 3 times with 10-second delays to handle containers starting in different orders.
    """
    max_retries = 3
    retry_delay = 10
    dapr_port = os.getenv("DAPR_HTTP_PORT", "3503")
    url = f"http://localhost:{dapr_port}/v1.0/invoke/agents/method/healthz"

    for attempt in range(1, max_retries + 1):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=2)) as response:
                    if response.status == 200:
                        logger.info("LLM functionality detected - agents service is available", attempt=attempt)
                        return True
                    else:
                        logger.info(
                            "Agents service responded with non-200 status",
                            status=response.status,
                            attempt=attempt,
                            max_retries=max_retries,
                        )
        except Exception as e:
            logger.info(
                "LLM functionality not available - agents service not reachable",
                error=str(e),
                attempt=attempt,
                max_retries=max_retries,
            )

        # If not the last attempt, wait before retrying
        if attempt < max_retries:
            logger.info(f"Waiting {retry_delay} seconds before retry...", attempt=attempt)
            await asyncio.sleep(retry_delay)

    logger.info("LLM functionality disabled - agents service not available after all retries")
    return False


# Cache LLM status to avoid repeated checks
_llm_enabled_cache = None


async def is_llm_enabled():
    """Get cached LLM status, checking on first call."""
    global _llm_enabled_cache
    if _llm_enabled_cache is None:
        _llm_enabled_cache = await check_llm_enabled()
        logger.info(f"LLM functionality: {'enabled' if _llm_enabled_cache else 'disabled'}")
    return _llm_enabled_cache


async def publish_alerts_for_findings(
    object_id: str, origin_include: list[str] | None = None, origin_exclude: list[str] | None = None
) -> None:
    """
    Core function to publish alerts for findings with optional origin filtering.

    Args:
        object_id: The object_id to fetch findings for
        origin_include: If provided, only alert on findings from these origins
        origin_exclude: If provided, skip alerting on findings from these origins
    """
    file_enriched = await get_file_enriched_async(object_id, global_vars.asyncpg_pool)

    # Build SQL query with origin filters
    where_clauses = ["object_id = $1"]
    params = [object_id]

    if origin_include:
        where_clauses.append("origin_name = ANY($2)")
        params.append(origin_include)
    elif origin_exclude:
        where_clauses.append("origin_name != ALL($2)")
        params.append(origin_exclude)

    query = f"""
        SELECT finding_name, category, severity, origin_name, raw_data
        FROM findings
        WHERE {" AND ".join(where_clauses)}
    """

    # Fetch findings from the database for this object_id
    async with global_vars.asyncpg_pool.acquire() as conn:
        findings = await conn.fetch(query, *params)

        logger.info(
            f"Fetched {len(findings)} findings for object_id {object_id}",
            origin_include=origin_include,
            origin_exclude=origin_exclude,
        )

        if findings:
            async with DaprClient(headers_callback=get_trace_injector()) as client:
                if file_enriched.path:
                    file_path = file_enriched.path
                else:
                    file_path = "UNKNOWN"

                llm_enabled = await is_llm_enabled()
                logger.debug(f"[publish_alerts_for_findings] llm_enabled: {llm_enabled}")

                for finding in findings:
                    finding_name = finding["finding_name"]
                    category = finding["category"]
                    severity = finding["severity"]
                    origin_name = finding["origin_name"]
                    raw_data = finding["raw_data"]

                    # If LLM is enabled and this category will be triaged, skip immediate alert
                    if llm_enabled and category not in LLM_EXCLUDED_CATEGORIES:
                        logger.debug(
                            "Skipping immediate alert for finding - LLM triage will handle it",
                            finding_name=finding_name,
                            category=category,
                            object_id=object_id,
                        )
                        continue

                    finding_message = f"- *Category:* {category} / *Severity:* {severity}\n"
                    file_message = f"- *File Path:* {helpers.sanitize_file_path(file_path)}\n"
                    nemesis_finding_url = f"{global_vars.nemesis_url}findings?object_id={file_enriched.object_id}"
                    nemesis_file_url = f"{global_vars.nemesis_url}files?object_id={file_enriched.object_id}"
                    nemesis_footer_finding = f"*<{nemesis_finding_url}|View Finding in Nemesis>* / "
                    nemesis_footer_file = f"*<{nemesis_file_url}|View File in Nemesis>*\n"
                    separator = "⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯"

                    rule_message = ""
                    try:
                        if finding_name == "noseyparker_match" and raw_data:
                            if "match" in raw_data and "rule_name" in raw_data["match"]:
                                rule_name = raw_data["match"]["rule_name"]
                                rule_message = f"- *Rule name:* {rule_name}\n"
                    except (json.JSONDecodeError, KeyError) as e:
                        logger.warning("Error processing raw_data for noseyparker_match", error=str(e))

                    body = f"{finding_message}{rule_message}{file_message}{nemesis_footer_finding}{nemesis_footer_file}{separator}"

                    alert = Alert(
                        title=finding_name,
                        body=body,
                        service=origin_name,
                        category=category,
                        severity=severity,
                        file_path=file_path,
                    )
                    await client.publish_event(
                        pubsub_name=ALERTING_PUBSUB,
                        topic_name=ALERTING_NEW_ALERT_TOPIC,
                        data=json.dumps(alert.model_dump(exclude_unset=True)),
                        data_content_type="application/json",
                    )
                    logger.debug("Published alert", alert=alert)


@workflow_activity
async def publish_findings_alerts(ctx: WorkflowActivityContext, object_id: str):
    """
    Workflow activity to publish alerts for findings, excluding async service origins.

    This is called at the end of the main enrichment workflow and handles findings
    from synchronous enrichment modules. Async services (dotnet, noseyparker) handle
    their own alerting when their results arrive.
    """
    logger.info("Executing activity: publish_findings_alerts", object_id=object_id)

    # Exclude async service origins to prevent double-alerting
    await publish_alerts_for_findings(object_id=object_id, origin_exclude=["dotnet_service", "noseyparker"])

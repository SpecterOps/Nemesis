"""Publish findings and alerts activity."""

import asyncio
import json
import os
import time
from collections.abc import Callable
from typing import Any
from uuid import UUID

import aiohttp
import common.helpers as helpers
from common.helpers import as_uuid
from common.logger import get_logger
from common.models import Alert
from common.queues import ALERTING_NEW_ALERT_TOPIC, ALERTING_PUBSUB
from common.state_helpers import get_file_enriched_async
from common.workflows.setup import workflow_activity
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext

from .. import global_vars

logger = get_logger(__name__)

# Categories that are excluded from LLM triage (always alert immediately)
LLM_EXCLUDED_CATEGORIES = ["extracted_hash", "yara_match", "extracted_data"]


# How long a known LLM status is trusted before it is re-probed (in the background, so no caller waits)
LLM_STATUS_TTL_SECONDS = 30.0
LLM_PROBE_TIMEOUT_SECONDS = 2.0


async def check_llm_enabled() -> bool:
    """Probe the agents service once via Dapr; True means LLM functionality is enabled."""
    dapr_port = os.getenv("DAPR_HTTP_PORT", "3503")
    url = f"http://localhost:{dapr_port}/v1.0/invoke/agents/method/healthz"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=LLM_PROBE_TIMEOUT_SECONDS)) as response:
                return response.status == 200
    except Exception as e:
        logger.debug("Agents service not reachable", error=str(e))
        return False


class _LlmStatus:
    """Cached agents-service availability.

    The first caller waits for one probe (~1s when agents is absent). Afterwards the cached value is returned at once
    and refreshed in the background once it is older than LLM_STATUS_TTL_SECONDS, so an agents service that starts
    later (or stops) is picked up without stalling activities on retries.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self.enabled: bool | None = None
        self.checked_at = 0.0
        self._probe: asyncio.Task | None = None

    def _start_probe(self) -> asyncio.Task:
        if self._probe is None or self._probe.done():
            self._probe = asyncio.create_task(self._run_probe())
        return self._probe

    async def _run_probe(self) -> bool:
        enabled = await check_llm_enabled()
        if enabled != self.enabled:
            logger.info(f"LLM functionality: {'enabled' if enabled else 'disabled'}")
        self.enabled = enabled
        self.checked_at = self._clock()
        return enabled

    async def get(self) -> bool:
        if self.enabled is None:
            return await asyncio.shield(self._start_probe())
        if self._clock() - self.checked_at >= LLM_STATUS_TTL_SECONDS:
            self._start_probe()
        return self.enabled


_llm_status = _LlmStatus()


async def is_llm_enabled() -> bool:
    """Whether the agents service (LLM triage) is available; never waits on more than one probe."""
    return await _llm_status.get()


async def publish_alerts_for_findings(
    object_id: UUID, origin_include: list[str] | None = None, origin_exclude: list[str] | None = None
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
    params: list[Any] = [object_id]

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
    assert global_vars.asyncpg_pool is not None
    # Release the connection before the LLM check and publishing: the first LLM check waits for a probe
    async with global_vars.asyncpg_pool.acquire() as conn:
        findings = await conn.fetch(query, *params)

    logger.info(
        f"Fetched {len(findings)} findings for object_id {object_id}",
        origin_include=origin_include,
        origin_exclude=origin_exclude,
    )

    if findings:
        client = global_vars.get_dapr_client()
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
            if isinstance(raw_data, str):
                raw_data = json.loads(raw_data)

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
            validation_message = ""
            try:
                if raw_data and finding_name.startswith("titus_"):
                    if "match" in raw_data and "rule_name" in raw_data["match"]:
                        rule_name = raw_data["match"]["rule_name"]
                        rule_id = raw_data["match"].get("rule_id", "")
                        rule_id_suffix = f" (`{rule_id}`)" if rule_id else ""
                        rule_message = f"- *Rule name:* {rule_name}{rule_id_suffix}\n"
                    if "match" in raw_data and raw_data["match"].get("validation_result"):
                        vr = raw_data["match"]["validation_result"]
                        status = vr.get("status", "undetermined")
                        status_label = {
                            "valid": "CONFIRMED ACTIVE",
                            "invalid": "INACTIVE",
                            "undetermined": "UNVERIFIED",
                        }.get(status, "UNVERIFIED")
                        validation_message = f"- *Validation:* {status_label}\n"
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                logger.warning("Error processing raw_data for titus finding", error=str(e))

            body = f"{finding_message}{rule_message}{validation_message}{file_message}{nemesis_footer_finding}{nemesis_footer_file}{separator}"

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
async def publish_findings_alerts(ctx: WorkflowActivityContext, activity_input: str):
    """
    Workflow activity to publish alerts for findings, excluding async service origins.

    This is called at the end of the main enrichment workflow and handles findings
    from synchronous enrichment modules. Async services (dotnet, titus) handle
    their own alerting when their results arrive.
    """
    object_id = as_uuid(activity_input)
    logger.info("Executing activity: publish_findings_alerts", object_id=object_id)

    # Exclude async service origins to prevent double-alerting
    await publish_alerts_for_findings(object_id=object_id, origin_exclude=["dotnet_service", "titus"])

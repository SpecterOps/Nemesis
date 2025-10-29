"""Publish findings and alerts activity."""

import json

import common.helpers as helpers
from common.logger import get_logger
from common.models import Alert
from common.state_helpers import get_file_enriched_async
from common.workflows.setup import workflow_activity
from dapr.clients import DaprClient
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext

from .. import global_vars
from ..tracing import get_trace_injector

logger = get_logger(__name__)


@workflow_activity
async def publish_findings_alerts(ctx: WorkflowActivityContext, object_id: str):
    """
    Activity to publish enriched file data to pubsub after retrieving from state store.
    """
    file_enriched = await get_file_enriched_async(object_id)

    # Fetch findings from the database for this object_id
    async with global_vars.asyncpg_pool.acquire() as conn:
        findings = await conn.fetch(
            """
            SELECT finding_name, category, severity, origin_name, raw_data
            FROM findings
            WHERE object_id = $1
        """,
            object_id,
        )

        if findings:
            with DaprClient(headers_callback=get_trace_injector()) as client:
                if file_enriched.path:
                    file_path = helpers.sanitize_file_path(file_enriched.path)
                else:
                    file_path = "UNKNOWN"

                for finding in findings:
                    finding_name = finding["finding_name"]
                    category = finding["category"]
                    severity = finding["severity"]
                    origin_name = finding["origin_name"]
                    raw_data = finding["raw_data"]

                    finding_message = f"- *Category:* {category} / *Severity:* {severity}\n"
                    file_message = f"- *File Path:* {file_path}\n"
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

                    alert = Alert(title=finding_name, body=body, service=origin_name)
                    client.publish_event(
                        pubsub_name="pubsub",
                        topic_name="alert",
                        data=json.dumps(alert.model_dump(exclude_unset=True)),
                        data_content_type="application/json",
                    )
                    logger.debug("Published alert", alert=alert)

"""File linking activity."""

from common.logger import get_logger
from common.state_helpers import get_file_enriched_async
from common.workflows.setup import workflow_activity
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext

from .. import global_vars

logger = get_logger(__name__)


@workflow_activity
async def check_file_linkings(ctx: WorkflowActivityContext, activity_input):
    """
    Check for file linkings using the rules engine and update database tables.
    """

    object_id = activity_input["object_id"]
    logger.info("Executing activity: check_file_linkings", object_id=object_id)

    file_enriched = await get_file_enriched_async(object_id, global_vars.asyncpg_pool)

    try:
        linkings_created = await global_vars.file_linking_engine.apply_linking_rules(file_enriched)

        logger.debug("File linking check complete", object_id=object_id, linkings_created=linkings_created)

        return {"linkings_created": linkings_created}

    except Exception as e:
        logger.exception("Error in file linking check", object_id=object_id, error=str(e))
        # Don't raise to ensure workflow can complete
        return {"linkings_created": 0, "error": str(e)}

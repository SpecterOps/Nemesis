"""Handler for bulk enrichment task subscription events."""

from common.logger import get_logger
from common.models import BulkEnrichmentEvent, CloudEvent, SingleEnrichmentWorkflowInput

logger = get_logger(__name__)


async def bulk_enrichment_subscription_handler(event: CloudEvent[BulkEnrichmentEvent]) -> None:
    """Handler for individual bulk enrichment tasks"""
    import file_enrichment.global_vars as global_vars

    evnt = event.data

    try:
        logger.debug("Received bulk enrichment task", enrichment_name=evnt.enrichment_name, object_id=evnt.object_id)

        # Check if module exists
        if not global_vars.global_module_map:
            logger.error("Modules not initialized")
            return

        if evnt.enrichment_name not in global_vars.global_module_map:
            logger.error(f"Enrichment module '{evnt.enrichment_name}' not found")
            return

        # Prepare workflow input for single enrichment
        workflow_input = SingleEnrichmentWorkflowInput(
            enrichment_name=evnt.enrichment_name,
            object_id=evnt.object_id,
        )

        # This will block if we're at max capacity, providing natural backpressure
        assert global_vars.workflow_manager is not None
        await global_vars.workflow_manager.run_single_enrichment_workflow(workflow_input)

    except Exception:
        logger.exception("Error processing bulk enrichment task")
        raise

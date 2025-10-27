"""Handler for bulk enrichment task subscription events."""

from common.logger import get_logger
from common.models import BulkEnrichmentEvent, SingleEnrichmentWorkflowInput
from file_enrichment.workflow_manager import WorkflowManager

logger = get_logger(__name__)


async def process_bulk_enrichment_event(
    evnt: BulkEnrichmentEvent, workflow_manager: WorkflowManager, global_module_map: dict
) -> None:
    """Process individual bulk enrichment tasks

    Args:
        task: The bulk enrichment task containing enrichment name and object ID
        workflow_manager: The workflow manager to schedule enrichment workflows
        global_module_map: Map of available enrichment modules

    Raises:
        Exception: If task processing fails
    """
    try:
        logger.debug("Received bulk enrichment task", enrichment_name=evnt.enrichment_name, object_id=object_id)

        # Check if module exists
        if not global_module_map:
            logger.error("Modules not initialized")
            return

        if evnt.enrichment_name not in global_module_map:
            logger.error(f"Enrichment module '{evnt.enrichment_name}' not found")
            return

        # Prepare workflow input for single enrichment
        workflow_input = SingleEnrichmentWorkflowInput(
            enrichment_name=evnt.enrichment_name,
            object_id=evnt.object_id,
        )

        # This will block if we're at max capacity, providing natural backpressure
        await workflow_manager.start_workflow_single_enrichment(workflow_input)

    except Exception:
        logger.exception("Error processing bulk enrichment task")
        raise

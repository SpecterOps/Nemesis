"""Handler for bulk enrichment task subscription events."""

from common.logger import get_logger
from common.models import BulkEnrichmentTask
from file_enrichment.workflow_manager import WorkflowManager

logger = get_logger(__name__)


async def process_bulk_enrichment_event(task: BulkEnrichmentTask, workflow_manager: WorkflowManager, global_module_map):
    """Process individual bulk enrichment tasks"""
    try:
        enrichment_name = task.enrichment_name
        object_id = task.object_id

        logger.debug("Received bulk enrichment task", enrichment_name=enrichment_name, object_id=object_id)

        # Check if module exists
        if not global_module_map:
            logger.error("Modules not initialized")
            return

        if enrichment_name not in global_module_map:
            logger.error(f"Enrichment module '{enrichment_name}' not found")
            return

        # Prepare workflow input for single enrichment
        workflow_input = {"enrichment_name": enrichment_name, "object_id": object_id}

        # This will block if we're at max capacity, providing natural backpressure
        await workflow_manager.start_workflow_single_enrichment(workflow_input)

    except Exception:
        logger.exception("Error processing bulk enrichment task")
        raise

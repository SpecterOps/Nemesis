"""Handler for bulk enrichment task subscription events."""

from common.logger import get_logger

logger = get_logger(__name__)


async def process_bulk_enrichment_event(data: dict, workflow_manager, workflow_runtime):
    """Process individual bulk enrichment tasks"""
    try:
        enrichment_name = data.get("enrichment_name")
        object_id = data.get("object_id")
        bulk_id = data.get("bulk_id")

        logger.debug(
            "Received bulk enrichment task", enrichment_name=enrichment_name, object_id=object_id, bulk_id=bulk_id
        )

        # Check if module exists
        if not workflow_runtime or not workflow_runtime.modules:
            logger.error("Workflow runtime or modules not initialized")
            return

        if enrichment_name not in workflow_runtime.modules:
            logger.error(f"Enrichment module '{enrichment_name}' not found")
            return

        # Prepare workflow input for single enrichment
        workflow_input = {"enrichment_name": enrichment_name, "object_id": object_id, "bulk_id": bulk_id}

        # This will block if we're at max capacity, providing natural backpressure
        await workflow_manager.start_workflow_single_enrichment(workflow_input)

    except Exception as e:
        logger.exception("Error processing bulk enrichment task", error=str(e))
        raise

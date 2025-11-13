"""Workflow concurrency management."""

import asyncio
import os

import document_conversion.global_vars as global_vars
from common.logger import get_logger
from common.models import FileEnriched

from .workflow import document_conversion_workflow

logger = get_logger(__name__)

# Configuration
max_parallel_workflows = int(os.getenv("MAX_PARALLEL_WORKFLOWS", 3))
max_workflow_execution_time = int(os.getenv("MAX_WORKFLOW_EXECUTION_TIME", 300))

# Semaphore for controlling concurrent workflow execution
workflow_semaphore = asyncio.Semaphore(max_parallel_workflows)
active_workflows = {}  # Track active workflows
workflow_lock = asyncio.Lock()  # For synchronizing access to active_workflows


async def start_workflow_with_concurrency_control(file_enriched: FileEnriched):
    """Start a workflow using semaphore for backpressure control."""
    # Acquire semaphore - this will block if we're at max capacity
    # This provides natural backpressure to the Dapr pub/sub system
    await workflow_semaphore.acquire()

    try:
        # Register workflow in database before scheduling
        object_id = file_enriched.object_id
        instance_id = await global_vars.tracking_service.register_workflow(
            object_id=object_id,
            filename=file_enriched.file_name,
        )

        # Add to active workflows tracking
        async with workflow_lock:
            active_workflows[instance_id] = {
                "object_id": object_id,
                "start_time": asyncio.get_event_loop().time(),
                "filename": file_enriched.file_name,
            }

        logger.debug(
            "Scheduling document conversion workflow",
            instance_id=instance_id,
            object_id=object_id,
            file_name=file_enriched.file_name,
            active_count=len(active_workflows),
        )

        # Schedule the workflow (using asyncio.to_thread for sync client)
        await asyncio.to_thread(
            global_vars.workflow_client.schedule_new_workflow,
            workflow=document_conversion_workflow,
            instance_id=instance_id,
            input={"object_id": object_id},
        )

        # Start monitoring task for this workflow
        asyncio.create_task(monitor_workflow_completion(instance_id))

    except Exception:
        logger.exception("Error starting document conversion workflow")
        # Release semaphore on error
        workflow_semaphore.release()
        raise


async def monitor_workflow_completion(instance_id: str):
    """Monitor a workflow until completion and release semaphore."""
    try:
        # Poll for workflow completion
        start_time = asyncio.get_event_loop().time()

        while True:
            try:
                # Check if workflow is still running (using asyncio.to_thread for sync client)
                state = await asyncio.to_thread(global_vars.workflow_client.get_workflow_state, instance_id)

                if state and hasattr(state, "runtime_status"):
                    status = state.runtime_status.name

                    if status in ["COMPLETED", "FAILED", "TERMINATED", "ERROR"]:
                        elapsed_time = asyncio.get_event_loop().time() - start_time
                        logger.info(
                            "Document conversion workflow finished",
                            instance_id=instance_id,
                            status=status,
                            elapsed_time=f"{elapsed_time:.2f}s",
                        )
                        break

                # Check for timeout
                if (asyncio.get_event_loop().time() - start_time) > max_workflow_execution_time:
                    logger.warning(
                        "Document conversion workflow timed out",
                        instance_id=instance_id,
                        max_execution_time=max_workflow_execution_time,
                    )
                    # Try to terminate the workflow (using asyncio.to_thread for sync client)
                    try:
                        await asyncio.to_thread(global_vars.workflow_client.terminate_workflow, instance_id)
                    except Exception as term_error:
                        logger.error(f"Failed to terminate workflow {instance_id}: {term_error}")
                    break

                await asyncio.sleep(0.3)

            except Exception as check_error:
                logger.warning(f"Error checking workflow status for {instance_id}: {check_error}")
                await asyncio.sleep(2)  # Wait longer on error

    except Exception:
        logger.exception(message=f"Error monitoring workflow {instance_id}")

    finally:
        # Always clean up and release semaphore
        async with workflow_lock:
            if instance_id in active_workflows:
                del active_workflows[instance_id]

        workflow_semaphore.release()
        logger.debug(f"Released semaphore for workflow {instance_id}", active_count=len(active_workflows))

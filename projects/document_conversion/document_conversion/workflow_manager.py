"""Workflow concurrency management."""

import asyncio
import math
import os

import document_conversion.global_vars as global_vars
from common.helpers import jsonable
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
_monitor_tasks: set[asyncio.Task] = set()  # Keep references so monitor tasks are not garbage-collected


async def start_workflow_with_concurrency_control(file_enriched: FileEnriched):
    """Start a workflow using semaphore for backpressure control."""
    assert global_vars.tracking_service is not None, "tracking_service must be initialized"
    assert global_vars.async_workflow_client is not None, "async_workflow_client must be initialized"

    # Acquire semaphore - this will block if we're at max capacity
    # This provides natural backpressure to the Dapr pub/sub system
    await workflow_semaphore.acquire()

    instance_id = None
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

        await global_vars.async_workflow_client.schedule_new_workflow(
            workflow=document_conversion_workflow,
            instance_id=instance_id,
            input=jsonable({"object_id": object_id}),
        )

        # Start monitoring task for this workflow
        task = asyncio.create_task(monitor_workflow_completion(instance_id))
        _monitor_tasks.add(task)
        task.add_done_callback(_monitor_tasks.discard)

    except Exception:
        logger.exception("Error starting document conversion workflow")
        async with workflow_lock:
            active_workflows.pop(instance_id, None)
        # Release semaphore on error
        workflow_semaphore.release()
        raise


async def monitor_workflow_completion(instance_id: str):
    """Wait for a workflow to finish (or time out), then release its semaphore slot."""
    client = global_vars.async_workflow_client
    assert client is not None, "async_workflow_client must be initialized"
    loop = asyncio.get_running_loop()
    start_time = loop.time()
    try:
        while True:
            remaining = max_workflow_execution_time - (loop.time() - start_time)
            if remaining <= 0:
                logger.warning(
                    "Document conversion workflow timed out",
                    instance_id=instance_id,
                    max_execution_time=max_workflow_execution_time,
                )
                try:
                    await client.terminate_workflow(instance_id)
                except Exception as term_error:
                    logger.error(f"Failed to terminate workflow {instance_id}: {term_error}")
                break

            try:
                # The sidecar answers as soon as the workflow reaches a terminal state (no polling)
                state = await client.wait_for_workflow_completion(
                    instance_id, fetch_payloads=False, timeout_in_seconds=max(1, math.ceil(remaining))
                )
            except TimeoutError:
                continue  # the next pass terminates it
            except Exception as wait_error:
                logger.warning(f"Error waiting for workflow {instance_id}: {wait_error}")
                await asyncio.sleep(2)
                continue

            logger.info(
                "Document conversion workflow finished",
                instance_id=instance_id,
                status=state.runtime_status.name if state else "UNKNOWN",
                elapsed_time=f"{loop.time() - start_time:.2f}s",
            )
            break

    except Exception:
        logger.exception(message=f"Error monitoring workflow {instance_id}")

    finally:
        # Always clean up and release semaphore
        async with workflow_lock:
            if instance_id in active_workflows:
                del active_workflows[instance_id]

        workflow_semaphore.release()
        logger.debug(f"Released semaphore for workflow {instance_id}", active_count=len(active_workflows))

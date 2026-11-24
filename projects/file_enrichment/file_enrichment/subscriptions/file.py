"""Handler for file subscription events.

Backpressure: each replica runs at most MAX_PARALLEL_WORKFLOWS enrichment workflows. A message takes a slot before its
workflow is scheduled and keeps it until that workflow reaches a terminal state, so the limit covers running workflows,
not just the (fast) act of scheduling them. While no slot is free, the handler waits, which holds the message
unacknowledged in RabbitMQ (prefetchCount bounds how many wait here); after WORKFLOW_SLOT_WAIT_SECONDS it returns RETRY
so the broker redelivers it later.

Errors: the message is acknowledged only after its workflow is durably scheduled in Dapr. Transient failures (database,
Dapr) return RETRY so the broker redelivers; messages that can never succeed (malformed payload, invalid values) return
DROP with a log, so they don't loop forever.
"""

import asyncio
import os
from datetime import datetime
from typing import Any

import asyncpg
import file_enrichment.global_vars as global_vars
from common.logger import get_logger
from common.models import CloudEvent, File
from dapr.ext.workflow.workflow_state import WorkflowStatus as DaprWorkflowStatus
from fastapi import Body
from pydantic import ValidationError

logger = get_logger(__name__)


# Configuration
NUM_WORKERS = int(os.getenv("MAX_PARALLEL_WORKFLOWS", 5))
SLOT_WAIT_SECONDS = float(os.getenv("WORKFLOW_SLOT_WAIT_SECONDS", 600))
COMPLETION_POLL_SECONDS = 2.0

# Dapr pub/sub responses
SUCCESS = {"status": "SUCCESS"}
RETRY = {"status": "RETRY"}
DROP = {"status": "DROP"}

TERMINAL_STATES = {DaprWorkflowStatus.COMPLETED, DaprWorkflowStatus.FAILED, DaprWorkflowStatus.TERMINATED}

# Errors that retrying the same message can't fix
PERMANENT_ERRORS: tuple[type[BaseException], ...] = (
    ValidationError,
    ValueError,
    asyncpg.DataError,
    asyncpg.IntegrityConstraintViolationError,
)

workflow_slots: asyncio.Semaphore | None = None
slot_holders: set[asyncio.Task] = set()


def start_workers():
    """Create the workflow slots (one per allowed parallel workflow)."""
    global workflow_slots

    if workflow_slots is not None:
        logger.warning("Workflow slots already created")
        return

    workflow_slots = asyncio.Semaphore(NUM_WORKERS)
    logger.info("Created workflow slots", max_parallel_workflows=NUM_WORKERS)


async def stop_workers():
    """Stop waiting on running workflows and drop the slots."""
    global workflow_slots

    for task in list(slot_holders):
        task.cancel()
    if slot_holders:
        await asyncio.gather(*slot_holders, return_exceptions=True)
    slot_holders.clear()
    workflow_slots = None

    logger.info("Workflow slots released")


def completion_timeout_seconds() -> float:
    """How long a slot may be held: the purger terminates running workflows after the max execution time, so this
    only guards against a workflow that never reports a terminal state."""
    return 2 * global_vars.max_workflow_execution_time + 300


async def hold_slot_until_done(instance_id: str) -> None:
    """Keep a slot until the workflow finishes (or disappears, or the safety timeout passes), then release it."""
    assert workflow_slots is not None
    slots = workflow_slots
    loop = asyncio.get_running_loop()
    deadline = loop.time() + completion_timeout_seconds()
    try:
        while True:
            try:
                state = await asyncio.to_thread(
                    global_vars.workflow_client.get_workflow_state, instance_id, fetch_payloads=False
                )
            except Exception as e:
                # State unknown for now; keep waiting until the deadline
                logger.warning("Could not read workflow state", instance_id=instance_id, error=str(e))
            else:
                # None means the workflow no longer exists (already purged)
                if state is None or state.runtime_status in TERMINAL_STATES:
                    return
            if loop.time() >= deadline:
                logger.warning(
                    "Workflow did not finish within the slot timeout; releasing its slot",
                    instance_id=instance_id,
                    timeout_seconds=completion_timeout_seconds(),
                )
                return
            await asyncio.sleep(COMPLETION_POLL_SECONDS)
    finally:
        slots.release()


async def file_subscription_handler(event: dict[str, Any] = Body(...)) -> dict[str, str]:
    """Handler for incoming file events; returns a Dapr pub/sub status (SUCCESS, RETRY or DROP)."""
    try:
        file = CloudEvent[File].model_validate(event).data
    except ValidationError as e:
        logger.error("Dropping malformed file event", event_id=event.get("id"), error=str(e))
        return DROP

    if workflow_slots is None:
        logger.warning("File event received before workflow slots exist; retrying", object_id=file.object_id)
        return RETRY

    try:
        await asyncio.wait_for(workflow_slots.acquire(), timeout=SLOT_WAIT_SECONDS)
    except TimeoutError:
        logger.info("No workflow slot free; asking the broker to redeliver", object_id=file.object_id)
        return RETRY

    try:
        await save_file_message(file)
        assert global_vars.workflow_manager is not None
        instance_id = await global_vars.workflow_manager.run_workflow(file)
    except PERMANENT_ERRORS:
        workflow_slots.release()
        logger.exception(message="Dropping file event that cannot be processed", object_id=file.object_id)
        return DROP
    except Exception:
        workflow_slots.release()
        logger.exception(message="Error scheduling workflow for file; asking for redelivery", object_id=file.object_id)
        return RETRY

    task = asyncio.create_task(hold_slot_until_done(instance_id))
    slot_holders.add(task)
    task.add_done_callback(slot_holders.discard)

    logger.debug("Scheduled workflow for file", object_id=file.object_id, instance_id=instance_id)
    return SUCCESS


async def save_file_message(file: File):
    """Save the file message to the database for recovery purposes"""
    try:
        # Only save files that are not nested (originating files)
        if file.nesting_level and file.nesting_level > 0:
            logger.debug(
                "nesting_level > 0, not saving file message",
                nesting_level=file.nesting_level,
                object_id=file.object_id,
            )
            return

        query = """
        INSERT INTO files (
            object_id, agent_id, source, project, timestamp, expiration,
            path, originating_object_id, originating_container_id, nesting_level,
            file_creation_time, file_access_time, file_modification_time
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
        ) ON CONFLICT (object_id) DO UPDATE SET
            agent_id = EXCLUDED.agent_id,
            source = EXCLUDED.source,
            project = EXCLUDED.project,
            timestamp = EXCLUDED.timestamp,
            expiration = EXCLUDED.expiration,
            path = EXCLUDED.path,
            originating_object_id = EXCLUDED.originating_object_id,
            originating_container_id = EXCLUDED.originating_container_id,
            nesting_level = EXCLUDED.nesting_level,
            file_creation_time = EXCLUDED.file_creation_time,
            file_access_time = EXCLUDED.file_access_time,
            file_modification_time = EXCLUDED.file_modification_time,
            updated_at = CURRENT_TIMESTAMP;
        """

        assert global_vars.asyncpg_pool is not None
        async with global_vars.asyncpg_pool.acquire() as conn:
            await conn.execute(
                query,
                file.object_id,
                file.agent_id,
                file.source,
                file.project,
                file.timestamp,
                file.expiration,
                file.path,
                file.originating_object_id,
                getattr(file, "originating_container_id", None),
                file.nesting_level,
                datetime.fromisoformat(file.creation_time) if file.creation_time else None,
                datetime.fromisoformat(file.access_time) if file.access_time else None,
                datetime.fromisoformat(file.modification_time) if file.modification_time else None,
            )

        logger.debug("Successfully saved file message to database", object_id=file.object_id)

    except Exception:
        logger.exception(message="Error saving file message to database", object_id=file.object_id)
        raise

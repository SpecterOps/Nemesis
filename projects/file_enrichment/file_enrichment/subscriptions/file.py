"""Handler for file subscription events."""

import asyncio
import os
from datetime import datetime

import file_enrichment.global_vars as global_vars
from common.logger import get_logger
from common.models import CloudEvent, File

logger = get_logger(__name__)


# Configuration
NUM_WORKERS = int(os.getenv("MAX_PARALLEL_WORKFLOWS", 5))

# Queue for file processing
file_queue: asyncio.Queue = None
worker_tasks: list[asyncio.Task] = []


async def worker(worker_id: int):
    """Worker task that continuously processes files from the queue"""
    logger.info(f"Worker {worker_id} started", pid=os.getpid())

    while True:
        try:
            # Get the next file from the queue
            file = await file_queue.get()

            try:
                logger.debug(f"Worker {worker_id} processing file", object_id=file.object_id, pid=os.getpid())

                # Save file and run workflow
                await save_file_message(file)
                await global_vars.workflow_manager.run_workflow(file)

                logger.debug(f"Worker {worker_id} completed file", object_id=file.object_id, pid=os.getpid())

            except Exception:
                logger.exception(
                    message=f"Worker {worker_id} error processing file", object_id=file.object_id, pid=os.getpid()
                )
            finally:
                # Mark the task as done
                file_queue.task_done()

        except asyncio.CancelledError:
            logger.info(f"Worker {worker_id} cancelled", pid=os.getpid())
            break
        except Exception:
            logger.exception(message=f"Worker {worker_id} unexpected error", pid=os.getpid())


def start_workers():
    """Start the worker tasks"""
    global file_queue, worker_tasks

    if file_queue is not None:
        logger.warning("Workers already started", pid=os.getpid())
        return

    # Create a bounded queue - only allows NUM_WORKERS items
    # This ensures we only accept work when a worker is available
    file_queue = asyncio.Queue(maxsize=NUM_WORKERS)
    worker_tasks = []

    for i in range(NUM_WORKERS):
        task = asyncio.create_task(worker(i))
        worker_tasks.append(task)

    logger.info("Started file enrichment workers", num_workers=NUM_WORKERS, pid=os.getpid())


async def stop_workers():
    """Stop all worker tasks"""
    global worker_tasks, file_queue

    if not worker_tasks:
        logger.warning("No workers to stop", pid=os.getpid())
        return

    logger.info("Stopping workers...", pid=os.getpid())

    # Cancel all worker tasks
    for task in worker_tasks:
        task.cancel()

    # Wait for all workers to finish
    await asyncio.gather(*worker_tasks, return_exceptions=True)

    worker_tasks = []
    file_queue = None

    logger.info("All workers stopped", pid=os.getpid())


async def file_subscription_handler(event: CloudEvent[File]):
    """Handler for incoming file events"""
    file = event.data

    try:
        # Try to add file to the queue
        # put() will block until a worker is available (queue has space)
        # This ensures we only accept work when there's capacity
        await file_queue.put(file)

        logger.debug("File added to queue", object_id=file.object_id, queue_size=file_queue.qsize(), pid=os.getpid())

    except Exception:
        logger.exception(message="Error adding file to queue", pid=os.getpid())
        raise


async def save_file_message(file: File):
    """Save the file message to the database for recovery purposes"""
    try:
        # Only save files that are not nested (originating files)
        if file.nesting_level and file.nesting_level > 0:
            logger.debug(
                "nesting_level > 0, not saving file message",
                nesting_level=file.nesting_level,
                object_id=file.object_id,
                pid=os.getpid(),
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

        logger.debug("Successfully saved file message to database", object_id=file.object_id, pid=os.getpid())

    except Exception:
        logger.exception(message="Error saving file message to database", object_id=file.object_id, pid=os.getpid())
        raise

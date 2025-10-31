import asyncio
import json
import os
import random

from common.logger import get_logger
from common.models import File
from common.queues import FILES_NEW_FILE_TOPIC, FILES_PUBSUB
from dapr.clients import DaprClient

from .tracing import get_trace_injector

logger = get_logger(__name__)


async def recover_interrupted_workflows(pool) -> None:
    """
    Recover workflows that were interrupted during system shutdown.

    NOTE/TODO:  if using multiple replicas or k8s, this process should be moved
                into a single instance and not replicated multiple times
    """
    try:
        # Tandom sleep delay to help with the worker overlap on recovery
        #   This, combined with the single atomic DELETE query, should
        #   ensure that only one worker will recover the workflows.
        delay = random.uniform(0, 10)
        logger.info(f"Workflow recovery starting in {delay:.1f} seconds...", pid=os.getpid())
        await asyncio.sleep(delay)

        logger.info("Starting workflow recovery process...", pid=os.getpid())

        # Get interrupted workflows atomically using asyncpg
        async with pool.acquire() as conn:
            # Atomic DELETE with RETURNING - only one worker will get the interrupted workflows
            running_ids = await conn.fetch("""
                DELETE FROM workflows
                WHERE status = 'RUNNING'
                RETURNING object_id
            """)
            running_object_ids = [row["object_id"] for row in running_ids]

            if running_object_ids:
                logger.info(f"Atomically claimed {len(running_object_ids)} interrupted workflows", pid=os.getpid())

        if not running_object_ids:
            logger.info("No interrupted workflows found", pid=os.getpid())
            return

        logger.info(f"Found {len(running_object_ids)} interrupted workflows to recover", pid=os.getpid())

        # Get file data and clean up partial results
        recovered_files = []
        async with pool.acquire() as conn:
            for object_id in running_object_ids:
                # Get file data for reconstruction
                row = await conn.fetchrow(
                    """
                    SELECT object_id, agent_id, source, project, timestamp, expiration,
                           path, originating_object_id, originating_container_id, nesting_level,
                           file_creation_time, file_access_time, file_modification_time
                    FROM files WHERE object_id = $1
                """,
                    object_id,
                )

                if row:
                    # Convert database row to File-compatible dict
                    file_data = {
                        "object_id": str(row["object_id"]),
                        "agent_id": row["agent_id"],
                        "source": row["source"],
                        "project": row["project"],
                        "timestamp": row["timestamp"],
                        "expiration": row["expiration"],
                        "path": row["path"],
                        "originating_object_id": str(row["originating_object_id"])
                        if row["originating_object_id"]
                        else None,
                        "originating_container_id": str(row["originating_container_id"])
                        if row["originating_container_id"]
                        else None,
                        "nesting_level": row["nesting_level"],
                        "creation_time": row["file_creation_time"].isoformat() if row["file_creation_time"] else None,
                        "access_time": row["file_access_time"].isoformat() if row["file_access_time"] else None,
                        "modification_time": row["file_modification_time"].isoformat()
                        if row["file_modification_time"]
                        else None,
                    }
                    recovered_files.append(file_data)
                    logger.debug("Recovered file data for workflow", object_id=object_id, pid=os.getpid())
                else:
                    logger.warning("No file data found for workflow", object_id=object_id, pid=os.getpid())

        if not recovered_files:
            logger.warning("No file data found for interrupted workflows", pid=os.getpid())
            return

        # Republish recovered files with priority
        with DaprClient(headers_callback=get_trace_injector()) as client:
            for file_data in recovered_files:
                try:
                    # Filter out None values for File object creation
                    clean_file_data = {k: v for k, v in file_data.items() if v is not None}

                    # Create File object from recovered data
                    file_obj = File(**clean_file_data)

                    # Publish with priority=3 for immediate processing
                    client.publish_event(
                        pubsub_name=FILES_PUBSUB,
                        topic_name=FILES_NEW_FILE_TOPIC,
                        data=json.dumps(file_obj.model_dump(exclude_unset=True, mode="json")),
                        data_content_type="application/json",
                        metadata=(("priority", "3"),),
                    )

                    logger.info("Republished interrupted workflow", object_id=file_data["object_id"], pid=os.getpid())

                except Exception as e:
                    logger.exception(f"Failed to republish workflow {file_data['object_id']}: {e}")
                    logger.error("File data that caused error", file_data=file_data)

        logger.info(f"Successfully recovered {len(recovered_files)} interrupted workflows", pid=os.getpid())

    except Exception as e:
        logger.exception("Error during workflow recovery", error=str(e), pid=os.getpid())
        # Don't raise - we want the service to continue even if recovery fails

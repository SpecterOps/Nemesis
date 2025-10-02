import asyncio
import json
import os
import random

from common.logger import get_logger
from common.models import File
from dapr.clients import DaprClient

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

        def get_and_delete_running_workflows():
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    # Atomic DELETE with RETURNING - only one worker will get the interrupted workflows
                    cur.execute("""
                        DELETE FROM workflows
                        WHERE status = 'RUNNING'
                        RETURNING object_id
                    """)
                    running_ids = [row[0] for row in cur.fetchall()]
                    conn.commit()

                    if running_ids:
                        logger.info(f"Atomically claimed {len(running_ids)} interrupted workflows", pid=os.getpid())

                    return running_ids

        def get_file_data_and_cleanup(object_ids):
            recovered_files = []
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    for object_id in object_ids:
                        # Get file data for reconstruction
                        cur.execute(
                            """
                            SELECT object_id, agent_id, source, project, timestamp, expiration,
                                   path, originating_object_id, originating_container_id, nesting_level,
                                   file_creation_time, file_access_time, file_modification_time
                            FROM files WHERE object_id = %s
                        """,
                            (object_id,),
                        )

                        row = cur.fetchone()
                        if row:
                            # Convert database row to File-compatible dict
                            file_data = {
                                "object_id": str(row[0]),
                                "agent_id": row[1],
                                "source": row[2],
                                "project": row[3],
                                "timestamp": row[4],
                                "expiration": row[5],
                                "path": row[6],
                                "originating_object_id": str(row[7]) if row[7] else None,
                                "originating_container_id": str(row[8]) if row[8] else None,
                                "nesting_level": row[9],
                                "creation_time": row[10].isoformat() if row[10] else None,
                                "access_time": row[11].isoformat() if row[11] else None,
                                "modification_time": row[12].isoformat() if row[12] else None,
                            }
                            recovered_files.append(file_data)
                            logger.debug("Recovered file data for workflow", object_id=object_id, pid=os.getpid())
                        else:
                            logger.warning("No file data found for workflow", object_id=object_id, pid=os.getpid())

                    conn.commit()

            return recovered_files

        # Get interrupted workflows
        running_object_ids = await asyncio.to_thread(get_and_delete_running_workflows)

        if not running_object_ids:
            logger.info("No interrupted workflows found", pid=os.getpid())
            return

        logger.info(f"Found {len(running_object_ids)} interrupted workflows to recover", pid=os.getpid())

        # Get file data and clean up partial results
        recovered_files = await asyncio.to_thread(get_file_data_and_cleanup, running_object_ids)

        if not recovered_files:
            logger.warning("No file data found for interrupted workflows", pid=os.getpid())
            return

        # Republish recovered files with priority
        with DaprClient() as client:
            for file_data in recovered_files:
                try:
                    # Filter out None values for File object creation
                    clean_file_data = {k: v for k, v in file_data.items() if v is not None}

                    # Create File object from recovered data
                    file_obj = File(**clean_file_data)

                    # Publish with priority=3 for immediate processing
                    client.publish_event(
                        pubsub_name="pubsub",
                        topic_name="file",
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

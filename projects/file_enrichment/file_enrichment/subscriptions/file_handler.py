"""Handler for file subscription events."""

import asyncio
import os
from datetime import datetime

from common.logger import get_logger
from common.models import File
from psycopg_pool import ConnectionPool

logger = get_logger(__name__)


async def save_file_message(file: File, pool: ConnectionPool):
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

        def save_to_db():
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    query = """
                    INSERT INTO files (
                        object_id, agent_id, source, project, timestamp, expiration,
                        path, originating_object_id, originating_container_id, nesting_level,
                        file_creation_time, file_access_time, file_modification_time
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
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

                    cur.execute(
                        query,
                        (
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
                        ),
                    )
                    conn.commit()

        await asyncio.to_thread(save_to_db)
        logger.debug("Successfully saved file message to database", object_id=file.object_id, pid=os.getpid())

    except Exception as e:
        logger.exception(e, message="Error saving file message to database", object_id=file.object_id, pid=os.getpid())
        raise


async def process_file_event(file: File, workflow_manager, module_execution_order: list, pool: ConnectionPool):
    """Process incoming file events"""
    try:
        # Save the file message to database first for recovery purposes
        await save_file_message(file, pool)

        workflow_input = {
            "file": file.model_dump(exclude_unset=True, mode="json"),
            "execution_order": module_execution_order,
        }

        # This will block if we're at max capacity, providing natural backpressure
        await workflow_manager.start_workflow(workflow_input)

    except Exception as e:
        logger.exception(e, message="Error processing file event", pid=os.getpid())
        raise

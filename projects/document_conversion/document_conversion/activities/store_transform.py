"""Storage and publishing activities."""

import json

import document_conversion.global_vars as global_vars
from common.logger import get_logger
from common.workflows.setup import workflow_activity

logger = get_logger(__name__)


@workflow_activity
async def store_transform(ctx, activity_input):
    """Store transform data in PostgreSQL."""
    assert global_vars.asyncpg_pool is not None, "asyncpg_pool must be initialized"

    try:
        object_id = activity_input["object_id"]
        transform = activity_input["transform"]
        transform_type = transform["type"]

        async with global_vars.asyncpg_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO transforms (object_id, type, transform_object_id, metadata)
                VALUES ($1, $2, $3, $4)
            """,
                object_id,
                transform["type"],
                transform["object_id"],
                json.dumps(transform["metadata"]) if transform.get("metadata") else None,
            )

        logger.debug(f"Stored {transform_type} transform", object_id=object_id)
    except Exception:
        logger.exception(message=f"Error storing {transform_type} transform")
        raise

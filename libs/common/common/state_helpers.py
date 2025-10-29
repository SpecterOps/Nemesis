import json

import asyncpg
import psycopg
from common.db import get_postgres_connection_str
from common.models import FileEnriched

from .logger import get_logger

logger = get_logger(__name__)

# Single source of truth for file_enriched query (using psycopg style with %s placeholders)
_FILE_ENRICHED_SELECT_QUERY = """
    SELECT
        object_id, agent_id, source, project, timestamp, expiration,
        path, file_name, extension, size, magic_type, mime_type,
        is_plaintext, is_container, originating_object_id,
        nesting_level, file_creation_time, file_access_time,
        file_modification_time, security_info, hashes
    FROM files_enriched
"""

_FILE_ENRICHED_SELECT_QUERY_PSYCHOPG = f"""
{_FILE_ENRICHED_SELECT_QUERY}
WHERE object_id = %s
"""

_FILE_ENRICHED_SELECT_QUERY_ASYNCPG = f"""
{_FILE_ENRICHED_SELECT_QUERY}
WHERE object_id = $1
"""


def _transform_file_enriched_data(file_data: dict) -> dict:
    """
    Transform raw database data into format suitable for FileEnriched model.

    Handles:
    - UUID to string conversion
    - Datetime to ISO format conversion
    - JSON field parsing
    - None value removal

    Args:
        file_data: Dictionary of raw database values

    Returns:
        Transformed dictionary ready for FileEnriched.model_validate()
    """
    # Convert UUID to string
    if "object_id" in file_data and file_data["object_id"]:
        file_data["object_id"] = str(file_data["object_id"])
    if "originating_object_id" in file_data and file_data["originating_object_id"]:
        file_data["originating_object_id"] = str(file_data["originating_object_id"])

    # Convert datetime objects to ISO format strings
    datetime_fields = [
        "timestamp",
        "expiration",
        "file_creation_time",
        "file_access_time",
        "file_modification_time",
    ]
    for field in datetime_fields:
        if field in file_data and file_data[field]:
            file_data[field] = file_data[field].isoformat()

    # Handle JSON fields (parse if string, keep as-is if dict)
    if "security_info" in file_data and isinstance(file_data["security_info"], str):
        file_data["security_info"] = json.loads(file_data["security_info"])
    if "hashes" in file_data and isinstance(file_data["hashes"], str):
        file_data["hashes"] = json.loads(file_data["hashes"])

    # Remove None values
    file_data = {k: v for k, v in file_data.items() if v is not None}

    return file_data


def get_file_enriched(object_id: str) -> FileEnriched:
    """
    Retrieve a file_enriched record from PostgreSQL (synchronous).

    Args:
        object_id: The object_id to query

    Returns:
        FileEnriched model instance

    Raises:
        ValueError: If no record found for object_id
        Exception: For database or parsing errors
    """
    try:
        with psycopg.connect(get_postgres_connection_str()) as conn:
            with conn.cursor() as cur:
                cur.execute(_FILE_ENRICHED_SELECT_QUERY_PSYCHOPG, (object_id,))

                result = cur.fetchone()
                if not result:
                    raise ValueError(f"No file_enriched record found for object_id {object_id}")

                if not cur.description:
                    raise RuntimeError("Query returned no column descriptions")

                columns = [desc[0] for desc in cur.description]
                file_data = dict(zip(columns, result))

                # Transform data using shared helper
                file_data = _transform_file_enriched_data(file_data)

                return FileEnriched.model_validate(file_data)

    except ValueError as e:
        logger.error(f"File not found: {str(e)}")
        raise
    except Exception:
        logger.exception(message="Error retrieving file_enriched from PostgreSQL")
        raise


async def get_file_enriched_async(object_id: str, connection: str | asyncpg.Pool | None = None) -> FileEnriched:
    """
    Retrieve a file_enriched record from PostgreSQL (asynchronous using asyncpg).

    Args:
        object_id: The object_id to query
        connection: Optional connection string or asyncpg.Pool. If not provided, uses get_postgres_connection_str()

    Returns:
        FileEnriched model instance

    Raises:
        ValueError: If no record found for object_id
        Exception: For database or parsing errors
    """
    try:
        # Determine if we're using a pool or creating a new connection
        if isinstance(connection, asyncpg.Pool):
            # Use the provided pool
            row = await connection.fetchrow(_FILE_ENRICHED_SELECT_QUERY_ASYNCPG, object_id)
        else:
            # Use connection string (provided or default)
            connection_string = connection if connection is not None else get_postgres_connection_str()
            conn = await asyncpg.connect(connection_string)
            try:
                row = await conn.fetchrow(_FILE_ENRICHED_SELECT_QUERY_ASYNCPG, object_id)
            finally:
                await conn.close()

        if not row:
            raise ValueError(f"No file_enriched record found for object_id {object_id}")

        # Convert asyncpg.Record to dict
        file_data = dict(row)

        # Transform data using shared helper
        file_data = _transform_file_enriched_data(file_data)

        return FileEnriched.model_validate(file_data)

    except ValueError as e:
        logger.error(f"File not found: {str(e)}")
        raise
    except Exception:
        logger.exception(message="Error retrieving file_enriched from PostgreSQL (async)")
        raise

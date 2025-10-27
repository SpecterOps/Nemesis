"""Basic file analysis activity."""

import json
import pathlib
import posixpath
from datetime import datetime

import common.helpers as helpers
import magic
from common.helpers import get_file_extension, is_container
from common.logger import get_logger
from common.workflows.setup import workflow_activity
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext

from .. import global_vars

logger = get_logger(__name__)


@workflow_activity
async def get_basic_analysis(ctx: WorkflowActivityContext, activity_input):
    """
    Perform 'basic' analysis on a file and save to database. Run for every file.

    This activity downloads the file, processes it to extract metadata,
    and saves the results to the database.
    """
    object_id = activity_input["object_id"]

    with global_vars.storage.download(object_id) as file:
        file_enriched = process_basic_analysis(file.name, activity_input)
        await save_file_enriched_to_db(file_enriched)

        return file_enriched


def parse_timestamp(ts):
    """Parse a timestamp string or return the datetime object as-is."""
    if isinstance(ts, str):
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return ts


def process_basic_analysis(temp_file_path: str, activity_input: dict) -> dict:
    """
    Process a file and extract basic metadata including hashes, mime type, etc.

    Args:
        temp_file_path: Path to the temporary file to analyze
        activity_input: Dictionary containing file metadata (object_id, path, etc.)

    Returns:
        Dictionary with all file enrichment data (activity_input merged with basic_analysis)
    """
    path = activity_input.get("path", "")

    mime_type = magic.from_file(temp_file_path, mime=True)
    if mime_type == "text/plain" or helpers.is_text_file(temp_file_path):
        is_plaintext = True
    else:
        is_plaintext = False

    basic_analysis = {
        "file_name": posixpath.basename(path),
        "extension": get_file_extension(path),
        "size": pathlib.Path(temp_file_path).stat().st_size,
        "hashes": {
            "md5": helpers.calculate_file_hash(temp_file_path, "md5"),
            "sha1": helpers.calculate_file_hash(temp_file_path, "sha1"),
            "sha256": helpers.calculate_file_hash(temp_file_path, "sha256"),
        },
        "magic_type": magic.from_file(temp_file_path),
        "mime_type": mime_type,
        "is_plaintext": is_plaintext,
        "is_container": is_container(mime_type),
    }

    file_enriched = {
        **activity_input,
        **basic_analysis,
    }

    return file_enriched


async def save_file_enriched_to_db(file_enriched: dict) -> None:
    """
    Save file enrichment data to the PostgreSQL database.

    Args:
        file_enriched: Dictionary containing all file enrichment data
    """
    try:
        async with global_vars.asyncpg_pool.acquire() as conn:
            # Convert field names to match database schema
            insert_query = """
                INSERT INTO files_enriched (
                    object_id, agent_id, source, project, timestamp, expiration, path,
                    file_name, extension, size, magic_type, mime_type,
                    is_plaintext, is_container, originating_object_id, originating_container_id,
                    nesting_level, file_creation_time, file_access_time,
                    file_modification_time, security_info, hashes
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
                    $17, $18, $19, $20, $21, $22
                )
                ON CONFLICT (object_id) DO UPDATE SET
                    agent_id = EXCLUDED.agent_id,
                    source = EXCLUDED.source,
                    project = EXCLUDED.project,
                    timestamp = EXCLUDED.timestamp,
                    expiration = EXCLUDED.expiration,
                    path = EXCLUDED.path,
                    file_name = EXCLUDED.file_name,
                    extension = EXCLUDED.extension,
                    size = EXCLUDED.size,
                    magic_type = EXCLUDED.magic_type,
                    mime_type = EXCLUDED.mime_type,
                    is_plaintext = EXCLUDED.is_plaintext,
                    is_container = EXCLUDED.is_container,
                    originating_object_id = EXCLUDED.originating_object_id,
                    originating_container_id = EXCLUDED.originating_container_id,
                    nesting_level = EXCLUDED.nesting_level,
                    file_creation_time = EXCLUDED.file_creation_time,
                    file_access_time = EXCLUDED.file_access_time,
                    file_modification_time = EXCLUDED.file_modification_time,
                    security_info = EXCLUDED.security_info,
                    hashes = EXCLUDED.hashes,
                    updated_at = CURRENT_TIMESTAMP
            """

            await conn.execute(
                insert_query,
                file_enriched["object_id"],
                file_enriched.get("agent_id"),
                file_enriched.get("source"),
                file_enriched.get("project"),
                parse_timestamp(file_enriched.get("timestamp")),
                parse_timestamp(file_enriched.get("expiration")),
                file_enriched.get("path"),
                file_enriched.get("file_name"),
                file_enriched.get("extension"),
                file_enriched.get("size"),
                file_enriched.get("magic_type"),
                file_enriched.get("mime_type"),
                file_enriched.get("is_plaintext"),
                file_enriched.get("is_container"),
                file_enriched.get("originating_object_id"),
                file_enriched.get("originating_container_id"),
                file_enriched.get("nesting_level"),
                parse_timestamp(file_enriched.get("file_creation_time")),
                parse_timestamp(file_enriched.get("file_access_time")),
                parse_timestamp(file_enriched.get("file_modification_time")),
                json.dumps(file_enriched.get("security_info")) if file_enriched.get("security_info") else None,
                json.dumps(file_enriched.get("hashes")) if file_enriched.get("hashes") else None,
            )
            logger.debug("Stored file_enriched in PostgreSQL", object_id=file_enriched["object_id"])
    except Exception as e:
        logger.exception(e, message="Error storing file_enriched in PostgreSQL", file_enriched=file_enriched)
        raise

import json

import psycopg
import structlog
from dapr.clients import DaprClient

from common.models import FileEnriched

logger = structlog.get_logger(module=__name__)


with DaprClient() as client:
    secret = client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_STRING")
    postgres_connection_string = secret.secret["POSTGRES_CONNECTION_STRING"]


def get_file_enriched(object_id: str) -> FileEnriched:
    """Retrieve a file_enriched record from PostgreSQL and parse it into a FileEnriched object."""
    try:
        with psycopg.connect(postgres_connection_string) as conn:
            with conn.cursor() as cur:
                # Query remains the same
                cur.execute(
                    """
                    SELECT
                        object_id, agent_id, project, timestamp, expiration, path,
                        file_name, extension, size, magic_type, mime_type,
                        is_plaintext, is_container, originating_object_id,
                        nesting_level, file_creation_time, file_access_time,
                        file_modification_time, security_info, hashes
                    FROM files_enriched
                    WHERE object_id = %s
                """,
                    (object_id,),
                )

                result = cur.fetchone()
                if not result:
                    raise ValueError(f"No file_enriched record found for object_id {object_id}")

                columns = [desc[0] for desc in cur.description]
                file_data = dict(zip(columns, result))

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

                # Handle JSON fields
                if "security_info" in file_data and isinstance(file_data["security_info"], str):
                    file_data["security_info"] = json.loads(file_data["security_info"])
                if "hashes" in file_data and isinstance(file_data["hashes"], str):
                    file_data["hashes"] = json.loads(file_data["hashes"])

                # Remove None values
                file_data = {k: v for k, v in file_data.items() if v is not None}

                return FileEnriched.model_validate(file_data)

    except ValueError as e:
        logger.error(f"File not found: {str(e)}")
        raise
    except Exception as e:
        logger.exception(e, message="Error retrieving file_enriched from PostgreSQL")
        raise

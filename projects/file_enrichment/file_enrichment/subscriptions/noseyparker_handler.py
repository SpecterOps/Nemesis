"""Handler for Nosey Parker output subscription events."""

import json
import os

from common.logger import get_logger
from common.models import NoseyParkerOutput
from file_enrichment.noseyparker import store_noseyparker_results
from psycopg_pool import ConnectionPool

logger = get_logger(__name__)


async def process_noseyparker_event(raw_data, pool: ConnectionPool):
    """Process incoming Nosey Parker scan results"""
    try:
        # Extract the raw data
        # logger.debug(f"Received NoseyParker output event: {raw_data}", pid=os.getpid())

        # Try to parse the event data into our NoseyParkerOutput model
        try:
            # If it's already a dict, use the from_dict factory method
            if isinstance(raw_data, dict):
                nosey_output = NoseyParkerOutput.from_dict(raw_data)
            # If it's a string, try to parse it as JSON
            elif isinstance(raw_data, str):
                parsed_data = json.loads(raw_data)
                nosey_output = NoseyParkerOutput.from_dict(parsed_data)
            else:
                logger.warning(f"Unexpected data type: {type(raw_data)}", pid=os.getpid())
                return

            # Now process the properly parsed output
            object_id = nosey_output.object_id
            matches = nosey_output.scan_result.matches
            stats = nosey_output.scan_result.stats

            logger.debug(f"Found {len(matches)} matches for object {object_id}", pid=os.getpid())

            # Store the findings in the database using our helper function
            await store_noseyparker_results(
                object_id=object_id,
                matches=matches,
                scan_stats=stats,
                pool=pool,
            )

        except Exception as parsing_error:
            # If parsing fails, fall back to direct dictionary access
            logger.warning(f"Error parsing NoseyParker output as model: {parsing_error}", pid=os.getpid())

            if hasattr(raw_data, "get"):
                object_id = raw_data.get("object_id")
                scan_result = raw_data.get("scan_result", {})
                matches = scan_result.get("matches", [])
                stats = scan_result.get("stats", {})

                logger.debug(f"Using dict access: Found {len(matches)} matches for {object_id}", pid=os.getpid())

                # Store the findings using direct dict access
                await store_noseyparker_results(
                    object_id=f"{object_id}",
                    matches=matches,
                    scan_stats=stats,
                    pool=pool,
                )

    except Exception as e:
        logger.exception(e, message="Error processing Nosey Parker output event", pid=os.getpid())
        raise

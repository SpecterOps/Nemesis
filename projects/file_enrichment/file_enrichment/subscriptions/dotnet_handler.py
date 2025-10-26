"""Handler for .NET output subscription events."""

import json
import os

import asyncpg
from common.logger import get_logger
from common.models import DotNetOutput
from common.state_helpers import get_file_enriched_async
from file_enrichment.dotnet import store_dotnet_results

logger = get_logger(__name__)


async def process_dotnet_event(raw_data, pool: asyncpg.Pool):
    """Process incoming .NET processing results from the dotnet_service"""
    try:
        logger.debug(f"Received DotNet output event: {raw_data}", pid=os.getpid())

        # Try to parse the event data into our DotNetOutput model
        try:
            # If it's already a dict, use it directly
            if isinstance(raw_data, dict):
                dotnet_output = DotNetOutput(**raw_data)
            # If it's a string, try to parse it as JSON
            elif isinstance(raw_data, str):
                parsed_data = json.loads(raw_data)
                dotnet_output = DotNetOutput(**parsed_data)
            else:
                raise ValueError(f"Unexpected data type: {type(raw_data)}", pid=os.getpid())

            object_id = dotnet_output.object_id
            decompilation_object_id = dotnet_output.decompilation
            analysis = dotnet_output.get_parsed_analysis()

            logger.debug(f"Processing dotnet results for object {object_id}", pid=os.getpid())

            # Get the file enriched data for creating transforms
            try:
                file_enriched = await get_file_enriched_async(object_id)
            except Exception as e:
                file_enriched = None
                logger.warning(f"Could not get file_enriched for {object_id}: {e}", pid=os.getpid())

            # Store the results in the database using our helper function
            await store_dotnet_results(
                object_id=object_id,
                decompilation_object_id=decompilation_object_id,
                analysis=analysis,
                pool=pool,
                file_enriched=file_enriched,
            )

        except Exception as parsing_error:
            # If parsing fails, log the error and try to extract what we can
            logger.warning(f"Error parsing DotNet output as model: {parsing_error}", pid=os.getpid())
            logger.debug(f"Raw data: {raw_data}", pid=os.getpid())

            # Try to extract object_id at minimum for logging
            object_id = None
            if hasattr(raw_data, "get"):
                object_id = raw_data.get("object_id")
            elif isinstance(raw_data, dict):
                object_id = raw_data.get("object_id")

            logger.error(f"Failed to process DotNet output for object_id: {object_id}", pid=os.getpid())

    except Exception as e:
        logger.exception(e, message="Error processing DotNet output event", pid=os.getpid())
        raise

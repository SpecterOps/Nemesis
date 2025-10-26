"""Handler for .NET output subscription events."""

import asyncpg
from common.logger import get_logger
from common.models import DotNetOutput
from common.state_helpers import get_file_enriched_async
from file_enrichment.dotnet import store_dotnet_results

logger = get_logger(__name__)


async def process_dotnet_event(dotnet_output: DotNetOutput, pool: asyncpg.Pool) -> None:
    """Process incoming .NET processing results from the dotnet_service"""

    logger.debug("Received DotNet output event", data=dotnet_output.model_dump_json())

    # Try to parse the event data into our DotNetOutput model
    try:
        logger.debug("Processing dotnet results for object", object_id=dotnet_output.object_id)

        object_id = dotnet_output.object_id
        decompilation_object_id = dotnet_output.decompilation
        analysis = dotnet_output.get_parsed_analysis()

        file_enriched = await get_file_enriched_async(object_id)

        await store_dotnet_results(
            object_id=object_id,
            decompilation_object_id=decompilation_object_id,
            analysis=analysis,
            pool=pool,
            file_enriched=file_enriched,
        )

    except Exception:
        logger.error(
            "Failed to process DotNet output for object_id",
            object_id=dotnet_output.object_id,
        )

"""Handler for Nosey Parker output subscription events."""

import os

import asyncpg
from common.logger import get_logger
from common.models import NoseyParkerOutput
from file_enrichment.noseyparker import store_noseyparker_results

logger = get_logger(__name__)


async def process_noseyparker_event(nosey_output: NoseyParkerOutput, pool: asyncpg.Pool):
    """Process incoming Nosey Parker scan results"""
    try:
        object_id = nosey_output.object_id
        matches = nosey_output.scan_result.matches
        stats = nosey_output.scan_result.stats

        logger.debug(f"Found {len(matches)} matches for object {object_id}", pid=os.getpid())

        await store_noseyparker_results(
            object_id=object_id,
            matches=matches,
            scan_stats=stats,
            pool=pool,
        )

    except Exception as e:
        logger.exception(e, message="Error processing Nosey Parker output event", pid=os.getpid())
        raise

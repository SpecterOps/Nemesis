"""
Helper functions for enrichment modules to create file linkings programmatically.

This module provides a simple interface for enrichment modules to register
file relationships they discover during analysis.
"""

import asyncpg
from common.db import get_postgres_connection_str
from common.logger import get_logger

from .rules_engine import FileLinkingEngine

logger = get_logger(__name__)


async def add_file_linkings(
    source: str,
    source_file_path: str,
    linked_file_paths: list[str],
    link_type: str,
    collection_reason: str | None = None,
    connection_pool: asyncpg.Pool | None = None,
) -> int:
    """
    Add file linkings programmatically from enrichment modules.

    This is the main function enrichment modules should call to register
    file relationships they discover during analysis.

    Args:
        source: Source identifier (typically agent_id)
        source_file_path: Path of the file that triggered the linking
        linked_file_paths: List of file paths to link
        link_type: Type of relationship (e.g., "pe_import", "config_dependency")
        collection_reason: Optional reason for collection
        connection_pool: Optional asyncpg.Pool. If not provided, will create a new connection.

    Returns:
        int: Number of linkings created

    Example:
        # In a PE analysis module
        from file_linking.helpers import add_file_linkings

        # After discovering imported DLL paths
        linked_paths = [
            "C:\\Windows\\System32\\kernel32.dll",
            "C:\\Windows\\System32\\advapi32.dll"
        ]

        await add_file_linkings(
            source="agent123",
            source_file_path="C:\\malware\\sample.exe",
            linked_file_paths=linked_paths,
            link_type="pe_import",
            collection_reason="Required DLL dependencies for analysis",
            connection_pool=pool  # Pass pool for better performance
        )
    """

    try:
        if connection_pool is not None:
            file_linking_engine = FileLinkingEngine(connection_pool)
        else:
            # Fallback: create temporary pool for backward compatibility
            logger.warning(
                "add_file_linkings called without connection_pool, creating temporary connection. "
                "Consider passing a connection pool for better performance."
            )
            temp_pool = await asyncpg.create_pool(
                get_postgres_connection_str(),
                min_size=1,
                max_size=2,
            )
            try:
                file_linking_engine = FileLinkingEngine(temp_pool)
            finally:
                # Note: We'll close this pool after use below
                pass
    except Exception:
        logger.exception("[add_file_linkings]")
        return 0

    if not linked_file_paths:
        return 0

    try:
        result = await file_linking_engine.add_programmatic_linking(
            source=source,
            source_file_path=source_file_path,
            linked_file_paths=linked_file_paths,
            link_type=link_type,
            collection_reason=collection_reason,
        )

        # Close temporary pool if we created one
        if connection_pool is None and temp_pool:
            await temp_pool.close()

        return result

    except Exception as e:
        logger.exception(
            "[add_file_linkings] Error adding programmatic file linkings",
            source=source,
            source_file_path=source_file_path,
            linked_file_paths=linked_file_paths,
            link_type=link_type,
            error=str(e),
        )
        # Close temporary pool if we created one
        if connection_pool is None and temp_pool:
            await temp_pool.close()
        return 0


async def add_file_linking(
    source: str,
    source_file_path: str,
    linked_file_path: str,
    link_type: str,
    collection_reason: str | None = None,
    connection_pool: asyncpg.Pool | None = None,
) -> bool:
    """
    Add a single file linking (convenience function).

    Uses FileLinkingEngine.add_programmatic_linking() which handles placeholder resolution.

    Args:
        source: Source identifier
        source_file_path: Path of the source file
        linked_file_path: Path of the linked file
        link_type: Type of relationship
        collection_reason: Optional reason for collection
        connection_pool: Optional asyncpg.Pool. If not provided, will create a new connection.

    Returns:
        bool: True if successful, False otherwise
    """
    return (
        await add_file_linkings(
            source=source,
            source_file_path=source_file_path,
            linked_file_paths=[linked_file_path],
            link_type=link_type,
            collection_reason=collection_reason,
            connection_pool=connection_pool,
        )
        > 0
    )

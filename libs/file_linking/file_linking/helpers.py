"""
Helper functions for enrichment modules to create file linkings programmatically.

This module provides a simple interface for enrichment modules to register
file relationships they discover during analysis.
"""

import structlog
from dapr.clients import DaprClient

from .rules_engine import FileLinkingEngine

logger = structlog.get_logger(module=__name__)


def _get_postgres_conn_str():
    with DaprClient() as client:
        secret = client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_STRING")
        return secret.secret["POSTGRES_CONNECTION_STRING"]


def add_file_linkings(
    source: str,
    source_file_path: str,
    linked_file_paths: list[str],
    link_type: str,
    collection_reason: str | None = None,
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

        add_file_linkings(
            source="agent123",
            source_file_path="C:\\malware\\sample.exe",
            linked_file_paths=linked_paths,
            link_type="pe_import",
            collection_reason="Required DLL dependencies for analysis"
        )
    """

    try:
        file_linking_engine = FileLinkingEngine(_get_postgres_conn_str())
    except Exception as e:
        logger.exception(e, "[add_file_linkings]")

    if not file_linking_engine:
        logger.error("[add_file_linkings] File linking engine not initialized")
        return 0

    if not linked_file_paths:
        return 0

    try:
        return file_linking_engine.add_programmatic_linking(
            source=source,
            source_file_path=source_file_path,
            linked_file_paths=linked_file_paths,
            link_type=link_type,
            collection_reason=collection_reason,
        )

    except Exception as e:
        logger.exception(
            "[add_file_linkings] Error adding programmatic file linkings",
            source=source,
            source_file_path=source_file_path,
            linked_file_paths=linked_file_paths,
            link_type=link_type,
            error=str(e),
        )
        return 0


def add_file_linking(
    source: str, source_file_path: str, linked_file_path: str, link_type: str, collection_reason: str | None = None
) -> bool:
    """
    Add a single file linking (convenience function).

    Args:
        source: Source identifier
        source_file_path: Path of the source file
        linked_file_path: Path of the linked file
        link_type: Type of relationship
        collection_reason: Optional reason for collection

    Returns:
        bool: True if successful, False otherwise
    """
    return (
        add_file_linkings(
            source=source,
            source_file_path=source_file_path,
            linked_file_paths=[linked_file_path],
            link_type=link_type,
            collection_reason=collection_reason,
        )
        > 0
    )

"""
File linking system for Nemesis.

This module provides rule-based detection and tracking of file dependencies and relationships.
"""

from .database_service import FileLinkingDatabaseService, FileListingStatus
from .helpers import add_file_linking, add_file_listing
from .rules_engine import FileLinkingEngine

__all__ = [
    "FileLinkingEngine",
    "FileLinkingDatabaseService",
    "FileListingStatus",
    "add_file_linking",
    "add_file_listing",
]

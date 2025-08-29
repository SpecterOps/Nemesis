"""
File linking system for Nemesis.

This module provides rule-based detection and tracking of file dependencies and relationships.
"""

from .rules_engine import FileLinkingEngine
from .database_service import FileLinkingDatabaseService

__all__ = ["FileLinkingEngine", "FileLinkingDatabaseService"]

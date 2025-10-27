"""
Placeholder resolution for file paths in file_listings and file_linkings tables.

Provides bidirectional resolution between placeholder paths (e.g., containing <WINDOWS_USERNAME>)
and real file paths, handling files arriving in any order.
"""

import re
from dataclasses import dataclass

from common.logger import get_logger

from file_linking.database_service import FileLinkingDatabaseService

logger = get_logger(__name__)


@dataclass
class PlaceholderDefinition:
    """Definition of a placeholder with its regex pattern."""

    name: str  # e.g., '<WINDOWS_USERNAME>'
    pattern: str  # Regex pattern with capture group
    description: str


# Registry of known placeholders - single source of truth
# Add new placeholders here to automatically support them throughout the system
PLACEHOLDERS = [
    PlaceholderDefinition(
        name="<WINDOWS_USERNAME>",
        pattern=r'([^"\\/\[\]:;|=,+*?<>]+)',
        description="Windows username (excludes forbidden characters)",
    ),
    PlaceholderDefinition(
        name="<WINDOWS_SECURITY_IDENTIFIER>",
        pattern=r"(S-1-5-(?:18|19|20|21-\d+-\d+-\d+-\d+))",
        description="Windows SID (supports user and system SIDs)",
    ),
    PlaceholderDefinition(
        name="<WINDOWS_MACHINE_GUID>",
        pattern=r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
        description="Windows Machine GUID (8-4-4-4-12 hex digits)",
    ),
]


class PlaceholderResolver:
    """
    Resolves placeholders in file paths bidirectionally.

    Supports two resolution modes:
    1. Forward: Real file arrives → update existing placeholder entries
    2. Backward: Placeholder path needed → check if real file already exists
    """

    def __init__(self, db_service: FileLinkingDatabaseService):
        """
        Initialize the placeholder resolver.

        Args:
            db_service: FileLinkingDatabaseService instance for database operations
        """
        self.db_service = db_service

    def _convert_placeholder_to_regex(self, template_path: str) -> re.Pattern | None:
        """
        Convert a placeholder template path to a compiled regex pattern.

        Replaces each placeholder with its regex pattern and escapes special characters.
        Handles both full paths and bare filenames.

        Args:
            template_path: Path containing placeholders (e.g., '/C:/Users/<WINDOWS_USERNAME>/...')

        Returns:
            Compiled case-insensitive regex pattern, or None if no placeholders found

        Example:
            Input:  '/C:/Users/<WINDOWS_USERNAME>/AppData/Roaming/file.txt'
            Output: Pattern matching '/C:/Users/john.doe/AppData/Roaming/file.txt' (case-insensitive)
        """
        if not template_path or ("<" not in template_path and ">" not in template_path):
            return None

        # Start with the template path
        regex_str = template_path

        # Track which placeholders we're replacing
        found_placeholders = []

        # Replace each placeholder with its regex pattern
        for placeholder_def in PLACEHOLDERS:
            if placeholder_def.name in regex_str:
                regex_str = regex_str.replace(placeholder_def.name, placeholder_def.pattern)
                found_placeholders.append(placeholder_def.name)

        if not found_placeholders:
            return None

        # Escape special regex characters, but preserve our capture groups
        # First, temporarily replace capture groups with placeholders
        group_placeholder = "###CAPTURE_GROUP_{}###"
        group_count = 0
        temp_str = regex_str

        # Extract and protect capture groups
        capture_groups = []
        while "(" in temp_str:
            start = temp_str.find("(")
            depth = 1
            i = start + 1
            while i < len(temp_str) and depth > 0:
                if temp_str[i] == "(":
                    depth += 1
                elif temp_str[i] == ")":
                    depth -= 1
                i += 1

            if depth == 0:
                capture_group = temp_str[start:i]
                capture_groups.append(capture_group)
                temp_str = temp_str[:start] + group_placeholder.format(group_count) + temp_str[i:]
                group_count += 1
            else:
                break

        # Escape regex special characters in the non-capture-group parts
        temp_str = re.escape(temp_str)

        # Restore capture groups
        for i, capture_group in enumerate(capture_groups):
            temp_str = temp_str.replace(re.escape(group_placeholder.format(i)), capture_group)

        # Compile with case-insensitive flag for Windows paths
        try:
            pattern = re.compile(temp_str, re.IGNORECASE)
            logger.debug(
                "Converted placeholder template to regex",
                template=template_path,
                placeholders=found_placeholders,
            )
            return pattern
        except re.error as e:
            logger.warning("Failed to compile regex pattern", template=template_path, error=str(e))
            return None

    def _replace_placeholders_with_captures(self, template_path: str, match: re.Match) -> str:
        """
        Replace placeholders in template with captured values from regex match.

        Args:
            template_path: Original path with placeholders
            match: Regex match object with captured groups

        Returns:
            Path with placeholders replaced by actual values

        Example:
            Input:  template='/C:/Users/<WINDOWS_USERNAME>/file.txt', match with group='john.doe'
            Output: '/C:/Users/john.doe/file.txt'
        """
        result = template_path
        captured_values = match.groups()

        if not captured_values:
            return template_path

        # Replace placeholders in order with captured values
        group_index = 0
        for placeholder_def in PLACEHOLDERS:
            if placeholder_def.name in result and group_index < len(captured_values):
                captured_value = captured_values[group_index]
                result = result.replace(placeholder_def.name, captured_value)
                group_index += 1
                logger.debug(
                    "Replaced placeholder",
                    placeholder=placeholder_def.name,
                    value=captured_value,
                )

        return result

    async def resolve_placeholders_for_file(self, file_path: str, source: str) -> int:
        """
        Forward resolution: Match a real file against placeholder entries and update them.

        Called when a real file arrives to resolve any existing placeholder entries
        that match this file's path.

        Args:
            file_path: Real file path that was just collected
            source: Source identifier

        Returns:
            Number of placeholder entries resolved

        Example:
            Placeholder entry: '/C:/Users/<WINDOWS_USERNAME>/AppData/.../abc123'
            Real file arrives: '/C:/Users/john.doe/AppData/.../abc123'
            → Updates placeholder entry to use real path
        """
        if not file_path or not source:
            return 0

        # Query for placeholder entries for this source
        placeholder_entries = await self.db_service.get_placeholder_entries(source)

        if not placeholder_entries:
            logger.debug("No placeholder entries found for source", source=source)
            return 0

        resolved_count = 0

        for entry in placeholder_entries:
            table_name = entry["table_name"]
            placeholder_path = entry["path"]

            # Convert placeholder path to regex
            pattern = self._convert_placeholder_to_regex(placeholder_path)
            if not pattern:
                continue

            # Try to match against the real file path
            match = pattern.match(file_path)

            if match:
                # Resolve the placeholder path using captured values
                resolved_path = self._replace_placeholders_with_captures(placeholder_path, match)

                logger.info(
                    "Matched placeholder entry with real file",
                    placeholder_path=placeholder_path,
                    real_path=file_path,
                    resolved_path=resolved_path,
                    table=table_name,
                    source=source,
                )

                # Update the database
                if table_name == "file_listings":
                    await self.db_service.update_file_listing_path(source, placeholder_path, resolved_path)
                elif table_name == "file_linkings":
                    await self.db_service.update_file_linking_path(source, placeholder_path, resolved_path)

                resolved_count += 1

        if resolved_count > 0:
            logger.info(
                "Resolved placeholder entries",
                file_path=file_path,
                source=source,
                count=resolved_count,
            )

        return resolved_count

    async def try_resolve_placeholder_path(self, source: str, placeholder_path: str) -> str | None:
        """
        Backward resolution: Try to find a real file that matches a placeholder path.

        Called before inserting a new placeholder path to check if a matching
        real file already exists.

        Args:
            source: Source identifier
            placeholder_path: Path containing placeholders

        Returns:
            Real file path if match found, None otherwise

        Example:
            Placeholder needed: '/C:/Users/<WINDOWS_USERNAME>/AppData/.../abc123'
            Real file exists:   '/C:/Users/john.doe/AppData/.../abc123'
            → Returns the real path instead of creating placeholder entry
        """
        if not placeholder_path or not source:
            return None

        # Only process if path contains placeholders
        if "<" not in placeholder_path or ">" not in placeholder_path:
            return None

        # Convert placeholder path to regex pattern
        pattern = self._convert_placeholder_to_regex(placeholder_path)
        if not pattern:
            return None

        # Get all collected files for this source
        collected_files = await self.db_service.get_collected_files(source)

        if not collected_files:
            logger.debug("No collected files found for backward resolution", source=source)
            return None

        # Try to match each collected file against the placeholder pattern
        for real_path in collected_files:
            match = pattern.match(real_path)

            if match:
                logger.info(
                    "Found existing file matching placeholder path (backward resolution)",
                    placeholder_path=placeholder_path,
                    real_path=real_path,
                    source=source,
                )
                return real_path

        logger.debug(
            "No existing file matches placeholder path",
            placeholder_path=placeholder_path,
            source=source,
        )
        return None

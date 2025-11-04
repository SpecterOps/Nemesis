"""
File linking rules engine.

Processes files to detect relationships and create linkings based on:
1. YAML rule files
2. Programmatic calls from enrichment modules
"""

import fnmatch
import os
import posixpath
from dataclasses import dataclass

import asyncpg
import yaml
from common.logger import get_logger
from common.models import FileEnriched

from .database_service import FileLinkingDatabaseService, FileListingStatus
from .placeholder_resolver import PlaceholderResolver

logger = get_logger(__name__)


@dataclass
class Trigger:
    """Represents a trigger condition for a linking rule."""

    file_patterns: list[str]
    mime_patterns: list[str]
    magic_patterns: list[str]


@dataclass
class LinkedFile:
    """Represents a file that should be linked/collected."""

    name: str
    description: str
    path_templates: list[str]
    priority: str
    collection_reason: str


@dataclass
class LinkingRule:
    """Represents a complete linking rule from YAML."""

    name: str
    description: str
    category: str
    enabled: bool
    triggers: list[Trigger]
    linked_files: list[LinkedFile]


class FileLinkingEngine:
    """
    Engine for processing file linking rules and creating database entries.

    Supports both YAML-based rules and programmatic calls from enrichment modules.
    """

    def __init__(self, connection_pool: asyncpg.Pool, rules_dir: str | None = None):
        self.db_service = FileLinkingDatabaseService(connection_pool)
        self.placeholder_resolver = PlaceholderResolver(self.db_service)
        self.rules: list[LinkingRule] = []

        if rules_dir is None:
            rules_dir = os.path.join(os.path.dirname(__file__), "rules")

        self.rules_dir = rules_dir
        self._load_rules()

    def _load_rules(self) -> None:
        """Load all YAML rule files from the rules directory."""
        if not os.path.exists(self.rules_dir):
            logger.warning("Rules directory does not exist", rules_dir=self.rules_dir)
            return

        rules_loaded = 0

        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith(".yaml") or file.endswith(".yml"):
                    rule_path = os.path.join(root, file)
                    try:
                        rule = self._load_rule_file(rule_path)
                        if rule and rule.enabled:
                            self.rules.append(rule)
                            rules_loaded += 1
                    except Exception as e:
                        logger.exception("Error loading rule file", rule_path=rule_path, error=str(e))

        logger.info("Loaded file linking rules", count=rules_loaded, rules_dir=self.rules_dir)

    def _load_rule_file(self, rule_path: str) -> LinkingRule | None:
        """Load a single YAML rule file."""
        try:
            with open(rule_path) as f:
                data = yaml.safe_load(f)

            # Convert triggers dictionaries to Trigger objects
            triggers = []
            for trigger_data in data.get("triggers", []):
                triggers.append(
                    Trigger(
                        file_patterns=trigger_data.get("file_patterns", []),
                        mime_patterns=trigger_data.get("mime_patterns", []),
                        magic_patterns=trigger_data.get("magic_patterns", []),
                    )
                )

            # Convert linked_files dictionaries to LinkedFile objects
            linked_files = []
            for lf_data in data.get("linked_files", []):
                linked_files.append(
                    LinkedFile(
                        name=lf_data["name"],
                        description=lf_data["description"],
                        path_templates=lf_data["path_templates"],
                        priority=lf_data["priority"],
                        collection_reason=lf_data["collection_reason"],
                    )
                )

            return LinkingRule(
                name=data["name"],
                description=data["description"],
                category=data["category"],
                enabled=data.get("enabled", True),
                triggers=triggers,
                linked_files=linked_files,
            )

        except Exception as e:
            logger.exception("Error parsing rule file", rule_path=rule_path, error=str(e))
            return None

    def _matches_trigger(self, file_enriched: FileEnriched, trigger: Trigger) -> bool:
        """Check if a file matches a path, mime type, or magic type trigger condition."""
        file_path = file_enriched.path
        mime_type = file_enriched.mime_type
        magic_type = file_enriched.magic_type

        # Check file patterns
        logger.debug(f"file_patterns: {trigger.file_patterns}")

        if trigger.file_patterns:
            path_match = any(fnmatch.fnmatch(file_path, pattern) for pattern in trigger.file_patterns)

            if not path_match:
                return False

        # Check MIME types
        if trigger.mime_patterns and mime_type not in trigger.mime_patterns:
            logger.debug(f"path_match but mime types mismatch: {mime_type}")
            return False

        # Check magic patterns
        if trigger.magic_patterns:
            magic_match = any(pattern in magic_type for pattern in trigger.magic_patterns)
            if not magic_match:
                logger.debug("path_match but magic string mismatch")
                return False

        return True

    async def _resolve_backward(self, source: str, linked_path: str) -> tuple[str, FileListingStatus]:
        """
        Perform backward resolution: check if a placeholder path has a matching real file.

        Args:
            source: Source identifier
            linked_path: Path that may contain placeholders

        Returns:
            Tuple of (resolved_path, status) where:
            - resolved_path: The real path if found, otherwise the original linked_path
            - status: COLLECTED if resolved, NEEDS_TO_BE_COLLECTED otherwise
        """
        status = FileListingStatus.NEEDS_TO_BE_COLLECTED
        final_path = linked_path

        if "<" in linked_path and ">" in linked_path:
            try:
                resolved_path = await self.placeholder_resolver.try_resolve_placeholder_path(source, linked_path)
                if resolved_path:
                    logger.info(
                        "Backward resolution: found existing file for placeholder",
                        placeholder_path=linked_path,
                        real_path=resolved_path,
                        source=source,
                    )
                    final_path = resolved_path
                    status = FileListingStatus.COLLECTED
            except Exception as e:
                logger.warning(
                    "Error in backward placeholder resolution",
                    linked_path=linked_path,
                    source=source,
                    error=str(e),
                )

        return final_path, status

    async def _resolve_forward_for_table(self, source: str, real_path: str, table_name: str) -> None:
        """
        Perform forward resolution for a specific table: check if a real path matches placeholders.

        Resolves ALL matching placeholders, not just the first one.

        Args:
            source: Source identifier
            real_path: The real file path (no placeholders)
            table_name: Either "file_listings" or "file_linkings"
        """
        if "<" in real_path and ">" in real_path:
            # This is a placeholder, not a real path, skip forward resolution
            return

        try:
            placeholder_entries = await self.db_service.get_placeholder_entries(source)

            for entry in placeholder_entries:
                if entry["table_name"] != table_name:
                    continue

                placeholder_path = entry["path"]

                # Convert placeholder to regex and try to match
                pattern = self.placeholder_resolver._convert_placeholder_to_regex(placeholder_path)
                if pattern and pattern.match(real_path):
                    # This real path matches an existing placeholder
                    resolved_path = self.placeholder_resolver._replace_placeholders_with_captures(
                        placeholder_path, pattern.match(real_path)
                    )

                    logger.info(
                        f"Forward resolution matched placeholder in {table_name}",
                        placeholder_path=placeholder_path,
                        real_path=real_path,
                        source=source,
                    )

                    # Update the placeholder in the appropriate table
                    if table_name == "file_listings":
                        await self.db_service.update_file_listing_path(source, placeholder_path, resolved_path)
                    elif table_name == "file_linkings":
                        await self.db_service.update_file_linking_path(source, placeholder_path, resolved_path)
                    # Continue checking other placeholders (no break)

        except Exception as e:
            logger.warning(
                f"Error in forward placeholder resolution for {table_name}",
                real_path=real_path,
                source=source,
                error=str(e),
            )

    def _expand_path_template(self, template: str, file_path: str) -> str:
        """Expand a path template with file-specific values."""

        if not file_path:
            return template

        # Files are already normalized to posix paths, so base it off that
        parent_dir = posixpath.dirname(file_path)
        basename = posixpath.splitext(posixpath.basename(file_path))[0]
        filename = posixpath.basename(file_path)
        extension = posixpath.splitext(file_path)[1]

        replacements = {
            "{parent_dir}": parent_dir,
            "{file_dir}": parent_dir,
            "{basename}": basename,
            "{filename}": filename,
            "{extension}": extension,
        }

        expanded = template
        for placeholder, value in replacements.items():
            expanded = expanded.replace(placeholder, value)

        logger.debug(f"Template: {template}, File path: {file_path}, Expanded before normpath: {expanded}")

        expanded = posixpath.normpath(expanded)
        logger.debug(f"Final expanded path: {expanded}")

        return expanded

    async def apply_linking_rules(self, file_enriched: FileEnriched) -> int:
        """
        Apply YAML-based linking rules to an enriched file.

        Evaluates the file against all loaded rule triggers. When a match is found,
        expands path templates to identify related files, marks them for collection,
        and creates linkings between the source file and related files.

        Also performs bidirectional placeholder resolution:
        - Forward: resolves existing placeholder entries using this real file
        - Backward: checks if placeholder paths already have matching real files

        Database operations use individual atomic upserts to avoid deadlocks in
        concurrent file processing scenarios.

        Args:
            file_enriched: File data from files_enriched table

        Returns:
            int: Number of linkings created
        """

        linkings_created = 0
        file_path = file_enriched.path

        if file_enriched.source:
            source = file_enriched.source
        elif file_enriched.agent_id:
            source = file_enriched.agent_id
        else:
            source = "unknown"

        logger.debug(
            "Applying linking rules",
            file_path=file_path,
            source=source,
            mime_type=file_enriched.mime_type,
            magic_type=file_enriched.magic_type,
            size=file_enriched.size,
            is_container=file_enriched.is_container,
        )

        # Skip marking these commonly derived files as collected
        if file_path.endswith("/strings.txt") or file_path.endswith("/decompiled.zip"):
            return 0

        # Forward resolution: Try to resolve existing placeholder entries with this real file
        # IMPORTANT: Do this BEFORE add_file_listing so the placeholder gets updated first,
        # then add_file_listing will find the updated row and not create a duplicate
        # NOTE: No transaction wrapper to avoid deadlocks during concurrent processing
        await self._resolve_forward_for_table(source, file_path, "file_listings")
        await self._resolve_forward_for_table(source, file_path, "file_linkings")

        await self.db_service.add_file_listing(
            source=source,
            path=file_path,
            status=FileListingStatus.COLLECTED,
            object_id=file_enriched.object_id,
        )
        logger.debug("Adding file listing (collected)", file_path=file_path, source=source)

        # Process each rule
        for rule in self.rules:
            try:
                # Check if any trigger matches
                for trigger in rule.triggers:
                    if self._matches_trigger(file_enriched, trigger):
                        logger.debug("File matches rule trigger", rule_name=rule.name, file_path=file_path)

                        # Process linked files for this rule
                        for linked_file in rule.linked_files:
                            for template in linked_file.path_templates:
                                linked_path = self._expand_path_template(template, file_enriched.path)

                                # Backward resolution: If linked_path contains placeholders,
                                # check if a matching real file already exists
                                linked_path, status = await self._resolve_backward(source, linked_path)

                                # Add file listing
                                await self.db_service.add_file_listing(
                                    source=source,
                                    path=linked_path,
                                    status=status,
                                )

                                # Add file linking
                                link_type = f"{rule.category}:{linked_file.name}"
                                await self.db_service.add_file_linking(
                                    source=source,
                                    file_path_1=file_path,
                                    file_path_2=linked_path,
                                    link_type=link_type,
                                )

                                linkings_created += 1

                                logger.debug(
                                    "Created file linking",
                                    rule_name=rule.name,
                                    linked_file=linked_file.name,
                                    source_path=file_path,
                                    linked_path=linked_path,
                                    link_type=link_type,
                                )

                        # Only match first trigger per rule
                        break

            except Exception as e:
                logger.exception("Error processing rule", rule_name=rule.name, file_path=file_path, error=str(e))

        if linkings_created > 0:
            logger.info("Created file linkings from rules", file_path=file_path, linkings_created=linkings_created)

        return linkings_created

    async def add_programmatic_linking(
        self,
        source: str,
        source_file_path: str,
        linked_file_paths: list[str],
        link_type: str,
        collection_reason: str | None = None,
    ) -> int:
        """
        Add file linkings programmatically (called by enrichment modules).

        Performs bidirectional placeholder resolution:
        - If linked_path has placeholders: checks if real file exists (backward resolution)
        - If linked_path is real: checks if placeholder exists and resolves it (forward resolution)

        Database operations use individual atomic upserts to avoid deadlocks in
        concurrent file processing scenarios.

        Args:
            source: Source identifier
            source_file_path: Path of the file that triggered the linking
            linked_file_paths: List of file paths to link
            link_type: Type of relationship
            collection_reason: Reason for collection (stored in link_type if provided)

        Returns:
            int: Number of linkings created
        """
        linkings_created = 0

        for linked_path in linked_file_paths:
            # Backward resolution: If linked_path contains placeholders,
            # check if a matching real file already exists in file_listings
            final_linked_path, status = await self._resolve_backward(source, linked_path)

            # Forward resolution: If linked_path is a real path,
            # check if placeholders exist that match it, and resolve them
            await self._resolve_forward_for_table(source, final_linked_path, "file_linkings")
            await self._resolve_forward_for_table(source, final_linked_path, "file_listings")

            # Add file listing
            await self.db_service.add_file_listing(
                source=source,
                path=final_linked_path,
                status=status,
            )

            # Add file linking
            full_link_type = link_type
            if collection_reason:
                full_link_type += f":{collection_reason}"

            await self.db_service.add_file_linking(
                source=source,
                file_path_1=source_file_path,
                file_path_2=final_linked_path,
                link_type=full_link_type,
            )

            linkings_created += 1

            logger.debug(
                "Created programmatic file linking",
                source_path=source_file_path,
                linked_path=final_linked_path,
                link_type=full_link_type,
            )

        return linkings_created

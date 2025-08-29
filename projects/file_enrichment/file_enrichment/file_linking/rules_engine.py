"""
File linking rules engine.

Processes files to detect relationships and create linkings based on:
1. YAML rule files
2. Programmatic calls from enrichment modules
"""

import fnmatch
import ntpath
import os
import posixpath
from dataclasses import dataclass
from typing import Any

import structlog
import yaml

from .database_service import FileLinkingDatabaseService, FileListingStatus, _normalize_file_path

logger = structlog.get_logger(module=__name__)


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
    triggers: list[dict[str, Any]]
    linked_files: list[LinkedFile]


class FileLinkingEngine:
    """
    Engine for processing file linking rules and creating database entries.

    Supports both YAML-based rules and programmatic calls from enrichment modules.
    """

    def __init__(self, postgres_connection_string: str, rules_dir: str | None = None):
        self.db_service = FileLinkingDatabaseService(postgres_connection_string)
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

        for root, dirs, files in os.walk(self.rules_dir):
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
                triggers=data.get("triggers", []),
                linked_files=linked_files,
            )

        except Exception as e:
            logger.exception("Error parsing rule file", rule_path=rule_path, error=str(e))
            return None

    def _matches_trigger(self, file_enriched: dict[str, Any], trigger: dict[str, Any]) -> bool:
        """Check if a file matches a trigger condition."""
        file_path = file_enriched.get("path", "")
        mime_type = file_enriched.get("mime_type", "")
        magic_type = file_enriched.get("magic_type", "")

        # Check file patterns
        file_patterns = trigger.get("file_patterns", [])
        logger.debug(f"file_patterns: {file_patterns}")
        if file_patterns:
            # Normalize path separators for cross-platform matching
            normalized_file_path = file_path.replace("\\", "/")
            normalized_patterns = [pattern.replace("\\", "/") for pattern in file_patterns]
            path_match = any(fnmatch.fnmatch(normalized_file_path, pattern) for pattern in normalized_patterns)

            if not path_match:
                return False

        # Check MIME types
        mime_types = trigger.get("mime_types", [])
        if mime_types and mime_type not in mime_types:
            logger.debug("path_match but mime types mismatch")
            return False

        # Check magic patterns
        magic_patterns = trigger.get("magic_patterns", [])
        if magic_patterns:
            magic_match = any(pattern in magic_type for pattern in magic_patterns)
            if not magic_match:
                logger.debug("path_match but magic string mismatch")
                return False

        return True

    def _expand_path_template(self, template: str, file_enriched: dict[str, Any]) -> str:
        """Expand a path template with file-specific values."""
        file_path = file_enriched.get("path", "")

        if not file_path:
            return template

        # Use appropriate path handling based on path style
        if "\\" in file_path:
            # Windows-style path - force ntpath usage
            parent_dir = ntpath.dirname(file_path)
            basename = ntpath.splitext(ntpath.basename(file_path))[0]
            filename = ntpath.basename(file_path)
            extension = ntpath.splitext(file_path)[1]
        else:
            # Unix-style path - use posixpath
            parent_dir = posixpath.dirname(file_path)
            basename = posixpath.splitext(posixpath.basename(file_path))[0]
            filename = posixpath.basename(file_path)
            extension = posixpath.splitext(file_path)[1]

        # Debug logging
        logger.debug(f"Path parsing - file_path: {file_path}, parent_dir: {parent_dir}")

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

        # Resolve relative path navigation using appropriate path library
        if "\\" in file_path:
            # Windows-style path - use ntpath
            expanded = ntpath.normpath(expanded)
        else:
            # Unix-style path - use posixpath
            expanded = posixpath.normpath(expanded)

        # Normalize the final path to use the same separator as the original file path
        if "\\" in file_path:
            # Windows-style paths - convert forward slashes to backslashes
            expanded = expanded.replace("/", "\\")
        else:
            # Unix-style paths - convert backslashes to forward slashes
            expanded = expanded.replace("\\", "/")

        logger.debug(f"normpath expanded: {expanded}")

        return expanded

    def process_file(self, file_enriched: dict[str, Any]) -> int:
        """
        Process a file against all loaded rules and create linkings.

        Args:
            file_enriched: File data from files_enriched table

        Returns:
            int: Number of linkings created
        """
        if not file_enriched.get("path"):
            logger.debug("Skipping file with no path", object_id=file_enriched.get("object_id"))
            return 0

        linkings_created = 0
        file_path = file_enriched["path"]
        source = file_enriched.get("source", file_enriched.get("agent_id", "unknown"))

        logger.debug(
            f"Processing file: {file_path}, source: {source}, file_enriched keys: {list(file_enriched.keys())}"
        )

        # Mark the current file as collected (save for two commonly derived files)
        if not file_path.endswith("/strings.txt") and not file_path.endswith("/decompiled.zip"):
            self.db_service.add_file_listing(
                source=source,
                path=_normalize_file_path(file_path),
                status=FileListingStatus.COLLECTED,
                object_id=file_enriched.get("object_id"),
            )

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
                                linked_path = self._expand_path_template(template, file_enriched)

                                # Add file listing
                                self.db_service.add_file_listing(
                                    source=source,
                                    path=_normalize_file_path(linked_path),
                                    status=FileListingStatus.NEEDS_TO_BE_COLLECTED,
                                )

                                # Add file linking
                                link_type = f"{rule.category}:{linked_file.name}"
                                self.db_service.add_file_linking(
                                    source=source,
                                    file_path_1=_normalize_file_path(file_path),
                                    file_path_2=_normalize_file_path(linked_path),
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

    def add_programmatic_linking(
        self,
        source: str,
        source_file_path: str,
        linked_file_paths: list[str],
        link_type: str,
        collection_reason: str | None = None,
    ) -> int:
        """
        Add file linkings programmatically (called by enrichment modules).

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

        try:
            for linked_path in linked_file_paths:
                # Add file listing
                self.db_service.add_file_listing(
                    source=source,
                    path=_normalize_file_path(linked_path),
                    status=FileListingStatus.NEEDS_TO_BE_COLLECTED,
                )

                # Add file linking
                full_link_type = f"programmatic:{link_type}"
                if collection_reason:
                    full_link_type += f":{collection_reason}"

                self.db_service.add_file_linking(
                    source=source,
                    file_path_1=_normalize_file_path(source_file_path),
                    file_path_2=_normalize_file_path(linked_path),
                    link_type=full_link_type,
                )

                linkings_created += 1

                logger.debug(
                    "Created programmatic file linking",
                    source_path=source_file_path,
                    linked_path=linked_path,
                    link_type=full_link_type,
                )

        except Exception as e:
            logger.exception(
                "Error creating programmatic linkings",
                source=source,
                source_file_path=source_file_path,
                linked_file_paths=linked_file_paths,
                error=str(e),
            )

        if linkings_created > 0:
            logger.info(
                "Created programmatic file linkings",
                source_file_path=source_file_path,
                linkings_created=linkings_created,
                link_type=link_type,
            )

        return linkings_created

    def reload_rules(self) -> None:
        """Reload all rules from disk."""
        self.rules.clear()
        self._load_rules()
        logger.info("Reloaded file linking rules", count=len(self.rules))

    def get_rules_summary(self) -> list[dict[str, Any]]:
        """Get summary of loaded rules."""
        return [
            {
                "name": rule.name,
                "description": rule.description,
                "category": rule.category,
                "enabled": rule.enabled,
                "trigger_count": len(rule.triggers),
                "linked_files_count": len(rule.linked_files),
            }
            for rule in self.rules
        ]

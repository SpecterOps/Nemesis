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

import yaml
from common.logger import get_logger
from common.models import FileEnriched

from .database_service import FileLinkingDatabaseService, FileListingStatus

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
            logger.debug("path_match but mime types mismatch")
            return False

        # Check magic patterns
        if trigger.magic_patterns:
            magic_match = any(pattern in magic_type for pattern in trigger.magic_patterns)
            if not magic_match:
                logger.debug("path_match but magic string mismatch")
                return False

        return True

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

    def process_file(self, file_enriched: FileEnriched) -> int:
        """
        Process a file against all loaded rules and create linkings.

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
            f"Processing file: {file_path}, source: {source}, file_enriched keys: {list(file_enriched.keys())}"
        )

        # Mark the current file as collected (save for two commonly derived files)
        if not file_path.endswith("/strings.txt") and not file_path.endswith("/decompiled.zip"):
            self.db_service.add_file_listing(
                source=source,
                path=file_path,
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
                                linked_path = self._expand_path_template(template, file_enriched.path)

                                # Add file listing
                                self.db_service.add_file_listing(
                                    source=source,
                                    path=linked_path,
                                    status=FileListingStatus.NEEDS_TO_BE_COLLECTED,
                                )

                                # Add file linking
                                link_type = f"{rule.category}:{linked_file.name}"
                                self.db_service.add_file_linking(
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

        for linked_path in linked_file_paths:
            # Add file listing
            self.db_service.add_file_listing(
                source=source,
                path=linked_path,
                status=FileListingStatus.NEEDS_TO_BE_COLLECTED,
            )

            # Add file linking
            full_link_type = link_type  # f"programmatic:{link_type}"
            if collection_reason:
                full_link_type += f":{collection_reason}"

            self.db_service.add_file_linking(
                source=source,
                file_path_1=source_file_path,
                file_path_2=linked_path,
                link_type=full_link_type,
            )

            linkings_created += 1

            logger.debug(
                "Created programmatic file linking",
                source_path=source_file_path,
                linked_path=linked_path,
                link_type=full_link_type,
            )



        if linkings_created > 0:
            logger.info(
                "Created programmatic file linkings",
                source_file_path=source_file_path,
                linkings_created=linkings_created,
                link_type=link_type,
            )

        return linkings_created


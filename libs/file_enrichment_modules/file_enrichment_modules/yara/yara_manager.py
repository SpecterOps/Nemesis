import glob
import os
import threading
from datetime import UTC, datetime
from typing import Optional

import plyara
import psycopg
import structlog
import yara_x
from common.dependency_checks import check_directory_exists
from dapr.clients import DaprClient
from plyara import utils as plyara_utils
from psycopg.rows import dict_row

logger = structlog.get_logger(module=__name__)

YARA_RULES_FOLDER_PATH = os.getenv("YARA_RULES_FOLDER_PATH", "/yara_rules/")
check_directory_exists(YARA_RULES_FOLDER_PATH)


class YaraRuleManager:
    _thread_local = threading.local()

    def __init__(self):
        self.parser = plyara.Plyara()
        self._compiler = yara_x.Compiler()
        self._compiled_rules: Optional[yara_x.Rules] = None

        with DaprClient() as client:
            secret = client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_STRING")
            postgres_connection_string = secret.secret["POSTGRES_CONNECTION_STRING"]

        self._conninfo = postgres_connection_string

        # Load and compile rules from disk first
        self._process_disk_rules()

        # Then load enabled rules from database
        self.load_rules()

    def _get_scanner(self) -> Optional[yara_x.Scanner]:
        """Get or create thread-local scanner instance."""
        if not hasattr(self._thread_local, "scanner"):
            if self._compiled_rules:
                self._thread_local.scanner = yara_x.Scanner(self._compiled_rules)
                self._thread_local.scanner.set_timeout(60)
            else:
                return None
        return self._thread_local.scanner

    def _clear_scanner(self):
        """Clear the thread-local scanner if it exists."""
        if hasattr(self._thread_local, "scanner"):
            delattr(self._thread_local, "scanner")

    def _process_disk_rules(self):
        """Load Yara rules from disk and insert into database if they don't exist."""
        try:
            disk_sources = {}
            disk_rules = {}  # Store rule name to content mapping

            # First load and parse all disk rules
            yara_file_paths = glob.glob(f"{YARA_RULES_FOLDER_PATH}**/*.yar*", recursive=True)
            for path in yara_file_paths:
                logger.info("Loading yara rules from disk", path=path)
                try:
                    with open(path) as fh:
                        rules = fh.read()
                        # Try to parse the rule to get its name
                        parsed_rules = self.parser.parse_string(rules)
                        for parsed_rule in parsed_rules:
                            rule_name = parsed_rule.get("rule_name")
                            if rule_name:
                                disk_rules[rule_name] = plyara_utils.rebuild_yara_rule(parsed_rule)
                                disk_sources[rule_name] = path
                        self.parser.clear()
                except Exception as e:
                    logger.warn("Error parsing Yara file", path=path)
                    logger.debug(f"Error parsing Yara file: {e}", path=path)
                    continue

            if disk_rules:
                # Try to compile all disk rules first to validate them
                try:
                    compiler = yara_x.Compiler()
                    for rule_name, rule_text in disk_rules.items():
                        try:
                            compiler.add_source(rule_text, origin=disk_sources[rule_name])
                        except Exception as e:
                            logger.warn("Error compiling disk rule", rule=rule_name)
                            logger.debug(f"Error compiling disk rule {rule_name} : {e}")
                    # Test compilation
                    compiler.build()
                    logger.info(f"Successfully built {len(disk_rules)} disk rules")
                except Exception as e:
                    logger.warn("Error compiling disk rules")
                    logger.debug(f"Error compiling disk rules: {e}")
                    return

                # Insert rules into database if they don't exist
                with psycopg.connect(self._conninfo) as conn:
                    for rule_name, rule_text in disk_rules.items():
                        try:
                            with conn.cursor() as cur:
                                # Try to insert the rule if it doesn't exist
                                cur.execute(
                                    """
                                    INSERT INTO yara_rules
                                        (name, content, source, enabled, alert_enabled, created_at, updated_at)
                                    VALUES
                                        (%s, %s, %s, true, true, %s, %s)
                                    ON CONFLICT (name) DO NOTHING
                                    """,
                                    (
                                        rule_name,
                                        rule_text.strip(),
                                        disk_sources[rule_name],
                                        datetime.now(UTC),
                                        datetime.now(UTC),
                                    ),
                                )
                            conn.commit()
                        except Exception as e:
                            logger.warn("Error inserting disk rule", rule=rule_name)
                            logger.debug(f"Error inserting disk rule: {e}", rule=rule_name)
                            continue

                logger.info(f"Processed {len(disk_rules)} disk rules")

        except Exception as e:
            logger.exception(e, message="Error processing disk rules")
            raise

    def get_rule_content(self, rule_name: str) -> Optional[str]:
        """
        Retrieve the content of a Yara rule by name.

        Args:
            rule_name: Name of the rule to retrieve

        Returns:
            The rule content if found, None otherwise
        """
        try:
            with psycopg.connect(self._conninfo, row_factory=dict_row) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT content
                        FROM yara_rules
                        WHERE name = %s
                        """,
                        (rule_name,),
                    )
                    result = cur.fetchone()
                    return result["content"] if result else None
        except Exception as e:
            logger.error(f"Error retrieving rule: {e}", rule=rule_name)
            return None

    def load_rules(self):
        """Load all enabled rules from database and compile them."""
        try:
            # Create a new compiler instance
            self._compiler = yara_x.Compiler()
            valid_rules = 0

            with psycopg.connect(self._conninfo, row_factory=dict_row) as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT name, content, source
                        FROM yara_rules
                        WHERE enabled = true
                        ORDER BY name
                    """)
                    rules = cur.fetchall()

            logger.info(f"Loading {len(rules)} yara rules from the database")

            # Try to add each rule to the compiler
            for rule in rules:
                try:
                    # Test compile the individual rule first
                    test_compiler = yara_x.Compiler()
                    test_compiler.add_source(rule["content"], origin=rule.get("source", "database"))
                    test_compiler.build()

                    # If test compilation succeeds, add to main compiler
                    self._compiler.add_source(rule["content"], origin=rule.get("source", "database"))
                    valid_rules += 1
                except Exception as e:
                    logger.warn(f"Error compiling database Yara rule '{rule['name']}': {e}")
                    logger.debug("Error compiling database rule", rule=rule["name"])
                    continue

            logger.info(f"{valid_rules} valid yara rules compiled from the database")

            if valid_rules > 0:
                try:
                    # Compile all valid rules together
                    self._compiled_rules = self._compiler.build()
                    # Clear any existing thread-local scanners
                    self._clear_scanner()
                    logger.info(f"Successfully compiled {valid_rules} database rules")
                except Exception as e:
                    logger.error(f"Error in final compilation of database rules: {e}")
                    self._compiled_rules = None
                    self._clear_scanner()
            else:
                logger.warning("No valid rules to compile")
                self._compiled_rules = None
                self._clear_scanner()

        except Exception as e:
            logger.exception(e, message="Error loading rules from database")
            raise

    def match(self, target) -> list[yara_x.Match]:
        """
        Performs Yara matching on the given target.
        Target can be either a file path string or raw data.
        """
        scanner = self._get_scanner()
        if not scanner:
            logger.warning("No Yara rules compiled")
            return []
        try:
            # Check if target is a string that could be a file path
            if isinstance(target, str) and os.path.isfile(target):
                return list(scanner.scan_file(target).matching_rules)
            else:
                # Treat as raw data
                if isinstance(target, str):
                    target = target.encode()
                return list(scanner.scan(target).matching_rules)
        except Exception as e:
            logger.error(f"Error during Yara scanning: {e}")
            return []

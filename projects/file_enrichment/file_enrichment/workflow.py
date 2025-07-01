# src/workflow/workflow.py
import io
import json
import ntpath
import os
import pathlib
from datetime import datetime
from typing import BinaryIO

import common.helpers as helpers
import dapr.ext.workflow as wf
import magic
import psycopg
import structlog
from common.helpers import is_container
from common.models import Alert, EnrichmentResult, File, NoseyParkerInput
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from dapr.clients import DaprClient
from dapr.ext.workflow.logger.options import LoggerOptions
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext
from file_enrichment_modules.module_loader import ModuleLoader

from .file_feature_extractor import FileFeatureExtractor
from .logger import configure_logging

logger = structlog.get_logger(module=__name__)

log_handler, log_formatter = configure_logging()
workflow_runtime_log_level = os.getenv("WORKFLOW_RUNTIME_LOG_LEVEL", "WARNING")
workflow_client_log_level = os.getenv("WORKFLOW_CLIENT_LOG_LEVEL", "WARNING")

workflow_runtime = wf.WorkflowRuntime(
    logger_options=LoggerOptions(
        log_level=workflow_runtime_log_level,
        log_handler=log_handler,
        log_formatter=log_formatter,
    )
)


workflow_client: wf.DaprWorkflowClient = None
activity_functions = {}
download_path = "/tmp/"
storage = StorageMinio()

dapr_port = os.getenv("DAPR_HTTP_PORT", 3500)
gotenberg_url = f"http://localhost:{dapr_port}/v1.0/invoke/gotenberg/method/forms/libreoffice/convert"
max_parallel_enrichment_modules = int(
    os.getenv("MAX_PARALLEL_ENRICHMENT_MODULES", 5)
)  # maximum workflows that can run at a time
container_nesting_limit = 2

logger.info(f"max_parallel_enrichment_modules: {max_parallel_enrichment_modules}")
nemesis_url = os.getenv("NEMESIS_URL", "http://localhost/")
nemesis_url = f"{nemesis_url}/" if not nemesis_url.endswith("/") else nemesis_url


with DaprClient() as client:
    secret = client.get_secret(store_name="nemesis-secret-store", key="POSTGRES_CONNECTION_STRING")
    postgres_connection_string = secret.secret["POSTGRES_CONNECTION_STRING"]


##########################################
#
# region Helper functions
#
##########################################


def create_enrichment_activity(module_name: str):
    """Creates a unique activity function for each module"""
    global activity_functions
    activity_name = f"enrich_{module_name}"

    @workflow_runtime.activity(name=activity_name)
    def activity_function(ctx, input_data: dict):
        logger.debug("Starting enrichment activity", module_name=module_name)
        object_id = input_data["object_id"]
        result = None

        try:
            if module_name not in workflow_runtime.modules:
                raise KeyError(f"Module {module_name} not found in workflow_runtime.modules")

            module = workflow_runtime.modules[module_name]

            # check if we should process with this module
            should_process = module.should_process(object_id)

            if not should_process:
                logger.debug("Module decided to skip processing", module_name=module_name)
                return None

            result: EnrichmentResult = module.process(object_id)
            if result:
                # Store enrichment result directly in database
                with psycopg.connect(postgres_connection_string) as conn:
                    with conn.cursor() as cur:
                        # escape any \x0000 characters/etc. and then dump to a form we can index
                        results_escaped = json.dumps(helpers.sanitize_for_jsonb(result.model_dump(mode="json")))

                        # Store enrichment
                        cur.execute(
                            """
                            INSERT INTO enrichments (object_id, module_name, result_data)
                            VALUES (%s, %s, %s)
                        """,
                            (object_id, module_name, results_escaped),
                        )

                        # Store any transforms
                        if result.transforms:
                            for transform in result.transforms:
                                cur.execute(
                                    """
                                    INSERT INTO transforms (object_id, type, transform_object_id, metadata)
                                    VALUES (%s, %s, %s, %s)
                                """,
                                    (
                                        object_id,
                                        transform.type,
                                        transform.object_id,
                                        json.dumps(transform.metadata) if transform.metadata else None,
                                    ),
                                )

                        # Store any findings
                        if result.findings:
                            for finding in result.findings:
                                cur.execute(
                                    """
                                    INSERT INTO findings (
                                        finding_name, category, severity, object_id,
                                        origin_type, origin_name, raw_data, data
                                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                                """,
                                    (
                                        finding.finding_name,
                                        finding.category,
                                        finding.severity,
                                        object_id,
                                        finding.origin_type,
                                        finding.origin_name,
                                        json.dumps(finding.raw_data),
                                        json.dumps([obj.model_dump_json() for obj in finding.data]),
                                    ),
                                )

                        # Update workflow in database with successful module
                        logger.debug(f"Enrichment success: {module_name}")
                        cur.execute(
                            """
                            UPDATE workflows
                            SET enrichments_success = array_append(enrichments_success, %s)
                            WHERE object_id = %s
                            """,
                            (module_name, object_id),
                        )

                    conn.commit()

                # Return minimal result to indicate success
                return {"status": "success", "module": module_name}

        except Exception as e:
            logger.exception(
                e,
                message="Error in enrichment module",
                module_name=module_name,
                object_id=object_id,
                result=result if result else None,
                exc_info=True,
            )

            # Update workflow in database with failed module
            try:
                with psycopg.connect(postgres_connection_string) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE workflows
                            SET enrichments_failure = array_append(enrichments_failure, %s)
                            WHERE object_id = %s
                            """,
                            (f"{module_name}:{str(e)[:100]}", object_id),
                        )
                        conn.commit()
            except Exception as db_error:
                logger.error(f"Failed to update workflow failure in database: {str(db_error)}")

            raise

    activity_functions[activity_name] = activity_function
    return activity_name


def build_dependency_graph(modules):
    """Build a dependency grap for enrichment modules and check for circular dependencies"""
    graph = {name: set() for name in modules.keys()}

    for name, module in modules.items():
        if hasattr(module, "dependencies"):
            for dep in module.dependencies:
                if dep not in modules:
                    raise ValueError(f"Module {name} has unknown dependency: {dep}")
                graph[name].add(dep)

    return graph


def topological_sort(graph):
    """Perform topological sort on the dependency graph"""
    visited = set()
    temp_visited = set()
    order = []

    def visit(node):
        if node in temp_visited:
            raise ValueError(f"Circular dependency detected involving module: {node}")
        if node not in visited:
            temp_visited.add(node)
            for dep in graph[node]:
                visit(dep)
            temp_visited.remove(node)
            visited.add(node)
            order.append(node)

    for node in graph:
        if node not in visited:
            visit(node)

    return order


# endregion

##########################################
#
# region Postgres state
#
##########################################


@workflow_runtime.activity
def index_file_message(ctx: WorkflowActivityContext, activity_input: dict):
    """Store the file message in PostgreSQL for later replay. Only indexes non-nested files."""
    try:
        file = File.model_validate(activity_input)

        # we don't want to index files that were extracted from existing files that we've already processed
        if file.nesting_level and file.nesting_level > 0:
            logger.debug(
                "nesting_level > 0, not indexing `file` message",
                nesting_level=file.nesting_level,
                object_id=file.object_id,
            )
            return

        with psycopg.connect(postgres_connection_string) as conn:
            with conn.cursor() as cur:
                query = """
                INSERT INTO files (
                    object_id, agent_id, project, timestamp, expiration,
                    path, originating_object_id, nesting_level,
                    file_creation_time, file_access_time, file_modification_time
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                ) ON CONFLICT (object_id) DO UPDATE SET
                    agent_id = EXCLUDED.agent_id,
                    project = EXCLUDED.project,
                    timestamp = EXCLUDED.timestamp,
                    expiration = EXCLUDED.expiration,
                    path = EXCLUDED.path,
                    originating_object_id = EXCLUDED.originating_object_id,
                    nesting_level = EXCLUDED.nesting_level,
                    file_creation_time = EXCLUDED.file_creation_time,
                    file_access_time = EXCLUDED.file_access_time,
                    file_modification_time = EXCLUDED.file_modification_time,
                    updated_at = CURRENT_TIMESTAMP;
                """

                cur.execute(
                    query,
                    (
                        file.object_id,
                        file.agent_id,
                        file.project,
                        file.timestamp,
                        file.expiration,
                        file.path,
                        file.originating_object_id,
                        file.nesting_level,
                        datetime.fromisoformat(file.creation_time) if file.creation_time else None,
                        datetime.fromisoformat(file.access_time) if file.access_time else None,
                        datetime.fromisoformat(file.modification_time) if file.modification_time else None,
                    ),
                )
                conn.commit()

        logger.info("Successfully stored file data in PostgreSQL", object_id=file.object_id)
        return {}

    except Exception as e:
        logger.exception(e, message="Error indexing file message")
        raise


@workflow_runtime.activity
def store_file_enriched(ctx, file_enriched):
    """Store the file_enriched data in PostgreSQL."""
    try:
        with psycopg.connect(postgres_connection_string) as conn:
            with conn.cursor() as cur:
                # Convert field names to match database schema
                insert_query = """
                    INSERT INTO files_enriched (
                        object_id, agent_id, project, timestamp, expiration, path,
                        file_name, extension, size, magic_type, mime_type,
                        is_plaintext, is_container, originating_object_id,
                        nesting_level, file_creation_time, file_access_time,
                        file_modification_time, security_info, hashes
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s
                    )
                    ON CONFLICT (object_id) DO UPDATE SET
                        agent_id = EXCLUDED.agent_id,
                        project = EXCLUDED.project,
                        timestamp = EXCLUDED.timestamp,
                        expiration = EXCLUDED.expiration,
                        path = EXCLUDED.path,
                        file_name = EXCLUDED.file_name,
                        extension = EXCLUDED.extension,
                        size = EXCLUDED.size,
                        magic_type = EXCLUDED.magic_type,
                        mime_type = EXCLUDED.mime_type,
                        is_plaintext = EXCLUDED.is_plaintext,
                        is_container = EXCLUDED.is_container,
                        originating_object_id = EXCLUDED.originating_object_id,
                        nesting_level = EXCLUDED.nesting_level,
                        file_creation_time = EXCLUDED.file_creation_time,
                        file_access_time = EXCLUDED.file_access_time,
                        file_modification_time = EXCLUDED.file_modification_time,
                        security_info = EXCLUDED.security_info,
                        hashes = EXCLUDED.hashes,
                        updated_at = CURRENT_TIMESTAMP
                """

                # Extract filename from path if it exists
                file_name = os.path.basename(file_enriched.get("path", "")) if file_enriched.get("path") else None

                cur.execute(
                    insert_query,
                    (
                        file_enriched["object_id"],
                        file_enriched.get("agent_id"),
                        file_enriched.get("project"),
                        file_enriched.get("timestamp"),
                        file_enriched.get("expiration"),
                        file_enriched.get("path"),
                        file_name,
                        file_enriched.get("extension"),
                        file_enriched.get("size"),
                        file_enriched.get("magic_type"),
                        file_enriched.get("mime_type"),
                        file_enriched.get("is_plaintext"),
                        file_enriched.get("is_container"),
                        file_enriched.get("originating_object_id"),
                        file_enriched.get("nesting_level"),
                        file_enriched.get("file_creation_time"),
                        file_enriched.get("file_access_time"),
                        file_enriched.get("file_modification_time"),
                        json.dumps(file_enriched.get("security_info")) if file_enriched.get("security_info") else None,
                        json.dumps(file_enriched.get("hashes")) if file_enriched.get("hashes") else None,
                    ),
                )
                conn.commit()
                logger.info("Stored file_enriched in PostgreSQL", object_id=file_enriched["object_id"])
    except Exception as e:
        logger.exception(e, message="Error storing file_enriched in PostgreSQL", file_enriched=file_enriched)
        raise


def index_plaintext_content(object_id: str, file_obj: io.TextIOWrapper, max_chunk_bytes: int = 800000):
    """Used to index plaintext content with byte-based chunking to avoid tsvector limits"""
    logger.info(f"indexing plaintext for {object_id}")

    with psycopg.connect(postgres_connection_string) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM plaintext_content WHERE object_id = %s", (object_id,))

            chunk_number = 0
            insert_query = """
            INSERT INTO plaintext_content (object_id, chunk_number, content)
            VALUES (%s, %s, %s);
            """

            # Read file content
            file_content = file_obj.read()

            # Process in chunks, ensuring we don't exceed byte limits
            i = 0
            while i < len(file_content):
                # Take a chunk that's guaranteed to be under the byte limit
                chunk_end = min(i + max_chunk_bytes // 4, len(file_content))  # Div by 4 for worst-case UTF-8
                chunk_content = file_content[i:chunk_end]

                # If chunk is still too big in bytes, trim it down
                while len(chunk_content.encode("utf-8")) > max_chunk_bytes and chunk_content:
                    chunk_content = chunk_content[:-100]  # Remove 100 chars at a time

                if chunk_content:  # Only insert non-empty chunks
                    actual_bytes = len(chunk_content.encode("utf-8"))
                    logger.debug(f"Inserting chunk {chunk_number} with {actual_bytes} bytes")
                    cur.execute(insert_query, (object_id, chunk_number, chunk_content))
                    chunk_number += 1

                # Move to next chunk
                i = chunk_end

            conn.commit()

        logger.debug("Indexed chunked content", object_id=object_id, num_chunks=chunk_number)


# endregion

##########################################
#
# region Dapr activities
#
##########################################


def get_file_extension(filepath):
    # Get just the final filename component of the path
    base_name = ntpath.basename(filepath)

    # Split on the last dot, but only if the dot isn't the first character
    if base_name.startswith(".") or "." not in base_name:
        return ""

    name_parts = base_name.split(".")
    if len(name_parts) > 1:
        return "." + name_parts[-1]
    return ""


@workflow_runtime.activity
def get_basic_analysis(ctx, activity_input):
    """Perform 'basic' analysis on a file. Run for every file."""

    object_id = activity_input["object_id"]
    path = activity_input.get("path", "")

    # download from Minio as a temporary file which will be cleaned up on exit
    with storage.download(object_id) as file:
        mime_type = magic.from_file(file.name, mime=True)
        if mime_type == "text/plain" or helpers.is_text_file(file.name):
            is_plaintext = True
        else:
            is_plaintext = False
        basic_analysis = {
            "file_name": ntpath.basename(path),
            "extension": get_file_extension(path),
            "size": pathlib.Path(file.name).stat().st_size,
            "hashes": {
                "md5": helpers.calculate_file_hash(file.name, "md5"),
                "sha1": helpers.calculate_file_hash(file.name, "sha1"),
                "sha256": helpers.calculate_file_hash(file.name, "sha256"),
            },
            "magic_type": magic.from_file(file.name),
            "mime_type": mime_type,
            "is_plaintext": is_plaintext,
            "is_container": is_container(mime_type),
        }

        return basic_analysis


@workflow_runtime.activity
def extract_and_store_features(ctx, activity_input):
    """Extract features from a file and store them in PostgreSQL."""
    try:
        logger.info("Starting feature extraction")
        object_id = activity_input["object_id"]
        file_enriched = get_file_enriched(object_id)

        # we only want to process things that were submitted and not things extracted/post-processed
        #   so things that don't have an originating_object_id
        if not file_enriched.originating_object_id:
            # Initialize feature extractor
            extractor = FileFeatureExtractor()

            # Default timestamp for missing values (Unix epoch)
            DEFAULT_TIMESTAMP = datetime(1970, 1, 1, 0, 0, 0, tzinfo=datetime.now().astimezone().tzinfo)

            # Use file timestamps from file_enriched, using epoch if not available
            creation_time = file_enriched.creation_time if file_enriched.creation_time else DEFAULT_TIMESTAMP
            modification_time = (
                file_enriched.modification_time if file_enriched.modification_time else DEFAULT_TIMESTAMP
            )
            access_time = file_enriched.access_time if file_enriched.access_time else DEFAULT_TIMESTAMP

            # Extract features
            features = extractor.extract_indivdiual_features(
                filepath=file_enriched.path,
                size=file_enriched.size,
                created_time=creation_time,
                modified_time=modification_time,
                accessed_time=access_time,
            )

            # Extract version and remove from features dict
            features_version = features.pop("_features_version")

            # Create labels dictionary
            labels = {
                "has_finding": False,
                "has_credential": False,
                "has_dotnet_vulns": False,
                "has_pii": False,
                "has_yara_match": False,
                "viewed": False,
            }

            # Fetch findings from database and update labels
            with psycopg.connect(postgres_connection_string) as conn:
                with conn.cursor() as cur:
                    # First get the findings
                    cur.execute(
                        """
                        SELECT category, finding_name
                        FROM findings
                        WHERE object_id = %s
                    """,
                        (file_enriched.object_id,),
                    )

                    findings = cur.fetchall()

                    if findings:
                        labels["has_finding"] = True
                        for category, finding_name in findings:
                            if category == "credential":
                                labels["has_credential"] = True
                            elif category == "vulnerability" and finding_name == "dotnet_vulns":
                                labels["has_dotnet_vulns"] = True
                            elif category == "pii":
                                labels["has_pii"] = True
                            elif category == "yara_match":
                                labels["has_yara_match"] = True

                    # Parse timestamps to datetime objects if they're strings
                    def parse_timestamp(ts):
                        if isinstance(ts, str):
                            return datetime.fromisoformat(ts)
                        return ts

                    # Now insert into files_enriched_dataset
                    query = """
                    INSERT INTO files_enriched_dataset (
                        object_id, agent_id, project, timestamp, expiration,
                        path, file_creation_time, file_access_time, file_modification_time,
                        features_version, individual_features, labels
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    ) ON CONFLICT (object_id) DO UPDATE SET
                        agent_id = EXCLUDED.agent_id,
                        project = EXCLUDED.project,
                        timestamp = EXCLUDED.timestamp,
                        expiration = EXCLUDED.expiration,
                        path = EXCLUDED.path,
                        file_creation_time = EXCLUDED.file_creation_time,
                        file_access_time = EXCLUDED.file_access_time,
                        file_modification_time = EXCLUDED.file_modification_time,
                        features_version = EXCLUDED.features_version,
                        individual_features = EXCLUDED.individual_features,
                        labels = EXCLUDED.labels;
                    """

                    cur.execute(
                        query,
                        [
                            file_enriched.object_id,
                            file_enriched.agent_id,
                            file_enriched.project,
                            parse_timestamp(file_enriched.timestamp),
                            parse_timestamp(file_enriched.expiration) if file_enriched.expiration else None,
                            file_enriched.path,
                            creation_time,
                            access_time,
                            modification_time,
                            features_version,
                            json.dumps(features),
                            json.dumps(labels),
                        ],
                    )
                    conn.commit()

            logger.info("Successfully stored file features in dataset", object_id=file_enriched.object_id)

    except Exception as e:
        logger.exception(e, message="Error extracting and storing features", activity_input=activity_input)
        raise


@workflow_runtime.activity
def publish_findings_alerts(ctx, activity_input):
    """
    Activity to publish enriched file data to pubsub after retrieving from state store.
    """
    object_id = activity_input["object_id"]
    file_enriched = get_file_enriched(object_id)

    # Fetch findings from the database for this object_id
    with psycopg.connect(postgres_connection_string) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT finding_name, category, severity, origin_name, raw_data
                FROM findings
                WHERE object_id = %s
            """,
                (object_id,),
            )

            findings = cur.fetchall()

            if findings:
                with DaprClient() as client:
                    if file_enriched.path:
                        file_path = helpers.sanitize_file_path(file_enriched.path)
                    else:
                        file_path = "UNKNOWN"

                    for finding in findings:
                        finding_name, category, severity, origin_name, raw_data = finding

                        finding_message = f"- *Category:* {category} / *Severity:* {severity}\n"
                        file_message = f"- *File Path:* {file_path}\n"
                        nemesis_finding_url = f"{nemesis_url}findings?object_id={file_enriched.object_id}"
                        nemesis_file_url = f"{nemesis_url}files?object_id={file_enriched.object_id}"
                        nemesis_footer_finding = f"*<{nemesis_finding_url}|View Finding in Nemesis>* / "
                        nemesis_footer_file = f"*<{nemesis_file_url}|View File in Nemesis>*\n"
                        separator = "⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯"

                        rule_message = ""
                        try:
                            if finding_name == "noseyparker_match" and raw_data:
                                if "match" in raw_data and "rule_name" in raw_data["match"]:
                                    rule_name = raw_data["match"]["rule_name"]
                                    rule_message = f"- *Rule name:* {rule_name}\n"
                        except (json.JSONDecodeError, KeyError) as e:
                            logger.warning("Error processing raw_data for noseyparker_match", error=str(e))

                        body = f"{finding_message}{rule_message}{file_message}{nemesis_footer_finding}{nemesis_footer_file}{separator}"

                        alert = Alert(title=finding_name, body=body, service=origin_name)
                        client.publish_event(
                            pubsub_name="pubsub",
                            topic_name="alert",
                            data=json.dumps(alert.model_dump(exclude_unset=True)),
                            data_content_type="application/json",
                        )
                        logger.debug("Published alert", alert=alert)


@workflow_runtime.activity
def handle_file_if_plaintext(ctx, activity_input):
    """
    Activity to index a file's contents if it's plaintext and
    send a pub/sub message to NoseyParker
    """
    object_id = activity_input["object_id"]
    file_enriched = get_file_enriched(object_id)

    # if the file is plaintext, make sure we index it
    if file_enriched.is_plaintext:
        with storage.download(object_id) as tmp_file:
            with open(tmp_file.name, "rb") as binary_file:
                with create_text_reader(binary_file) as text_file:
                    index_plaintext_content(f"{object_id}", text_file)

    nosey_parker_input = NoseyParkerInput(object_id=object_id)
    with DaprClient() as client:
        client.publish_event(
            pubsub_name="pubsub",
            topic_name="noseyparker-input",
            data=json.dumps(nosey_parker_input.model_dump()),
            data_content_type="application/json",
        )
    logger.debug(f"Published noseyparker_input: {object_id}")


@workflow_runtime.activity
def publish_enriched_file(ctx, activity_input):
    """
    Activity to publish enriched file data to pubsub after retrieving from state store.
    """
    object_id = activity_input["object_id"]
    file_enriched = get_file_enriched(object_id)

    try:
        with DaprClient() as client:
            data = file_enriched.model_dump(
                exclude_unset=True,
                mode="json",
            )

            # Publish to pubsub
            client.publish_event(
                pubsub_name="pubsub",
                topic_name="file_enriched",
                data=json.dumps(data),
                data_content_type="application/json",
            )

            return True

    except Exception as e:
        logger.exception(e, message="Error publishing enriched file data", object_id=object_id)
        # Don't raise to ensure workflow can complete
        return False


def create_text_reader(binary_file: BinaryIO) -> io.TextIOWrapper:
    """Creates a text reader that handles BOMs and mixed content"""

    bom_check = binary_file.read(4)
    binary_file.seek(0)  # Reset to start

    if bom_check.startswith(b"\xff\xfe"):
        return io.TextIOWrapper(binary_file, encoding="utf-16le")
    elif bom_check.startswith(b"\xfe\xff"):
        return io.TextIOWrapper(binary_file, encoding="utf-16be")
    elif bom_check.startswith(b"\xef\xbb\xbf"):
        return io.TextIOWrapper(binary_file, encoding="utf-8-sig")
    else:
        return io.TextIOWrapper(binary_file, encoding="utf-8", errors="replace")


# endregion

##########################################
#
# region Dapr workflows
#
##########################################


@workflow_runtime.workflow
def enrichment_module_workflow(ctx: wf.DaprWorkflowContext, workflow_input: dict):
    """Child workflow that runs enrichment modules with a rolling window of parallel tasks."""

    object_id = workflow_input["file"]["object_id"]
    execution_order = workflow_input["execution_order"]

    try:
        logger.info("Module execution order", execution_order=execution_order, instance_id=ctx.instance_id)

        # Track all results
        results = []
        # Track in-flight tasks with their module names
        in_flight_tasks = {}  # task -> module_name mapping

        # execution_order = ["filename"] # for testing a single specific module

        # Process modules with rolling window
        for module_name in execution_order:
            activity_name = f"enrich_{module_name}"
            if activity_name not in activity_functions:
                raise KeyError(f"Activity {activity_name} not registered")

            # If we've hit max parallelism, wait for any task to complete
            if len(in_flight_tasks) >= max_parallel_enrichment_modules:
                # Use when_any to get the first completed task
                completed_task = yield wf.when_any(list(in_flight_tasks.keys()))
                completed_module = in_flight_tasks[completed_task]

                try:
                    result = completed_task.get_result()
                    logger.debug("Module completed", module_name=completed_module, result=result)
                    results.append((completed_module, result))
                    logger.debug(f"Module COMPLETED: {completed_module}")
                except Exception as e:
                    logger.exception(e, message="Error in module execution", module_name=completed_module)
                    # Continue with other modules even if one fails
                    results.append((completed_module, None))
                    logger.error(f"Module ERROR: {completed_module}")

                # Remove completed task from in_flight
                del in_flight_tasks[completed_task]

            # Start new task
            task = ctx.call_activity(activity_functions[activity_name], input={"object_id": object_id})
            in_flight_tasks[task] = module_name
            logger.debug("Started task for module", module_name=module_name)

        # Wait for remaining tasks to complete
        while in_flight_tasks:
            completed_task = yield wf.when_any(list(in_flight_tasks.keys()))
            completed_module = in_flight_tasks[completed_task]

            try:
                result = completed_task.get_result()
                logger.debug("Module completed", module_name=completed_module, result=result)
                results.append((completed_module, result))
                logger.debug(f"Module COMPLETED: {completed_module}")
            except Exception as e:
                logger.exception(e, message="Error in module execution", module_name=completed_module)
                results.append((completed_module, None))
                logger.warning(f"Module ERROR: {completed_module}")

            del in_flight_tasks[completed_task]

        logger.info("All modules completed", total_modules=len(results), results=results)

        return results

    except Exception as e:
        logger.error(f"Error in workflow execution: {str(e)}")
        raise


@workflow_runtime.workflow
def enrichment_workflow(ctx: wf.DaprWorkflowContext, workflow_input: dict):
    """Main workflow that orchestrates all enrichment activities."""

    logger.info("Starting main enrichment workflow")

    try:
        input_file = workflow_input["file"]
        object_id = input_file["object_id"]  # the only guaranteed field to exist

        logger.debug("Workflow input", object_id=object_id, workflow_input=workflow_input, instance_id=ctx.instance_id)

        initial_tasks = [
            ctx.call_activity(index_file_message, input=input_file),
            ctx.call_activity(get_basic_analysis, input=input_file),
        ]

        try:
            initial_tasks_results = yield wf.when_all(initial_tasks)
            basic_analysis = initial_tasks_results[1]
            logger.debug("Initial tasks complete - index_file_message, get_basic_analysis")
        except Exception as e:
            logger.exception("Error in index_file_message or get_basic_analysis", error=str(e))
            raise

        # create file_enriched object
        file_enriched = {
            **input_file,
            **basic_analysis,
        }

        # store the basic file analysis into the file_enriched object in Postgres
        try:
            yield ctx.call_activity(store_file_enriched, input=file_enriched)
            logger.debug("Stored file_enriched in PostgreSQL")
        except Exception:
            logger.exception(
                "Error in initial tasks - calling store_file_enriched_postgres", store_file_enriched=store_file_enriched
            )
            raise

        enrichment_tasks = [
            ctx.call_activity(handle_file_if_plaintext, input=file_enriched),
            ctx.call_child_workflow(workflow=enrichment_module_workflow, input=workflow_input),
        ]

        try:
            yield wf.when_all(enrichment_tasks)
            logger.debug("Enrichment tasks complete - handle_file_if_plaintext, enrichment_module_workflow")
        except Exception as e:
            logger.exception(
                "Error in enrichment tasks - handle_file_if_plaintext or enrichment_module_workflow", error=str(e)
            )
            raise

        final_tasks = [
            ctx.call_activity(publish_enriched_file, input={"object_id": object_id}),
            ctx.call_activity(extract_and_store_features, input={"object_id": object_id}),
            ctx.call_activity(publish_findings_alerts, input={"object_id": object_id}),
        ]

        try:
            yield wf.when_all(final_tasks)
            logger.debug(
                "Final tasks complete - publish_enriched_file, extract_and_store_features, publish_findings_alerts"
            )
        except Exception as e:
            logger.exception(
                "Error in final tasks - publish_enriched_file, extract_and_store_features, publish_findings_alerts",
                error=str(e),
            )
            raise

        logger.info("Workflow completed successfully", object_id=object_id)
        return {}

    except Exception:
        logger.exception("Error in main workflow execution", workflow_input=workflow_input)
        raise


# endregion

##########################################
#
# region: Management functions
#
##########################################


async def initialize_workflow_runtime():
    """Initialize the workflow runtime and load modules. Returns the execution order for modules."""
    global workflow_runtime, workflow_client

    # Load enrichment modules
    module_loader = ModuleLoader()
    await module_loader.load_modules()
    workflow_runtime.modules = module_loader.modules

    # Filter modules by workflow and determine execution order
    workflow_name = "default"  # This could be made configurable later
    available_modules = {
        name: module
        for name, module in workflow_runtime.modules.items()
        if hasattr(module, "workflows") and workflow_name in module.workflows
    }

    # Build dependency graph from filtered modules
    graph = build_dependency_graph(available_modules)
    execution_order = topological_sort(graph)
    logger.info(
        "Determined module execution order",
        execution_order=execution_order,
        workflow=workflow_name,
        total_modules=len(available_modules),
        filtered_from=len(workflow_runtime.modules),
    )

    # Register each module as an activity
    for module_name in available_modules.keys():
        activity_name = create_enrichment_activity(module_name)
        logger.info("Registered activity", activity_name=activity_name)

    # Start workflow runtime
    workflow_runtime.start()

    # Initialize workflow client
    workflow_client = wf.DaprWorkflowClient(
        logger_options=LoggerOptions(
            log_level=workflow_client_log_level,
            log_handler=log_handler,
            log_formatter=log_formatter,
        )
    )

    return execution_order


def shutdown_workflow_runtime():
    """Shutdown the workflow runtime"""
    if workflow_runtime:
        workflow_runtime.shutdown()


def get_workflow_client() -> wf.DaprWorkflowClient:
    """Get the workflow client instance"""
    return workflow_client


def reload_yara_rules():
    """Reloads all disk/state yara rules."""
    logger.debug("workflow/workflow.py reloading Yara rules")
    workflow_runtime.modules["yara"].rule_manager.load_rules()


# endregion

# src/workflow/workflow.py
import asyncio
import io
import json
import os
import pathlib
import posixpath
from datetime import datetime

import asyncpg
import common.helpers as helpers
import dapr.ext.workflow as wf
import magic
from common.db import get_postgres_connection_str
from common.helpers import create_text_reader, get_file_extension, is_container
from common.logger import WORKFLOW_CLIENT_LOG_LEVEL, get_logger
from common.models import Alert, EnrichmentResult, NoseyParkerInput
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from common.workflows.setup import wf_runtime, workflow_activity
from dapr.clients import DaprClient
from dapr.ext.workflow.logger.options import LoggerOptions
from file_enrichment_modules.module_loader import EnrichmentModule, ModuleLoader
from file_linking import FileLinkingEngine
from nemesis_dpapi import DpapiManager

logger = get_logger(__name__)

workflow_client = wf.DaprWorkflowClient(
    logger_options=LoggerOptions(
        log_level=WORKFLOW_CLIENT_LOG_LEVEL,
    )
)
activity_functions = {}
download_path = "/tmp/"
storage = StorageMinio()
global_module_map: dict[str, EnrichmentModule] = {}  # Enrichment modules loaded at initialization

dapr_port = os.getenv("DAPR_HTTP_PORT", 3500)
gotenberg_url = f"http://localhost:{dapr_port}/v1.0/invoke/gotenberg/method/forms/libreoffice/convert"

nemesis_url = os.getenv("NEMESIS_URL", "http://localhost/")
nemesis_url = f"{nemesis_url}/" if not nemesis_url.endswith("/") else nemesis_url

postgres_pool: asyncpg.Pool = None  # Connection pool for database operations

file_linking_engine = FileLinkingEngine(get_postgres_connection_str())
asyncio_loop: asyncio.AbstractEventLoop = None

##########################################
#
# region Helper functions
#
##########################################


def parse_timestamp(ts):
    """Parse a timestamp string or return the datetime object as-is."""
    if isinstance(ts, str):
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return ts


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


async def index_plaintext_content(object_id: str, file_obj: io.TextIOWrapper, max_chunk_bytes: int = 800000):
    """Used to index plaintext content with byte-based chunking to avoid tsvector limits"""
    logger.debug(f"indexing plaintext for {object_id}")

    async with postgres_pool.acquire() as conn:
        await conn.execute("DELETE FROM plaintext_content WHERE object_id = $1", object_id)

        chunk_number = 0
        insert_query = """
        INSERT INTO plaintext_content (object_id, chunk_number, content)
        VALUES ($1, $2, $3);
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
                await conn.execute(insert_query, object_id, chunk_number, chunk_content)
                chunk_number += 1

            # Move to next chunk
            i = chunk_end

        logger.debug("Indexed chunked content", object_id=object_id, num_chunks=chunk_number)


# endregion

##########################################
#
# region Dapr activities
#
##########################################


@workflow_activity
async def get_basic_analysis(ctx, activity_input):
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
            "file_name": posixpath.basename(path),
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

        file_enriched = {
            **activity_input,
            **basic_analysis,
        }

        try:
            async with postgres_pool.acquire() as conn:
                # Convert field names to match database schema
                insert_query = """
                    INSERT INTO files_enriched (
                        object_id, agent_id, source, project, timestamp, expiration, path,
                        file_name, extension, size, magic_type, mime_type,
                        is_plaintext, is_container, originating_object_id, originating_container_id,
                        nesting_level, file_creation_time, file_access_time,
                        file_modification_time, security_info, hashes
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
                        $17, $18, $19, $20, $21, $22
                    )
                    ON CONFLICT (object_id) DO UPDATE SET
                        agent_id = EXCLUDED.agent_id,
                        source = EXCLUDED.source,
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
                        originating_container_id = EXCLUDED.originating_container_id,
                        nesting_level = EXCLUDED.nesting_level,
                        file_creation_time = EXCLUDED.file_creation_time,
                        file_access_time = EXCLUDED.file_access_time,
                        file_modification_time = EXCLUDED.file_modification_time,
                        security_info = EXCLUDED.security_info,
                        hashes = EXCLUDED.hashes,
                        updated_at = CURRENT_TIMESTAMP
                """

                await conn.execute(
                    insert_query,
                    file_enriched["object_id"],
                    file_enriched.get("agent_id"),
                    file_enriched.get("source"),
                    file_enriched.get("project"),
                    parse_timestamp(file_enriched.get("timestamp")),
                    parse_timestamp(file_enriched.get("expiration")),
                    file_enriched.get("path"),
                    file_enriched.get("file_name"),
                    file_enriched.get("extension"),
                    file_enriched.get("size"),
                    file_enriched.get("magic_type"),
                    file_enriched.get("mime_type"),
                    file_enriched.get("is_plaintext"),
                    file_enriched.get("is_container"),
                    file_enriched.get("originating_object_id"),
                    file_enriched.get("originating_container_id"),
                    file_enriched.get("nesting_level"),
                    parse_timestamp(file_enriched.get("file_creation_time")),
                    parse_timestamp(file_enriched.get("file_access_time")),
                    parse_timestamp(file_enriched.get("file_modification_time")),
                    json.dumps(file_enriched.get("security_info")) if file_enriched.get("security_info") else None,
                    json.dumps(file_enriched.get("hashes")) if file_enriched.get("hashes") else None,
                )
                logger.debug("Stored file_enriched in PostgreSQL", object_id=file_enriched["object_id"])
        except Exception as e:
            logger.exception(e, message="Error storing file_enriched in PostgreSQL", file_enriched=file_enriched)
            raise

        return file_enriched


@workflow_activity
async def check_file_linkings(ctx, activity_input):
    """
    Check for file linkings using the rules engine and update database tables.
    """

    object_id = activity_input["object_id"]
    file_enriched = await get_file_enriched_async(object_id)

    try:
        global file_linking_engine
        linkings_created = await file_linking_engine.apply_linking_rules(file_enriched)

        logger.debug("File linking check complete", object_id=object_id, linkings_created=linkings_created)

        return {"linkings_created": linkings_created}

    except Exception as e:
        logger.exception("Error in file linking check", object_id=object_id, error=str(e))
        # Don't raise to ensure workflow can complete
        return {"linkings_created": 0, "error": str(e)}


@workflow_activity
async def publish_findings_alerts(ctx, activity_input):
    """
    Activity to publish enriched file data to pubsub after retrieving from state store.
    """
    object_id = activity_input["object_id"]
    file_enriched = await get_file_enriched_async(object_id)

    # Fetch findings from the database for this object_id
    async with postgres_pool.acquire() as conn:
        findings = await conn.fetch(
            """
            SELECT finding_name, category, severity, origin_name, raw_data
            FROM findings
            WHERE object_id = $1
        """,
            object_id,
        )

        if findings:
            with DaprClient() as client:
                if file_enriched.path:
                    file_path = helpers.sanitize_file_path(file_enriched.path)
                else:
                    file_path = "UNKNOWN"

                for finding in findings:
                    finding_name = finding["finding_name"]
                    category = finding["category"]
                    severity = finding["severity"]
                    origin_name = finding["origin_name"]
                    raw_data = finding["raw_data"]

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


@workflow_activity
async def handle_file_if_plaintext(ctx, activity_input):
    """
    Activity to index a file's contents if it's plaintext and
    send a pub/sub message to NoseyParker
    """
    object_id = activity_input["object_id"]
    file_enriched = await get_file_enriched_async(object_id)

    # if the file is plaintext, make sure we index it
    if file_enriched.is_plaintext:
        with storage.download(object_id) as tmp_file:
            with open(tmp_file.name, "rb") as binary_file:
                with create_text_reader(binary_file) as text_file:
                    await index_plaintext_content(f"{object_id}", text_file)

    nosey_parker_input = NoseyParkerInput(object_id=object_id)
    with DaprClient() as client:
        client.publish_event(
            pubsub_name="pubsub",
            topic_name="noseyparker-input",
            data=json.dumps(nosey_parker_input.model_dump()),
            data_content_type="application/json",
        )
    logger.debug(f"Published noseyparker_input: {object_id}")


@workflow_activity
async def publish_enriched_file(ctx, activity_input):
    """
    Activity to publish enriched file data to pubsub after retrieving from state store.
    """
    object_id = activity_input["object_id"]
    file_enriched = await get_file_enriched_async(object_id)

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


@workflow_activity
async def run_enrichment_modules(ctx, activity_input: dict):
    """Activity that runs all enrichment modules for a file with single file download."""

    object_id = activity_input["object_id"]
    execution_order = activity_input["execution_order"]

    logger.info("Starting enrichment modules processing", object_id=object_id, execution_order=execution_order)

    results = []

    try:
        # Download the file once at the beginning
        with storage.download(object_id) as temp_file:
            logger.debug(
                "Downloaded file for processing",
                object_id=object_id,
                temp_file=temp_file.name,
                size=os.path.getsize(temp_file.name),
            )

            # First pass: determine which modules should process this file
            modules_to_process = []
            for module_name in execution_order:
                if module_name not in global_module_map:
                    logger.warning("Module not found", module_name=module_name)
                    continue

                module = global_module_map[module_name]
                try:
                    should_process = module.should_process(object_id, temp_file.name)

                    if should_process:
                        modules_to_process.append(module_name)
                    #     logger.debug("Module will process file", module_name=module_name)
                    # else:
                    #     logger.debug("Module will skip file", module_name=module_name)
                except Exception as e:
                    logger.exception("Error in should_process", module_name=module_name, error=str(e))

            logger.info("Modules selected for processing", object_id=object_id, modules_to_process=modules_to_process)

            # Second pass: process with modules that should run
            for module_name in modules_to_process:
                try:
                    module = global_module_map[module_name]
                    logger.debug("Starting module processing", module_name=module_name)

                    # Check if the module's process method returns a coroutine (async)
                    result_or_coro = module.process(object_id, temp_file.name)
                    if hasattr(result_or_coro, "__await__"):
                        # It's a coroutine, await it
                        result: EnrichmentResult = await result_or_coro
                    else:
                        # It's a synchronous result
                        result: EnrichmentResult = result_or_coro

                    if result:
                        # Debug: Check for coroutines in the result before serialization
                        import inspect

                        def check_for_coroutines(obj, path="root"):
                            """Recursively check for coroutines in nested structures."""
                            if inspect.iscoroutine(obj):
                                logger.error(f"FOUND COROUTINE at {path}: {obj}")
                                return True
                            elif isinstance(obj, dict):
                                for key, value in obj.items():
                                    if check_for_coroutines(value, f"{path}.{key}"):
                                        return True
                            elif isinstance(obj, (list, tuple)):
                                for i, item in enumerate(obj):
                                    if check_for_coroutines(item, f"{path}[{i}]"):
                                        return True
                            return False

                        # Check the result object
                        try:
                            result_dict = result.model_dump(mode="json")
                            if check_for_coroutines(result_dict, f"result({module_name})"):
                                logger.error(
                                    "Coroutine found in enrichment result before serialization",
                                    module_name=module_name,
                                    object_id=object_id,
                                    result_keys=list(result_dict.keys()) if isinstance(result_dict, dict) else None,
                                )
                        except Exception as debug_err:
                            logger.error(
                                "Error during coroutine debug check",
                                module_name=module_name,
                                error=str(debug_err),
                            )

                        # Store enrichment result directly in database (same as before)
                        async with postgres_pool.acquire() as conn:
                            # Store enrichment
                            results_escaped = json.dumps(helpers.sanitize_for_jsonb(result.model_dump(mode="json")))
                            await conn.execute(
                                """
                                INSERT INTO enrichments (object_id, module_name, result_data)
                                VALUES ($1, $2, $3)
                            """,
                                object_id,
                                module_name,
                                results_escaped,
                            )

                            # Store any transforms
                            if result.transforms:
                                for transform in result.transforms:
                                    await conn.execute(
                                        """
                                        INSERT INTO transforms (object_id, type, transform_object_id, metadata)
                                        VALUES ($1, $2, $3, $4)
                                    """,
                                        object_id,
                                        transform.type,
                                        transform.object_id,
                                        json.dumps(transform.metadata) if transform.metadata else None,
                                    )

                            # Store any findings
                            if result.findings:
                                for finding in result.findings:
                                    await conn.execute(
                                        """
                                        INSERT INTO findings (
                                            finding_name, category, severity, object_id,
                                            origin_type, origin_name, raw_data, data
                                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                                    """,
                                        finding.finding_name,
                                        finding.category,
                                        finding.severity,
                                        object_id,
                                        finding.origin_type,
                                        finding.origin_name,
                                        json.dumps(finding.raw_data),
                                        json.dumps([obj.model_dump_json() for obj in finding.data]),
                                    )

                            # Update workflow in database with successful module
                            await conn.execute(
                                """
                                UPDATE workflows
                                SET enrichments_success = array_append(enrichments_success, $1)
                                WHERE object_id = $2
                                """,
                                module_name,
                                object_id,
                            )

                        results.append((module_name, {"status": "success", "module": module_name}))
                        logger.debug("Module completed successfully", module_name=module_name)
                    else:
                        results.append((module_name, None))
                        logger.debug("Module returned no result", module_name=module_name)

                except Exception as e:
                    logger.exception(
                        "Error in enrichment module", module_name=module_name, object_id=object_id, error=str(e)
                    )

                    # Update workflow in database with failed module
                    try:
                        async with postgres_pool.acquire() as conn:
                            await conn.execute(
                                """
                                UPDATE workflows
                                SET enrichments_failure = array_append(enrichments_failure, $1)
                                WHERE object_id = $2
                                """,
                                f"{module_name}:{str(e)[:100]}",
                                object_id,
                            )
                    except Exception as db_error:
                        logger.error(f"Failed to update workflow failure in database: {str(db_error)}")

                    results.append((module_name, None))
                    # Continue with other modules instead of raising

    except Exception as e:
        logger.exception("Error in run_enrichment_modules", object_id=object_id, error=str(e))
        raise

    logger.debug("Enrichment modules processing completed", object_id=object_id, total_modules=len(results))
    return results


# endregion

##########################################
#
# region Dapr workflows
#
##########################################


@wf_runtime.workflow
def enrichment_workflow(ctx: wf.DaprWorkflowContext, workflow_input: dict):
    """Main workflow that orchestrates all enrichment activities."""

    if not ctx.is_replaying:
        logger.debug("Starting main enrichment workflow", workflow_input=workflow_input)

    start_time = ctx.current_utc_datetime

    try:
        input_file = workflow_input["file"]
        object_id = input_file["object_id"]  # the only guaranteed field to exist

        if not ctx.is_replaying:
            logger.debug("Workflow input", object_id=object_id, workflow_input=workflow_input)

        # Get basic analysis for the file
        try:
            # basic_analysis = yield ctx.call_activity(get_basic_analysis, input=input_file)
            file_enriched = yield ctx.call_activity(get_basic_analysis, input=input_file)
            if not ctx.is_replaying:
                logger.debug(
                    "get_basic_analysis complete",
                    processing_time=f"{ctx.current_utc_datetime - start_time}",
                )
        except Exception as e:
            logger.exception("Error in get_basic_analysis", error=str(e))
            raise

        enrichment_tasks = [
            ctx.call_activity(handle_file_if_plaintext, input=file_enriched),
            ctx.call_activity(check_file_linkings, input={"object_id": object_id}),
            ctx.call_activity(
                run_enrichment_modules,
                input={"object_id": object_id, "execution_order": workflow_input["execution_order"]},
            ),
        ]

        try:
            yield wf.when_all(enrichment_tasks)

            if not ctx.is_replaying:
                logger.debug(
                    "Enrichment tasks complete - handle_file_if_plaintext, enrichment_module_workflow",
                    processing_time=f"{ctx.current_utc_datetime - start_time}",
                )
        except Exception as e:
            import traceback

            # Extract detailed information about each task
            task_details = []
            for i, task in enumerate(enrichment_tasks):
                task_info = {
                    "index": i,
                    "type": type(task).__name__,
                    "repr": repr(task),
                }
                # Try to extract activity name if available
                if hasattr(task, "_activity_name"):
                    task_info["activity_name"] = task._activity_name
                if hasattr(task, "_input"):
                    task_info["input"] = str(task._input)[:200]  # Truncate long inputs
                task_details.append(task_info)

            logger.exception(
                "Error in enrichment tasks - handle_file_if_plaintext or enrichment_module_workflow",
                error=str(e),
                error_type=type(e).__name__,
                error_args=e.args,
                traceback=traceback.format_exc(),
                enrichment_tasks_count=len(enrichment_tasks),
                enrichment_tasks_details=task_details,
            )
            raise

        final_tasks = [
            ctx.call_activity(publish_enriched_file, input={"object_id": object_id}),
            # ctx.call_activity(extract_and_store_features, input={"object_id": object_id}),
            ctx.call_activity(publish_findings_alerts, input={"object_id": object_id}),
        ]

        try:
            yield wf.when_all(final_tasks)

            if not ctx.is_replaying:
                logger.debug(
                    "Final tasks complete - publish_enriched_file, publish_findings_alerts",
                    processing_time=f"{ctx.current_utc_datetime - start_time}",
                )
        except Exception as e:
            logger.exception(
                "Error in final tasks - publish_enriched_file, publish_findings_alerts",
                error=str(e),
            )
            raise

        if not ctx.is_replaying:
            logger.debug(
                "Workflow completed successfully",
                processing_time=f"{ctx.current_utc_datetime - start_time}",
            )
        return {}

    except Exception:
        logger.exception("Error in main workflow execution", workflow_input=workflow_input)
        raise


@wf_runtime.workflow
def single_enrichment_workflow(ctx: wf.DaprWorkflowContext, workflow_input: dict):
    """Lightweight workflow that runs a single enrichment module for bulk operations."""

    workflow_logger = logger.bind(instance_id=ctx.instance_id, workflow_is_replaying=ctx.is_replaying)

    try:
        enrichment_name = workflow_input["enrichment_name"]
        object_id = workflow_input["object_id"]

        workflow_logger.debug(
            "Starting single enrichment workflow",
            enrichment_name=enrichment_name,
            object_id=object_id,
            instance_id=ctx.instance_id,
        )

        # Get the activity name for this enrichment
        activity_name = f"enrich_{enrichment_name}"
        if activity_name not in activity_functions:
            raise KeyError(f"Activity {activity_name} not registered")

        # Run the single enrichment activity
        result = yield ctx.call_activity(activity_functions[activity_name], input={"object_id": object_id})

        workflow_logger.debug(
            "Single enrichment workflow completed",
            enrichment_name=enrichment_name,
            object_id=object_id,
            result=result,
            instance_id=ctx.instance_id,
        )

        return result

    except Exception as e:
        workflow_logger.exception(
            "Error in single enrichment workflow",
            enrichment_name=enrichment_name if "enrichment_name" in locals() else "unknown",
            object_id=object_id if "object_id" in locals() else "unknown",
            error=str(e),
        )
        raise


# endregion

##########################################
#
# region: Management functions
#
##########################################


async def initialize_workflow_runtime(dpapi_manager: DpapiManager, pool: asyncpg.Pool = None):
    """Initialize the workflow runtime and load modules. Returns the execution order for modules."""
    global wf_runtime, workflow_client, asyncio_loop, postgres_pool, global_module_map

    # Store the connection pool for use in workflow activities
    postgres_pool = pool

    # Load enrichment modules
    module_loader = ModuleLoader()
    await module_loader.load_modules()
    global_module_map = module_loader.modules

    asyncio_loop = asyncio.get_running_loop()

    # Filter modules by workflow and determine execution order
    workflow_name = "default"  # This could be made configurable later
    available_modules = {
        name: module
        for name, module in global_module_map.items()
        if hasattr(module, "workflows") and workflow_name in module.workflows
    }

    # janky pass-through for any modules that have a 'dpapi_manager' property
    for module in global_module_map.values():
        if hasattr(module, "dpapi_manager") and module.dpapi_manager is None:
            logger.debug(f"Setting 'dpapi_manager' for '{module}'")
            module.dpapi_manager = dpapi_manager  # type: ignore
            module.loop = asyncio.get_running_loop()  # type: ignore
        elif hasattr(wf_runtime, "dpapi_manager"):
            logger.debug(f"'dpapi_manager' already set for for '{module}'")

    # Build dependency graph from filtered modules
    graph = build_dependency_graph(available_modules)
    execution_order = topological_sort(graph)

    # execution_order = ["yara"]  # for testing a single specific module

    logger.info(
        "Determined module execution order",
        execution_order=execution_order,
        workflow=workflow_name,
        total_modules=len(available_modules),
        filtered_from=len(global_module_map),
    )

    logger.info("Modules loaded and ready for processing", total_modules=len(available_modules))

    wf_runtime.start()

    return execution_order


def get_workflow_client() -> wf.DaprWorkflowClient:
    """Get the workflow client instance"""
    return workflow_client


def reload_yara_rules():
    """Reloads all disk/state yara rules."""
    logger.debug("workflow/workflow.py reloading Yara rules")
    global_module_map["yara"].rule_manager.load_rules()


# endregion


# @workflow_runtime.activity
# async def extract_and_store_features(ctx, activity_input):
#     """Extract features from a file and store them in PostgreSQL."""
#     try:
#         logger.info("Starting feature extraction")
#         object_id = activity_input["object_id"]
#         file_enriched = get_file_enriched(object_id)

#         # we only want to process things that were submitted and not things extracted/post-processed
#         #   so things that don't have an originating_object_id
#         if not file_enriched.originating_object_id:
#             # Initialize feature extractor
#             extractor = FileFeatureExtractor()

#             # Default timestamp for missing values (Unix epoch)
#             DEFAULT_TIMESTAMP = datetime(1970, 1, 1, 0, 0, 0, tzinfo=datetime.now().astimezone().tzinfo)

#             # Use file timestamps from file_enriched, using epoch if not available
#             creation_time = file_enriched.creation_time if file_enriched.creation_time else DEFAULT_TIMESTAMP
#             modification_time = (
#                 file_enriched.modification_time if file_enriched.modification_time else DEFAULT_TIMESTAMP
#             )
#             access_time = file_enriched.access_time if file_enriched.access_time else DEFAULT_TIMESTAMP

#             # Extract features
#             features = extractor.extract_indivdiual_features(
#                 filepath=file_enriched.path,
#                 size=file_enriched.size,
#                 created_time=creation_time,
#                 modified_time=modification_time,
#                 accessed_time=access_time,
#             )

#             # Extract version and remove from features dict
#             features_version = features.pop("_features_version")

#             # Create labels dictionary
#             labels = {
#                 "has_finding": False,
#                 "has_credential": False,
#                 "has_dotnet_vulns": False,
#                 "has_pii": False,
#                 "has_yara_match": False,
#                 "viewed": False,
#             }

#             # Fetch findings from database and update labels
#             with psycopg.connect(postgres_connection_string) as conn:
#                 with conn.cursor() as cur:
#                     # First get the findings
#                     cur.execute(
#                         """
#                         SELECT category, finding_name
#                         FROM findings
#                         WHERE object_id = %s
#                     """,
#                         (file_enriched.object_id,),
#                     )

#                     findings = cur.fetchall()

#                     if findings:
#                         labels["has_finding"] = True
#                         for category, finding_name in findings:
#                             if category == "credential":
#                                 labels["has_credential"] = True
#                             elif category == "vulnerability" and finding_name == "dotnet_vulns":
#                                 labels["has_dotnet_vulns"] = True
#                             elif category == "pii":
#                                 labels["has_pii"] = True
#                             elif category == "yara_match":
#                                 labels["has_yara_match"] = True

#                     # Parse timestamps to datetime objects if they're strings
#                     def parse_timestamp(ts):
#                         if isinstance(ts, str):
#                             return datetime.fromisoformat(ts)
#                         return ts

#                     # Now insert into files_enriched_dataset
#                     query = """
#                     INSERT INTO files_enriched_dataset (
#                         object_id, agent_id, source, project, timestamp, expiration,
#                         path, file_creation_time, file_access_time, file_modification_time,
#                         features_version, individual_features, labels
#                     ) VALUES (
#                         %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
#                     ) ON CONFLICT (object_id) DO UPDATE SET
#                         agent_id = EXCLUDED.agent_id,
#                         source = EXCLUDED.source,
#                         project = EXCLUDED.project,
#                         timestamp = EXCLUDED.timestamp,
#                         expiration = EXCLUDED.expiration,
#                         path = EXCLUDED.path,
#                         file_creation_time = EXCLUDED.file_creation_time,
#                         file_access_time = EXCLUDED.file_access_time,
#                         file_modification_time = EXCLUDED.file_modification_time,
#                         features_version = EXCLUDED.features_version,
#                         individual_features = EXCLUDED.individual_features,
#                         labels = EXCLUDED.labels;
#                     """

#                     cur.execute(
#                         query,
#                         [
#                             file_enriched.object_id,
#                             file_enriched.agent_id,
#                             file_enriched.source,
#                             file_enriched.project,
#                             parse_timestamp(file_enriched.timestamp),
#                             parse_timestamp(file_enriched.expiration) if file_enriched.expiration else None,
#                             file_enriched.path,
#                             creation_time,
#                             access_time,
#                             modification_time,
#                             features_version,
#                             json.dumps(features),
#                             json.dumps(labels),
#                         ],
#                     )
#                     conn.commit()

#             logger.info("Successfully stored file features in dataset", object_id=file_enriched.object_id)

#     except Exception as e:
#         logger.exception(e, message="Error extracting and storing features", activity_input=activity_input)
#         raise

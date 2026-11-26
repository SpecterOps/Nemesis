# src/workflow/workflow.py

from uuid import UUID

import dapr.ext.workflow as wf
import file_enrichment.global_vars as global_vars
from common.helpers import as_uuid, jsonable
from common.logger import get_logger
from common.models import File
from common.workflows.setup import wf_runtime
from dapr.ext.workflow import TaskFailedError
from file_enrichment_modules.module_loader import ModuleLoader
from nemesis_dpapi import DpapiManager

from .activities import (
    check_file_linkings,
    finalize_workflow_failure,
    finalize_workflow_success,
    get_basic_analysis,
    handle_file_if_plaintext,
    publish_enriched_file,
    publish_findings_alerts,
    run_enrichment_modules,
)

logger = get_logger(__name__)


##########################################
#
# region Helper functions
#
##########################################


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


def _await_each(ctx: wf.DaprWorkflowContext, named_tasks, object_id: UUID):
    """Wait for already-scheduled tasks one by one, tolerating individual failures.

    Used with ``yield from`` inside a workflow. The tasks were all scheduled before this is called, so they still run
    concurrently. Returns ``(results_by_name, failed_names)``.
    """
    results: dict = {}
    failed: list[str] = []
    for name, task in named_tasks:
        try:
            results[name] = yield task
        except TaskFailedError as e:
            failed.append(name)
            if not ctx.is_replaying:
                logger.error(
                    "Workflow activity failed; continuing with the remaining steps",
                    activity=name,
                    object_id=object_id,
                    error_type=e.details.error_type,
                    error_message=e.details.message,
                )
    return results, failed


# endregion

##########################################
#
# region Dapr workflows
#
##########################################


@wf_runtime.workflow
def enrichment_pipeline_workflow(ctx: wf.DaprWorkflowContext, file_dict: dict):
    """Main workflow that orchestrates all enrichment activities."""

    file_obj = File.model_validate(file_dict)
    object_id = file_obj.object_id

    if not ctx.is_replaying:
        logger.debug("Starting main enrichment workflow", object_id=object_id, workflow_input=file_dict)

    # Use ctx.current_utc_datetime for workflow replay determinism
    start_time = ctx.current_utc_datetime

    try:
        yield ctx.call_activity(get_basic_analysis, input=file_dict)
        if not ctx.is_replaying:
            logger.debug(
                "get_basic_analysis complete",
                processing_time=f"{ctx.current_utc_datetime - start_time}",
            )

        # The three tasks are scheduled together and run in parallel. Each is awaited on its own so one failure
        # (e.g. plaintext indexing) doesn't skip the others or the publishing steps below; wf.when_all would raise on
        # the first failure and abandon the rest of the workflow.
        enrichment_tasks = [
            (
                "run_enrichment_modules",
                ctx.call_activity(run_enrichment_modules, input=jsonable({"object_id": object_id})),
            ),
            ("check_file_linkings", ctx.call_activity(check_file_linkings, input=jsonable({"object_id": object_id}))),
            (
                "handle_file_if_plaintext",
                ctx.call_activity(handle_file_if_plaintext, input=jsonable({"object_id": object_id})),
            ),
        ]
        results, failed = yield from _await_each(ctx, enrichment_tasks, object_id)

        if not ctx.is_replaying:
            for name, r in results.items():
                logger.debug(f"enrichment_tasks result: {name}: {r}")

            logger.debug(
                "Enrichment tasks complete - handle_file_if_plaintext, check_file_linkings, enrichment_module_workflow",
                processing_time=f"{ctx.current_utc_datetime - start_time}",
                failed=failed,
            )

        # Always wait (also on replay), or finalize runs before the alerts are published
        final_tasks = [
            ("publish_enriched_file", ctx.call_activity(publish_enriched_file, input=jsonable(object_id))),
            ("publish_findings_alerts", ctx.call_activity(publish_findings_alerts, input=jsonable(object_id))),
        ]
        results, final_failed = yield from _await_each(ctx, final_tasks, object_id)
        failed += final_failed
        if not ctx.is_replaying:
            for name, r in results.items():
                logger.debug(f"final_tasks result: {name}: {r}")

            logger.debug(
                "Final tasks complete - publish_enriched_file, publish_findings_alerts",
                processing_time=f"{ctx.current_utc_datetime - start_time}",
            )

        if failed:
            # Everything that could run has run; record the partial failure instead of failing the whole workflow.
            if not ctx.is_replaying:
                logger.error(
                    "Enrichment workflow finished with failed activities",
                    object_id=object_id,
                    failed_activities=failed,
                    processing_time=f"{ctx.current_utc_datetime - start_time}",
                )
            yield ctx.call_activity(
                finalize_workflow_failure,
                input={
                    "error_message": f"activities failed: {', '.join(failed)}"[:200],
                    "start_time": start_time.isoformat(),
                },
            )
            return {"failed_activities": failed}

        if not ctx.is_replaying:
            logger.info(
                "All workflow activites have completed",
                processing_time=f"{ctx.current_utc_datetime - start_time}",
            )

        # Mark workflow as completed
        yield ctx.call_activity(
            finalize_workflow_success,
            input={"start_time": start_time.isoformat()},
        )

        return {}

    except TaskFailedError as e:
        logger.exception(
            "An activity failed in the enrichment workflow",
            workflow_input=file_dict,
            error_type=e.details.error_type,
            error_message=e.details.message,
            stack_trace=e.details.stack_trace,
        )

        # Mark workflow as failed
        try:
            yield ctx.call_activity(
                finalize_workflow_failure,
                input={
                    "error_message": str(e.details.message)[:200],
                    "start_time": start_time.isoformat(),
                },
            )
        except Exception:
            logger.error("Failed to finalize workflow failure status")

        raise

    except Exception as e:
        logger.exception("Unexpected error in execution", workflow_input=file_dict)

        # Mark workflow as failed
        try:
            yield ctx.call_activity(
                finalize_workflow_failure,
                input={
                    "error_message": str(e)[:400],
                    "start_time": start_time.isoformat(),
                },
            )
        except Exception:
            logger.error("Failed to finalize workflow failure status")

        raise


@wf_runtime.workflow
def single_enrichment_workflow(ctx: wf.DaprWorkflowContext, workflow_input: dict):
    """Lightweight workflow that runs a single enrichment module for bulk operations.

    Same as the module step of the main workflow, restricted to one module: the module decides with should_process
    whether the file applies, and its results are stored and tracked the same way. Findings are not re-alerted.
    """
    enrichment_name = workflow_input["enrichment_name"]
    object_id = as_uuid(workflow_input["object_id"])
    start_time = ctx.current_utc_datetime

    if not ctx.is_replaying:
        logger.debug(
            "Starting single enrichment workflow",
            enrichment_name=enrichment_name,
            object_id=object_id,
            instance_id=ctx.instance_id,
        )

    try:
        results = yield ctx.call_activity(
            run_enrichment_modules, input=jsonable({"object_id": object_id, "modules": [enrichment_name]})
        )
    except TaskFailedError as e:
        if not ctx.is_replaying:
            logger.error(
                "Single enrichment workflow failed",
                enrichment_name=enrichment_name,
                object_id=object_id,
                error_message=e.details.message,
            )
        yield ctx.call_activity(
            finalize_workflow_failure,
            input={"error_message": str(e.details.message)[:200], "start_time": start_time.isoformat()},
        )
        raise

    yield ctx.call_activity(finalize_workflow_success, input={"start_time": start_time.isoformat()})

    if not ctx.is_replaying:
        logger.debug(
            "Single enrichment workflow completed",
            enrichment_name=enrichment_name,
            object_id=object_id,
            result=results,
            instance_id=ctx.instance_id,
        )
    return results


# endregion

##########################################
#
# region: Management functions
#
##########################################


async def initialize_enrichment_modules(dpapi_manager: DpapiManager) -> list[str]:
    """Initialize the workflow runtime and load modules. Returns the execution order for modules."""

    # Load enrichment modules
    module_loader = ModuleLoader()
    await module_loader.load_modules()
    # Update the global_module_map in the enrichment_modules activity

    global_vars.global_module_map = module_loader.modules

    # Filter modules by workflow and determine execution order
    workflow_name = "default"  # This could be made configurable later
    available_modules = {
        name: module
        for name, module in module_loader.modules.items()
        if workflow_name in getattr(module, "workflows", [])
    }

    # janky pass-through for any modules that have a 'dpapi_manager' property
    for module in module_loader.modules.values():
        if hasattr(module, "dpapi_manager"):
            module.dpapi_manager = dpapi_manager  # type: ignore

        if hasattr(module, "asyncpg_pool"):
            logger.debug(f"Setting 'asyncpg_pool' for '{module}'")
            module.asyncpg_pool = global_vars.asyncpg_pool  # type: ignore

    # Initialize YaraRuleManager if present
    if "yara" in module_loader.modules:
        yara_module = module_loader.modules["yara"]
        if hasattr(yara_module, "rule_manager"):
            # Pass asyncpg_pool to rule_manager before initializing
            if hasattr(yara_module.rule_manager, "asyncpg_pool"):  # pyright: ignore[reportAttributeAccessIssue]
                yara_module.rule_manager.asyncpg_pool = global_vars.asyncpg_pool  # pyright: ignore[reportAttributeAccessIssue]
            if hasattr(yara_module.rule_manager, "initialize"):  # pyright: ignore[reportAttributeAccessIssue]
                await yara_module.rule_manager.initialize()  # pyright: ignore[reportAttributeAccessIssue]

    # Build dependency graph from filtered modules
    graph = build_dependency_graph(available_modules)
    execution_order = topological_sort(graph)

    # execution_order = ["yara"]  # for testing a single specific module

    logger.info(
        "Determined module execution order",
        execution_order=execution_order,
        workflow=workflow_name,
        total_modules=len(available_modules),
        filtered_from=len(module_loader.modules),
    )

    logger.info("Modules loaded and ready for processing", total_modules=len(available_modules))

    return execution_order


async def reload_yara_rules():
    """Reloads all disk/state yara rules."""

    logger.debug("workflow/workflow.py reloading Yara rules")
    yara_module = global_vars.global_module_map.get("yara")

    if yara_module is None:
        raise ValueError("Yara module not found in global_module_map")

    if not hasattr(yara_module, "rule_manager"):
        raise ValueError(f"Yara module missing rule_manager attribute. Type: {type(yara_module)}")

    await yara_module.rule_manager.load_db_rules()  # pyright: ignore[reportAttributeAccessIssue]


# endregion


# @workflow_runtime.activity
# async def extract_and_store_features(ctx, activity_input):
#     """Extract features from a file and store them in PostgreSQL."""
#     try:
#         logger.info("Starting feature extraction")
#         object_id = activity_input["object_id"]
#         file_enriched = await get_file_enriched_async(object_id)

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
#         logger.exception(message="Error extracting and storing features", activity_input=activity_input)
#         raise

# src/workflow/workflow.py
import asyncio

import dapr.ext.workflow as wf
from common.logger import get_logger
from common.models import File
from common.workflows.setup import wf_runtime
from file_enrichment_modules.module_loader import ModuleLoader
from file_enrichment_modules.yara.yara_manager import YaraRuleManager
from nemesis_dpapi import DpapiManager

from . import global_vars
from .activities import (
    check_file_linkings,
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
        # Parse the workflow input to strongly typed objects
        file_data = workflow_input["file"]
        file_obj = File.model_validate(file_data)
        execution_order: list[str] = global_vars.module_execution_order
        object_id = file_obj.object_id

        if not ctx.is_replaying:
            logger.debug("Workflow input", object_id=object_id, workflow_input=workflow_input)

        # Convert file back to dict for activity (activities expect dict)
        file_enriched = yield ctx.call_activity(get_basic_analysis, input=file_data)
        if not ctx.is_replaying:
            logger.debug(
                "get_basic_analysis complete",
                processing_time=f"{ctx.current_utc_datetime - start_time}",
            )

        enrichment_tasks = [
            ctx.call_activity(handle_file_if_plaintext, input=file_enriched),
            ctx.call_activity(check_file_linkings, input={"object_id": object_id}),
            ctx.call_activity(
                run_enrichment_modules,
                input={"object_id": object_id, "execution_order": execution_order},
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
            logger.info(
                "All workflow activites have completed",
                processing_time=f"{ctx.current_utc_datetime - start_time}",
            )
        return {}

    except Exception:
        logger.exception("Error in main workflow execution", workflow_input=workflow_input)
        raise


@wf_runtime.workflow
def single_enrichment_workflow(ctx: wf.DaprWorkflowContext, workflow_input: dict):
    """Lightweight workflow that runs a single enrichment module for bulk operations."""

    try:
        enrichment_name = workflow_input["enrichment_name"]
        object_id = workflow_input["object_id"]

        if not ctx.is_replaying:
            logger.debug(
                "Starting single enrichment workflow",
                enrichment_name=enrichment_name,
                object_id=object_id,
                instance_id=ctx.instance_id,
            )

        # Get the activity name for this enrichment
        activity_name = f"enrich_{enrichment_name}"
        if activity_name not in global_vars.activity_functions:
            raise KeyError(f"Activity {activity_name} not registered")

        # Run the single enrichment activity
        result = yield ctx.call_activity(global_vars.activity_functions[activity_name], input={"object_id": object_id})

        if not ctx.is_replaying:
            logger.debug(
                "Single enrichment workflow completed",
                enrichment_name=enrichment_name,
                object_id=object_id,
                result=result,
                instance_id=ctx.instance_id,
            )

        return result

    except Exception as e:
        logger.exception(
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


async def initialize_workflow_runtime(dpapi_manager: DpapiManager) -> list[str]:
    """Initialize the workflow runtime and load modules. Returns the execution order for modules."""

    global wf_runtime, asyncio_loop

    # Load enrichment modules
    module_loader = ModuleLoader()
    await module_loader.load_modules()
    # Update the global_module_map in the enrichment_modules activity

    global_vars.global_module_map = module_loader.modules

    asyncio_loop = asyncio.get_running_loop()

    # Filter modules by workflow and determine execution order
    workflow_name = "default"  # This could be made configurable later
    available_modules = {
        name: module
        for name, module in module_loader.modules.items()
        if hasattr(module, "workflows") and workflow_name in module.workflows
    }

    # janky pass-through for any modules that have a 'dpapi_manager' property
    for module in module_loader.modules.values():
        if hasattr(module, "dpapi_manager") and module.dpapi_manager is None:
            logger.debug(f"Setting 'dpapi_manager' for '{module}'")
            module.dpapi_manager = dpapi_manager  # type: ignore
            module.loop = asyncio.get_running_loop()  # type: ignore
        elif hasattr(module, "dpapi_manager"):
            logger.debug(f"'dpapi_manager' already set for for '{module}'")

    # Set asyncpg_pool on modules that need database access
    for module in module_loader.modules.values():
        if hasattr(module, "asyncpg_pool"):
            logger.debug(f"Setting 'asyncpg_pool' for '{module}'")
            module.asyncpg_pool = global_vars.asyncpg_pool  # type: ignore

    # Initialize YaraRuleManager if present
    if "yara" in module_loader.modules:
        yara_module = module_loader.modules["yara"]
        if hasattr(yara_module, "initialize"):
            logger.info("Initializing Yara rule manager...")
            await yara_module.initialize()
            logger.info("Yara rule manager initialized successfully")

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

    wf_runtime.start()

    return execution_order


async def reload_yara_rules():
    """Reloads all disk/state yara rules."""

    logger.debug("workflow/workflow.py reloading Yara rules")
    rule_manager = global_vars.global_module_map["yara"]

    if not isinstance(rule_manager, YaraRuleManager):
        raise ValueError(f"Yara rule manager is incorrect type. Type: {type(rule_manager)}")

    await rule_manager.load_rules()


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

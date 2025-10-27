"""Enrichment modules activity."""

import json
import os

import common.helpers as helpers
import file_enrichment.global_vars as global_vars
from common.logger import get_logger
from common.models import EnrichmentResult
from common.workflows.setup import workflow_activity
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext

from ..tracing import get_tracer

logger = get_logger(__name__)

# Global module map - will be set during initialization


@workflow_activity
async def run_enrichment_modules(ctx: WorkflowActivityContext, activity_input: dict):
    """Activity that runs all enrichment modules for a file with single file download."""

    object_id = activity_input["object_id"]
    execution_order = activity_input["execution_order"]

    tracer = get_tracer()

    with tracer.start_as_current_span("run_enrichment_modules") as span:
        span.set_attribute("object_id", object_id)
        span.set_attribute("module_count", len(execution_order))

        logger.info("Starting enrichment modules processing", object_id=object_id, execution_order=execution_order)

        results = []

        try:
            with global_vars.storage.download(object_id) as temp_file:
                logger.debug(
                    "Downloaded file for processing",
                    object_id=object_id,
                    temp_file=temp_file.name,
                    size=os.path.getsize(temp_file.name),
                )

                modules_to_process = await determine_modules_to_process(object_id, temp_file.name, execution_order)
                span.set_attribute("modules_to_process_count", len(modules_to_process))

                for module_name in modules_to_process:
                    # Create a span for each module execution
                    with tracer.start_as_current_span(f"enrichment.{module_name}") as module_span:
                        module_span.set_attribute("module.name", module_name)
                        module_span.set_attribute("object_id", object_id)

                        try:
                            result = await execute_enrichment_module(object_id, temp_file.name, module_name)

                            if result:
                                # Store enrichment result directly in database
                                await store_enrichment_results(object_id, module_name, result)

                                results.append((module_name, {"status": "success", "module": module_name}))
                                logger.debug("Module completed successfully", module_name=module_name)
                                module_span.set_attribute("module.status", "success")
                            else:
                                results.append((module_name, None))
                                logger.debug("Module returned no result", module_name=module_name)
                                module_span.set_attribute("module.status", "no_result")

                        except Exception as e:
                            logger.exception(
                                "Error in enrichment module", module_name=module_name, object_id=object_id, error=str(e)
                            )

                            # Update workflow in database with failed module
                            await record_module_failure(object_id, module_name, e)

                            results.append((module_name, None))
                            module_span.set_attribute("module.status", "error")
                            module_span.set_attribute("module.error", str(e)[:200])
                            # Continue with other modules instead of raising

        except Exception as e:
            logger.exception("Error in run_enrichment_modules", object_id=object_id, error=str(e))
            span.set_attribute("error", True)
            span.set_attribute("error.message", str(e)[:200])
            raise

        logger.debug("Enrichment modules processing completed", object_id=object_id, total_modules=len(results))
        span.set_attribute("total_results", len(results))
        return results


async def determine_modules_to_process(object_id: str, temp_file_path: str, execution_order: list[str]) -> list[str]:
    """First pass: determine which modules should process this file."""
    modules_to_process = []

    for module_name in execution_order:
        if module_name not in global_vars.global_module_map:
            logger.warning("Module not found", module_name=module_name)
            continue

        module = global_vars.global_module_map[module_name]
        try:
            should_process = await module.should_process(object_id, temp_file_path)

            if should_process:
                modules_to_process.append(module_name)
        except Exception as e:
            logger.exception("Error in should_process", module_name=module_name, error=str(e))

    logger.info("Modules selected for processing", object_id=object_id, modules_to_process=modules_to_process)
    return modules_to_process


async def execute_enrichment_module(object_id: str, temp_file_path: str, module_name: str) -> EnrichmentResult | None:
    """Second pass: process a single module and return its result."""

    logger.debug("Starting module processing", module_name=module_name)

    module = global_vars.global_module_map[module_name]
    result = await module.process(object_id, temp_file_path)

    return result


async def store_enrichment_results(object_id: str, module_name: str, result: EnrichmentResult):
    """Store enrichment results, transforms, and findings in the database."""
    async with global_vars.asyncpg_pool.acquire() as conn:
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


async def record_module_failure(object_id: str, module_name: str, error: Exception):
    """Record a module failure in the database."""
    try:
        async with global_vars.asyncpg_pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE workflows
                SET enrichments_failure = array_append(enrichments_failure, $1)
                WHERE object_id = $2
                """,
                f"{module_name}:{str(error)[:100]}",
                object_id,
            )
    except Exception as db_error:
        logger.error(f"Failed to update workflow failure in database: {str(db_error)}")

"""Enrichment module routes."""

import asyncio
import json
import os
import uuid

import common.helpers as helpers
from common.logger import get_logger
from fastapi import APIRouter, Body, HTTPException, Path
from file_enrichment.workflow import workflow_runtime
from pydantic import BaseModel

logger = get_logger(__name__)

# Create the router directly - no prefix to maintain original URLs
router = APIRouter(tags=["enrichments"])


class EnrichmentRequest(BaseModel):
    object_id: str


@router.get("/llm_enrichments")
async def list_enabled_llm_enrichments():
    """List the enabled LLM enrichments based on environment variables."""
    try:
        if not workflow_runtime or not workflow_runtime.modules:
            raise HTTPException(status_code=503, detail="Workflow runtime or modules not initialized")

        llm_enrichments = []
        if os.getenv("RIGGING_GENERATOR_CREDENTIALS"):
            llm_enrichments.append("llm_credential_analysis")
        if os.getenv("RIGGING_GENERATOR_SUMMARY"):
            llm_enrichments.append("text_summarizer")
        if os.getenv("RIGGING_GENERATOR_TRIAGE"):
            llm_enrichments.append("finding_triage")

        return {"modules": llm_enrichments}

    except Exception as e:
        logger.exception(e, message="Error listing enabled LLM enrichment modules", pid=os.getpid())
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}") from e


@router.get("/enrichments")
async def list_enrichments():
    """List all available enrichment modules."""
    try:
        if not workflow_runtime or not workflow_runtime.modules:
            raise HTTPException(status_code=503, detail="Workflow runtime or modules not initialized")

        modules = list(workflow_runtime.modules.keys())
        return {"modules": modules}

    except Exception as e:
        logger.exception(e, message="Error listing enrichment modules", pid=os.getpid())
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}") from e


@router.post("/enrichments/{enrichment_name}")
async def run_enrichment(
    enrichment_name: str = Path(..., description="Name of the enrichment module to run"),
    request: EnrichmentRequest = Body(..., description="The enrichment request containing the object ID"),
):
    """Run a specific enrichment module directly."""
    # Import pool from controller module to avoid circular imports
    from file_enrichment import controller

    try:
        # Check if module
        if not workflow_runtime or not workflow_runtime.modules:
            raise HTTPException(status_code=503, detail="Workflow runtime or modules not initialized")

        if enrichment_name not in workflow_runtime.modules:
            raise HTTPException(status_code=404, detail=f"Enrichment module '{enrichment_name}' not found")

        # Get the module
        module = workflow_runtime.modules[enrichment_name]

        # Check if we should process this file - run in thread since it might use sync operations
        should_process = await asyncio.to_thread(module.should_process, request.object_id)
        if not should_process:
            return {
                "status": "skipped",
                "message": f"Module {enrichment_name} decided to skip processing",
                "object_id": request.object_id,
                "instance_id": "",
            }

        # Process the file in a separate thread to avoid event loop conflicts
        result = await asyncio.to_thread(module.process, request.object_id)

        if result:
            # Store enrichment result in database
            def store_results():
                with controller.pool.connection() as conn:
                    with conn.cursor() as cur:
                        # Store main enrichment result
                        results_escaped = json.dumps(helpers.sanitize_for_jsonb(result.model_dump(mode="json")))
                        cur.execute(
                            """
                            INSERT INTO enrichments (object_id, module_name, result_data)
                            VALUES (%s, %s, %s)
                            """,
                            (request.object_id, enrichment_name, results_escaped),
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
                                        request.object_id,
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
                                        request.object_id,
                                        finding.origin_type,
                                        finding.origin_name,
                                        json.dumps(finding.raw_data),
                                        json.dumps([obj.model_dump_json() for obj in finding.data]),
                                    ),
                                )

                    conn.commit()

            # Run database operations in thread
            await asyncio.to_thread(store_results)

        return {
            "status": "success",
            "message": f"Completed enrichment with module '{enrichment_name}'",
            "object_id": request.object_id,
            "instance_id": str(uuid.uuid4()),  # Generate a unique instance ID
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(
            e,
            message="Error running enrichment module",
            enrichment_name=enrichment_name,
            object_id=request.object_id,
            pid=os.getpid(),
        )
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}") from e


@router.post("/enrichments/{enrichment_name}/bulk")
async def run_bulk_enrichment(
    enrichment_name: str = Path(..., description="Name of the enrichment module to run"),
):
    """Bulk enrichment is now handled by the web API using distributed processing."""
    raise HTTPException(
        status_code=501,
        detail="Bulk enrichment has been moved to the web API for distributed processing. Please use the main API endpoint.",
    )


@router.get("/enrichments/{enrichment_name}/bulk/status")
async def get_bulk_enrichment_status(
    enrichment_name: str = Path(..., description="Name of the enrichment module to check status for"),
):
    """Bulk enrichment status is now handled by the web API."""
    raise HTTPException(
        status_code=501,
        detail="Bulk enrichment status is now handled by the web API. Please use the main API endpoint.",
    )


@router.post("/enrichments/{enrichment_name}/bulk/stop")
async def stop_bulk_enrichment(
    enrichment_name: str = Path(..., description="Name of the enrichment module to stop"),
):
    """Bulk enrichment stopping is now handled by the web API."""
    raise HTTPException(
        status_code=501,
        detail="Bulk enrichment stopping is now handled by the web API. Please use the main API endpoint.",
    )

"""Enrichment module routes."""

import asyncio
import json
import os
import uuid
from typing import TYPE_CHECKING

import common.helpers as helpers
import file_enrichment.global_vars as global_vars
from common.logger import get_logger
from common.models2.enrichments import EnrichmentRequest, EnrichmentResponse, ModulesListResponse
from fastapi import APIRouter, Body, HTTPException, Path

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)

router = APIRouter(tags=["enrichments"])


@router.get("/llm_enrichments", response_model=ModulesListResponse)
async def list_enabled_llm_enrichments() -> ModulesListResponse:
    """List the enabled LLM enrichments based on environment variables."""
    try:
        if not global_vars.global_module_map:
            raise HTTPException(status_code=503, detail="Modules not initialized")

        llm_enrichments = []
        if os.getenv("RIGGING_GENERATOR_CREDENTIALS"):
            llm_enrichments.append("llm_credential_analysis")
        if os.getenv("RIGGING_GENERATOR_SUMMARY"):
            llm_enrichments.append("text_summarizer")
        if os.getenv("RIGGING_GENERATOR_TRIAGE"):
            llm_enrichments.append("finding_triage")

        return ModulesListResponse(modules=llm_enrichments)

    except Exception as e:
        logger.exception(message="Error listing enabled LLM enrichment modules", pid=os.getpid())
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}") from e


@router.get("/enrichments", response_model=ModulesListResponse)
async def list_enrichments() -> ModulesListResponse:
    """List all available enrichment modules."""
    try:
        if not global_vars.global_module_map:
            raise HTTPException(status_code=503, detail="Modules not initialized")

        module_names = list(global_vars.global_module_map.keys())
        return ModulesListResponse(modules=module_names)

    except Exception as e:
        logger.exception(message="Error listing enrichment modules", pid=os.getpid())
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}") from e


@router.post("/enrichments/{enrichment_name}", response_model=EnrichmentResponse)
async def run_enrichment(
    enrichment_name: str = Path(..., description="Name of the enrichment module to run"),
    enrichment_request: EnrichmentRequest = Body(..., description="The enrichment request containing the object ID"),
) -> EnrichmentResponse:
    """Run a specific enrichment module directly."""
    try:
        if enrichment_name not in global_vars.global_module_map:
            raise HTTPException(status_code=404, detail=f"Enrichment module '{enrichment_name}' not found")

        # Get the module
        module = global_vars.global_module_map[enrichment_name]

        # Check if we should process this file - run in thread since it might use sync operations
        should_process = await asyncio.to_thread(module.should_process, enrichment_request.object_id)
        if not should_process:
            return EnrichmentResponse(
                status="skipped",
                message=f"Module {enrichment_name} decided to skip processing",
                object_id=enrichment_request.object_id,
                instance_id="",
            )

        # Process the file in a separate thread to avoid event loop conflicts
        result = await asyncio.to_thread(module.process, enrichment_request.object_id)

        if result:
            # Store enrichment result in database
            async with global_vars.asyncpg_pool.acquire() as conn:
                # Store main enrichment result
                results_escaped = json.dumps(helpers.sanitize_for_jsonb(result.model_dump(mode="json")))
                await conn.execute(
                    """
                    INSERT INTO enrichments (object_id, module_name, result_data)
                    VALUES ($1, $2, $3)
                    """,
                    enrichment_request.object_id,
                    enrichment_name,
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
                            enrichment_request.object_id,
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
                            enrichment_request.object_id,
                            finding.origin_type,
                            finding.origin_name,
                            json.dumps(finding.raw_data),
                            json.dumps([obj.model_dump() for obj in finding.data]),
                        )

        return EnrichmentResponse(
            status="success",
            message=f"Completed enrichment with module '{enrichment_name}'",
            object_id=enrichment_request.object_id,
            instance_id=str(uuid.uuid4()),  # Generate a unique instance ID
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(
            e,
            message="Error running enrichment module",
            enrichment_name=enrichment_name,
            object_id=enrichment_request.object_id,
            pid=os.getpid(),
        )
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}") from e

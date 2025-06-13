import json
import os
import urllib.parse
import uuid
from datetime import datetime
from typing import Annotated, Optional

import requests
import structlog
from common.models import File as FileModel
from common.models2.api import (
    APIInfo,
    ErrorResponse,
    FileMetadata,
    FileWithMetadataResponse,
    HealthResponse,
    YaraReloadResponse,
)
from common.storage import StorageMinio
from dapr.clients import DaprClient
from fastapi import Body, FastAPI, File, Form, HTTPException, Path, Query, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ValidationError

logger = structlog.get_logger(module=__name__)

VERSION = "0.1.0"


app = FastAPI(
    title="Enrichment API",
    description="API for file enrichment services",
    version=VERSION,
    root_path="/api",
    openapi_tags=[
        {"name": "files", "description": "File management operations"},
        {"name": "workflows", "description": "Workflow management operations"},
        {"name": "enrichments", "description": "Enrichment management operations"},
        {"name": "system", "description": "System and health check endpoints"},
    ],
)

storage = StorageMinio()
DOWNLOAD_SIZE_LIMIT_MB = 500
DEFAULT_EXPIRATION_DAYS = 100


class EnrichmentRequest(BaseModel):
    object_id: str


class EnrichmentResponse(BaseModel):
    status: str
    message: str
    instance_id: str
    object_id: str


class EnrichmentsListResponse(BaseModel):
    modules: list[str]


class CleanupRequest(BaseModel):
    expiration: Optional[str] = None  # ISO datetime or "all"


class WorkflowProcessingStats(BaseModel):
    avg_seconds: Optional[float] = None
    min_seconds: Optional[float] = None
    max_seconds: Optional[float] = None
    p50_seconds: Optional[float] = None
    p90_seconds: Optional[float] = None
    p95_seconds: Optional[float] = None
    p99_seconds: Optional[float] = None
    samples_count: Optional[int] = None


class WorkflowMetrics(BaseModel):
    completed_count: int
    failed_count: int
    total_processed: int
    success_rate: Optional[float] = None
    processing_times: Optional[WorkflowProcessingStats] = None


class ActiveWorkflowDetail(BaseModel):
    id: str
    status: str
    filename: Optional[str] = None
    object_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    runtime_seconds: Optional[float] = None
    error: Optional[str] = None


class WorkflowStatusResponse(BaseModel):
    queued_files: int
    active_workflows: int
    status_counts: Optional[dict[str, int]] = None
    active_details: list[ActiveWorkflowDetail] = []
    metrics: WorkflowMetrics
    timestamp: str
    error: Optional[str] = None


class FailedWorkflowsResponse(BaseModel):
    failed_count: int
    workflows: list[ActiveWorkflowDetail] = []
    timestamp: str


# file routes


@app.post(
    "/files",
    response_model=FileWithMetadataResponse,
    tags=["files"],
    summary="Upload file with metadata",
    description="""
    Upload a file using multipart/form-data with metadata.
    Returns an object_id for the uploaded file and submission_id for the metadata submission.

    Example:
    ```
    curl -k -u n:n -F "file=@example.txt" \
         -F 'metadata={"agent_id":"agent123","project":"proj1","timestamp":"2024-01-29T12:00:00Z","expiration":"2024-02-29T12:00:00Z","path":"/tmp/example.txt"}' \
         https://nemesis:7443/api/files
    ```
    """,
)
async def upload_file(
    file: Annotated[UploadFile, File(description="The file to upload")],
    metadata: Annotated[str, Form(description="JSON string containing file metadata")],
) -> FileWithMetadataResponse:
    try:
        # Parse the metadata string into FileMetadata model
        logger.debug("Metadata received", metadata=metadata)
        metadata_dict = json.loads(metadata)
        file_metadata = FileMetadata(**metadata_dict)

        logger.info(
            "Received file upload request",
            filename=file.filename,
            content_type=file.content_type,
            has_metadata=metadata is not None,
        )

        # Upload file
        object_id = storage.upload_uploadfile(file)
        logger.info("File uploaded to datalake", object_id=object_id)

        # Handle metadata if provided
        metadata_dict = file_metadata.model_dump()
        metadata_dict["object_id"] = object_id
        submission_id = await submit_file_metadata_internal(metadata_dict)

        logger.info("Metadata submitted", submission_id=submission_id)
        return FileWithMetadataResponse(object_id=object_id, submission_id=submission_id)

    except Exception as e:
        logger.exception(e, message="Error processing file upload")
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get(
    "/files/{object_id}",
    tags=["files"],
    responses={404: {"model": ErrorResponse}, 400: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    summary="Download a file",
    description="Download a file by its object ID with optional raw format and custom filename",
)
async def download_file(
    object_id: str = Path(..., description="Unique identifier of the file to download"),
    raw: bool = Query(False, description="Whether to return the file in raw format"),
    name: str = Query("", description="Custom filename for the downloaded file"),
):
    try:
        if not storage.check_file_exists(object_id):
            raise HTTPException(status_code=404, detail=f"File {object_id} not found")

        file_data = storage.get_object_stats(object_id)

        if not file_data:
            raise HTTPException(status_code=404, detail=f"File data for {object_id} not retrieved")

        if not file_data.size:
            raise HTTPException(status_code=404, detail=f"File data for {object_id} has no size information")

        if file_data.size > DOWNLOAD_SIZE_LIMIT_MB * 1024 * 1024:
            raise HTTPException(
                status_code=400,
                detail=f"File too large to download directly. Maximum size is {DOWNLOAD_SIZE_LIMIT_MB}MB.",
            )

        headers = {"Content-Type": "text/plain" if raw else "application/octet-stream"}

        if not raw:
            if name:
                filename = urllib.parse.quote(name)
                headers["Content-Disposition"] = f'attachment; filename="{filename}"'
            else:
                headers["Content-Disposition"] = f'attachment; filename="{object_id}"'
        else:
            headers["X-Content-Type-Options"] = "nosniff"

        return StreamingResponse(
            storage.download_stream(object_id), headers=headers, media_type=headers["Content-Type"]
        )

    except Exception as e:
        logger.exception(e, message="Error downloading file")
        raise HTTPException(status_code=500, detail=str(e)) from e


# workflow routes


@app.get(
    "/workflows/status",
    response_model=WorkflowStatusResponse,
    tags=["workflows"],
    responses={500: {"model": ErrorResponse}},
    summary="Get workflow enrichment workflow status",
    description="Get the current status of the enrichment workflow system",
)
async def get_status():
    """Gets the current enrichment pipeline status with metrics."""
    try:
        dapr_port = os.getenv("DAPR_HTTP_PORT", 3500)
        url = f"http://localhost:{dapr_port}/v1.0/invoke/file-enrichment/method/status"

        response = requests.get(url)
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code, detail=f"Error enrichment pipeline status: {response.text}"
            )

        return response.json()

    except requests.RequestException as e:
        logger.exception(e, message="Error connecting to enrichment service")
        raise HTTPException(status_code=503, detail="Enrichment service unavailable") from e
    except Exception as e:
        logger.exception(e, message="Error getting file enrichment status")
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get(
    "/workflows/failed",
    response_model=FailedWorkflowsResponse,
    tags=["workflows"],
    responses={500: {"model": ErrorResponse}},
    summary="Get failed workflows",
    description="Get the set of failed enrichment workflows",
)
async def get_failed():
    """Gets the set of failed enrichment workflows."""
    try:
        dapr_port = os.getenv("DAPR_HTTP_PORT", 3500)
        url = f"http://localhost:{dapr_port}/v1.0/invoke/file-enrichment/method/failed"

        response = requests.get(url)
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code, detail=f"Error getting failed enrichment workflows: {response.text}"
            )

        return response.json()

    except requests.RequestException as e:
        logger.exception(e, message="Error connecting to enrichment service")
        raise HTTPException(status_code=503, detail="Enrichment service unavailable") from e
    except Exception as e:
        logger.exception(e, message="Error getting file enrichment failed workflows")
        raise HTTPException(status_code=500, detail=str(e)) from e


# enrichment routes


@app.get(
    "/enrichments",
    response_model=EnrichmentsListResponse,
    tags=["enrichments"],
    responses={500: {"model": ErrorResponse}},
    summary="List enrichment modules",
    description="Get a list of all available enrichment modules",
)
async def list_enrichments():
    """List all available enrichment modules by forwarding to file-enrichment service."""
    try:
        dapr_port = os.getenv("DAPR_HTTP_PORT", 3500)
        url = f"http://localhost:{dapr_port}/v1.0/invoke/file-enrichment/method/enrichments"

        response = requests.get(url)
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=f"Error listing enrichments: {response.text}")

        return response.json()

    except requests.RequestException as e:
        logger.exception(e, message="Error connecting to enrichment service")
        raise HTTPException(status_code=503, detail="Enrichment service unavailable") from e
    except Exception as e:
        logger.exception(e, message="Error listing enrichment modules")
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get(
    "/enrichments/llm",
    response_model=EnrichmentsListResponse,
    tags=["enrichments"],
    responses={500: {"model": ErrorResponse}},
    summary="List enabled LLM enrichment modules",
    description="Get a list of enabled LLM enrichment modules",
)
async def list_enabled_llm_enrichments():
    """List all enabled LLM enrichment modules by forwarding to file-enrichment service."""
    try:
        dapr_port = os.getenv("DAPR_HTTP_PORT", 3500)
        url = f"http://localhost:{dapr_port}/v1.0/invoke/file-enrichment/method/llm_enrichments"

        response = requests.get(url)
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code, detail=f"Error listing LLM enrichment modules: {response.text}"
            )

        return response.json()

    except requests.RequestException as e:
        logger.exception(e, message="Error connecting to enrichment service")
        raise HTTPException(status_code=503, detail="Enrichment service unavailable") from e
    except Exception as e:
        logger.exception(e, message="Error listing enrichment modules")
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post(
    "/enrichments/{enrichment_name}",
    response_model=EnrichmentResponse,
    tags=["enrichments"],
    responses={404: {"model": ErrorResponse}, 500: {"model": ErrorResponse}, 503: {"model": ErrorResponse}},
    summary="Run enrichment module",
    description="Run a specific enrichment module on a file",
)
async def run_enrichment(
    enrichment_name: str = Path(..., description="Name of the enrichment module to run"),
    request: EnrichmentRequest = Body(..., description="The enrichment request containing the object ID"),
):
    """Run a specific enrichment module by forwarding the request to file-enrichment service."""
    try:
        # First verify the file exists in our storage
        if not storage.check_file_exists(request.object_id):
            raise HTTPException(status_code=404, detail=f"File {request.object_id} not found")

        # Forward the request to the enrichment service
        dapr_port = os.getenv("DAPR_HTTP_PORT", 3500)
        url = f"http://localhost:{dapr_port}/v1.0/invoke/file-enrichment/method/enrichments/{enrichment_name}"

        logger.info("Forwarding enrichment request", enrichment_name=enrichment_name, object_id=request.object_id)

        response = requests.post(
            url,
            json=request.model_dump(),
            timeout=30,  # Add reasonable timeout
        )

        # Handle various response status codes
        if response.status_code == 404:
            raise HTTPException(status_code=404, detail=f"Enrichment module '{enrichment_name}' not found")
        elif response.status_code == 503:
            raise HTTPException(status_code=503, detail="Enrichment service is unavailable or not initialized")
        elif response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code, detail=f"Error from enrichment service: {response.text}"
            )

        return response.json()

    except requests.Timeout as e:
        logger.error("Timeout connecting to enrichment service", enrichment_name=enrichment_name)
        raise HTTPException(status_code=504, detail="Request to enrichment service timed out") from e
    except requests.RequestException as e:
        logger.exception(e, message="Error connecting to enrichment service")
        raise HTTPException(status_code=503, detail="Enrichment service unavailable") from e
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(
            e, message="Error running enrichment", enrichment_name=enrichment_name, object_id=request.object_id
        )
        raise HTTPException(status_code=500, detail=str(e)) from e


# system routes


@app.post(
    "/system/yara/reload",
    response_model=YaraReloadResponse,
    tags=["system"],
    responses={500: {"model": ErrorResponse}},
    summary="Reload Yara rules",
    description="Trigger a reload of all Yara rules in the backend",
)
async def reload_yara_rules():
    try:
        with DaprClient() as client:
            reload_message = {"action": "reload"}
            client.publish_event(
                pubsub_name="pubsub",
                topic_name="yara",
                data=json.dumps(reload_message),
                data_content_type="application/json",
            )
            logger.info("Published Yara rules reload request")
            return {"message": "Yara rules reload triggered"}
    except Exception as e:
        logger.exception(e, message="Error triggering Yara rules reload")
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post(
    "/system/cleanup",
    tags=["system"],
    responses={500: {"model": ErrorResponse}, 503: {"model": ErrorResponse}},
    summary="Trigger database and datalake cleanup",
    description="Trigger the housekeeping service to clean up expired files and database entries, "
    "and reset the workflow manager state. Optionally specify an expiration date or 'all' to remove all files.",
)
async def trigger_cleanup(request: CleanupRequest = Body(default=None, description="Optional cleanup parameters")):
    """
    Trigger the housekeeping service to clean up expired files and reset the workflow manager
    by forwarding requests through Dapr service invocation.
    """
    try:
        # Create request payload (default to empty dict if no request body provided)
        payload = {} if request is None else request.model_dump(exclude_unset=True)
        dapr_port = os.getenv("DAPR_HTTP_PORT", 3500)
        results = {}

        # 1. Call housekeeping service
        housekeeping_url = f"http://localhost:{dapr_port}/v1.0/invoke/housekeeping/method/trigger-cleanup"
        logger.info("Forwarding cleanup request to housekeeping service", expiration=payload.get("expiration"))

        housekeeping_response = requests.post(
            housekeeping_url,
            json=payload,
            timeout=30,  # Add reasonable timeout
        )

        # Handle housekeeping response
        if housekeeping_response.status_code != 200:
            logger.warning(
                "Error from housekeeping service",
                status_code=housekeeping_response.status_code,
                response=housekeeping_response.text,
            )
            results["housekeeping"] = {
                "status": "error",
                "message": f"Error from housekeeping service: {housekeeping_response.text}",
            }
        else:
            results["housekeeping"] = housekeeping_response.json()

        # 2. Call file-enrichment reset
        enrichment_url = f"http://localhost:{dapr_port}/v1.0/invoke/file-enrichment/method/reset"
        logger.info("Forwarding reset request to file-enrichment service")

        enrichment_response = requests.post(
            enrichment_url,
            timeout=30,  # Add reasonable timeout
        )

        # Handle enrichment response
        if enrichment_response.status_code != 200:
            logger.warning(
                "Error from file-enrichment service",
                status_code=enrichment_response.status_code,
                response=enrichment_response.text,
            )
            results["file_enrichment"] = {
                "status": "error",
                "message": f"Error from file-enrichment service: {enrichment_response.text}",
            }
        else:
            results["file_enrichment"] = enrichment_response.json()

        # Return combined results
        return {"status": "completed", "services": results, "timestamp": datetime.now().isoformat()}

    except requests.Timeout as e:
        service = getattr(e, "request", None)
        if service and hasattr(service, "url"):
            service_name = "housekeeping" if "housekeeping" in service.url else "file-enrichment"
            logger.error(f"Timeout connecting to {service_name} service")
            raise HTTPException(status_code=504, detail=f"Request to {service_name} service timed out") from e
        else:
            logger.error("Timeout connecting to services")
            raise HTTPException(status_code=504, detail="Request to services timed out") from e
    except requests.RequestException as e:
        logger.exception(e, message="Error connecting to services")
        raise HTTPException(status_code=503, detail="One or more services unavailable") from e
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(e, message="Error triggering cleanup")
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get(
    "/system/health",
    response_model=HealthResponse,
    tags=["system"],
    summary="Health check",
    description="Health check endpoint for Docker healthcheck",
)
@app.head("/healthz", include_in_schema=False)
async def healthcheck():
    return {"status": "healthy"}


@app.get(
    "/system/info",
    response_model=APIInfo,
    tags=["system"],
    summary="API information",
    description="Root endpoint that shows API information",
)
async def root():
    return {
        "name": "Enrichment API",
        "version": VERSION,
    }


async def submit_file_metadata_internal(metadata: dict) -> uuid.UUID:
    """
    Internal function to handle metadata submission.
    Returns a submission ID.
    """
    try:
        try:
            file_data = FileModel.model_validate(metadata)
        except ValidationError as e:
            logger.error("Validation error in file metadata", errors=e.errors())
            raise HTTPException(status_code=400, detail=e.errors()) from e

        if not storage.check_bucket_exists():
            logger.error("Bucket doesn't exist, file likely not uploaded first")
            raise HTTPException(status_code=400, detail="Bucket doesn't exist")

        if not storage.check_file_exists(file_data.object_id):
            logger.error("File doesn't exist", object_id=file_data.object_id)
            raise HTTPException(status_code=400, detail=f"File {file_data.object_id} doesn't exist")

        submission_id = uuid.uuid4()

        with DaprClient() as client:
            data = file_data.model_dump(
                exclude_unset=True,
                mode="json",
            )
            client.publish_event(
                pubsub_name="pubsub",
                topic_name="file",
                data=json.dumps(data),
                data_content_type="application/json",
            )
            logger.info(
                "Published file metadata for enrichment", object_id=file_data.object_id, submission_id=submission_id
            )

        return submission_id

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(e, message="Error submitting file metadata")
        raise HTTPException(status_code=500, detail=str(e)) from e

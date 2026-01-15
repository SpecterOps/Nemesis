"""API models for enrichment operations."""

from pydantic import BaseModel


class EnrichmentRequest(BaseModel):
    object_id: str


class EnrichmentResponse(BaseModel):
    status: str
    message: str
    object_id: str
    instance_id: str


class ModulesListResponse(BaseModel):
    modules: list[str]


# Alias for backwards compatibility
EnrichmentsListResponse = ModulesListResponse


class BulkEnrichmentResponse(BaseModel):
    status: str
    message: str
    total_files: int
    enrichment_name: str


class BulkEnrichmentStatusResponse(BaseModel):
    status: str
    start_time: str | None = None
    end_time: str | None = None
    total_files: int
    processed: int
    skipped: int
    failed: int
    current_file: str | None = None
    cancelled: bool
    error: str | None = None
    progress_percentage: float
    enrichment_name: str


class BulkEnrichmentStopResponse(BaseModel):
    status: str
    message: str
    enrichment_name: str

"""API models for container operations."""

from pydantic import BaseModel


class ContainerSubmissionResponse(BaseModel):
    container_id: str
    message: str
    estimated_files: int
    estimated_size: int
    filter_config: dict | None = None


class ContainerStatusResponse(BaseModel):
    container_id: str
    status: str
    progress_percent_files: float | None = None
    progress_percent_bytes: float | None = None
    processed_files: int
    total_files: int
    processed_bytes: int
    total_bytes: int
    current_file: str | None = None
    started_at: str | None = None
    error: str | None = None
    filter_stats: dict | None = None

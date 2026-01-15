"""API models for workflow status responses."""

from datetime import datetime

from pydantic import BaseModel


class WorkflowProcessingStats(BaseModel):
    avg_seconds: float | None = None
    min_seconds: float | None = None
    max_seconds: float | None = None
    p50_seconds: float | None = None
    p90_seconds: float | None = None
    p95_seconds: float | None = None
    p99_seconds: float | None = None
    samples_count: int | None = None


class WorkflowMetrics(BaseModel):
    completed_count: int
    failed_count: int
    total_processed: int
    success_rate: float | None = None
    processing_times: WorkflowProcessingStats | None = None


class ActiveWorkflowDetail(BaseModel):
    id: str
    status: str
    filename: str | None = None
    object_id: str | None = None
    timestamp: datetime | None = None
    runtime_seconds: float | None = None
    error: str | None = None


class WorkflowStatusResponse(BaseModel):
    active_workflows: int
    status_counts: dict[str, int] | None = None
    active_details: list[ActiveWorkflowDetail] = []
    metrics: WorkflowMetrics
    timestamp: str
    error: str | None = None


class FailedWorkflowsResponse(BaseModel):
    failed_count: int
    workflows: list[ActiveWorkflowDetail] = []
    timestamp: str

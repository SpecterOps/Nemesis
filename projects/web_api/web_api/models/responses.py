from datetime import datetime

from pydantic import BaseModel


class EnrichmentResponse(BaseModel):
    status: str
    message: str
    instance_id: str
    object_id: str


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


class EnrichmentsListResponse(BaseModel):
    modules: list[str]


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


class QueueMetrics(BaseModel):
    total_messages: int
    ready_messages: int
    processing_messages: int
    consumers: int
    queue_exists: bool
    memory_bytes: int
    state: str
    message_stats: dict
    error: str | None = None


class QueueSummary(BaseModel):
    total_queued_messages: int
    total_processing_messages: int
    total_consumers: int
    healthy_queues: int
    total_queues_checked: int
    bottleneck_queues: list[str]
    queues_without_consumers: list[str]
    total_memory_bytes: int


class QueuesResponse(BaseModel):
    queue_details: dict[str, QueueMetrics]
    summary: QueueSummary
    timestamp: str


class SingleQueueResponse(BaseModel):
    topic: str
    metrics: QueueMetrics
    timestamp: str


# Reporting Models


class SourceSummary(BaseModel):
    source: str
    file_count: int
    finding_count: int
    verified_findings: int
    last_activity: datetime | None = None


class RiskIndicators(BaseModel):
    credentials: dict[str, int]
    sensitive_data: dict[str, int]


class TimelineEntry(BaseModel):
    date: str
    files_submitted: int
    findings_created: int


class TopFinding(BaseModel):
    finding_id: int
    finding_name: str
    category: str
    severity: int
    triage_state: str | None = None
    file_path: str | None = None
    created_at: datetime


class SourceReport(BaseModel):
    report_type: str
    source: str
    generated_at: datetime
    summary: dict
    risk_indicators: RiskIndicators
    findings_detail: dict
    timeline: dict
    enrichment_performance: dict
    top_findings: list[TopFinding]


class SystemReport(BaseModel):
    report_type: str
    generated_at: datetime
    time_range: dict
    summary: dict
    sources: list[SourceSummary]
    findings_by_category: dict[str, int]
    findings_by_severity: dict[str, int]
    timeline: dict
    enrichment_stats: dict


class LLMSynthesisResponse(BaseModel):
    success: bool
    report_markdown: str | None = None
    risk_level: str | None = None  # "high", "medium", "low"
    key_findings: list[str] = []
    recommendations: list[str] = []
    token_usage: int | None = None
    error: str | None = None

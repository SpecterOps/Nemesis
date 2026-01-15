"""API models for reporting."""

from datetime import datetime

from pydantic import BaseModel


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

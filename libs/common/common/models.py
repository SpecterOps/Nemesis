# src/common/models.py
from datetime import datetime
from enum import Enum
from typing import Any, Generic, TypeVar

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(module=__name__)


##########################################
#
# Used for findings
#
##########################################
class FileObject(BaseModel):
    type: str
    object_id: str | None = None
    metadata: dict | None = None


class FindingCategory(str, Enum):
    CREDENTIAL = "credential"
    EXTRACTED_HASH = "extracted_hash"
    EXTRACTED_DATA = "extracted_data"
    VULNERABILITY = "vulnerability"
    YARA_MATCH = "yara_match"
    PII = "pii"
    MISC = "misc"


class FindingOrigin(str, Enum):
    ENRICHMENT_MODULE = "enrichment_module"
    AI_AGENT = "ai_agent"
    MANUAL = "manual"


class Finding(BaseModel):
    category: FindingCategory
    finding_name: str
    origin_type: FindingOrigin
    origin_name: str
    object_id: str
    severity: int = Field(ge=0, le=10)
    raw_data: dict[str, Any]
    data: list[FileObject]


##########################################
#
# Used for publishing alerts
#
##########################################
class Alert(BaseModel):
    body: str
    title: str | None = None  # title is optional, will have a default
    tag: str | None = None  # optional
    service: str | None = None  # service that sent the message (optional)


##########################################
#
# Special case for NoseyParker
#
##########################################


class NoseyParkerInput(BaseModel):
    object_id: str


class MatchLocation(BaseModel):
    line: int
    column: int


class MatchInfo(BaseModel):
    rule_name: str
    rule_type: str
    matched_content: str
    location: MatchLocation
    snippet: str


class ScanStats(BaseModel):
    blobs_seen: int
    blobs_scanned: int
    bytes_seen: int
    bytes_scanned: int
    matches_found: int

    # Allow aliases for field names
    class Config:
        populate_by_name = True
        extra = "ignore"  # Ignore extra fields


class ScanResults(BaseModel):
    scan_duration_ms: int
    bytes_scanned: int
    matches: list[MatchInfo] = []  # Default to empty list
    stats: ScanStats

    class Config:
        populate_by_name = True
        extra = "ignore"  # Ignore extra fields


class NoseyParkerOutput(BaseModel):
    object_id: str
    scan_result: ScanResults

    class Config:
        populate_by_name = True
        extra = "ignore"  # Ignore extra fields

    # Add a factory method to handle flexible parsing
    @classmethod
    def from_dict(cls, data: dict):
        """Parse from a dictionary, handling errors more gracefully"""
        try:
            return cls(**data)
        except Exception as e:
            logger.warning(f"Error creating NoseyParkerOutput from dict: {e}")
            # Try to construct with just the required fields
            return cls(
                object_id=data.get("object_id", ""),
                scan_result=ScanResults(
                    scan_duration_ms=data.get("scan_result", {}).get("scan_duration_ms", 0),
                    bytes_scanned=data.get("scan_result", {}).get("bytes_scanned", 0),
                    matches=data.get("scan_result", {}).get("matches", []),
                    stats=ScanStats(
                        blobs_seen=data.get("scan_result", {}).get("stats", {}).get("blobs_seen", 0),
                        blobs_scanned=data.get("scan_result", {}).get("stats", {}).get("blobs_scanned", 0),
                        bytes_seen=data.get("scan_result", {}).get("stats", {}).get("bytes_seen", 0),
                        bytes_scanned=data.get("scan_result", {}).get("stats", {}).get("bytes_scanned", 0),
                        matches_found=data.get("scan_result", {}).get("stats", {}).get("matches_found", 0),
                    ),
                ),
            )


##########################################
#
# Model for files submitted to the API
#
##########################################
class File(BaseModel):
    object_id: str
    agent_id: str
    project: str
    timestamp: datetime
    expiration: datetime
    path: str | None = None
    originating_object_id: str | None = None
    nesting_level: int | None = None
    creation_time: str | None = None
    access_time: str | None = None
    modification_time: str | None = None

    class Config:
        exclude_none = True
        exclude_unset = True
        json_encoders = {datetime: lambda dt: dt.isoformat()}


##########################################
#
# Models for enriched files
#
##########################################
class Transform(FileObject):
    pass


# what's returned by enrichment modules
class EnrichmentResult(BaseModel):
    module_name: str  # Keeping this from original model
    results: dict[str, Any] | None = None  # Raw parsed data
    transforms: list[Transform] = []
    findings: list[Finding] = []
    dependencies: list[str] = []


class FileHashes(BaseModel):
    md5: str
    sha1: str
    sha256: str


class FileEnriched(File):
    file_name: str
    extension: str | None = None
    size: int
    hashes: FileHashes
    magic_type: str
    mime_type: str
    is_plaintext: bool
    is_container: bool

    class Config:
        json_encoders = {datetime: lambda dt: dt.isoformat()}


##########################################
#
# Dapr helper models
#
##########################################
class WorkflowResponse(BaseModel):
    workflow_id: str
    status_url: str


class WorkflowStatus(BaseModel):
    status: str
    result: dict | None = None


T = TypeVar("T")


class CloudEvent(BaseModel, Generic[T]):
    """Cloud event schema used in Dapr pub/sub"""

    data: T
    datacontenttype: str
    id: str
    pubsubname: str
    source: str
    specversion: str
    topic: str
    traceid: str
    traceparent: str
    tracestate: str
    type: str

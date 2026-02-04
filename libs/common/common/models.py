# src/common/models.py
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

from .logger import get_logger

if TYPE_CHECKING:
    from .models2.api import FileMetadata

logger = get_logger(__name__)


##########################################
#
# Used for findings
#
##########################################
class FileObject(BaseModel):
    type: str
    object_id: str | None = None
    metadata: dict | None = None


class FindingCategory(StrEnum):
    CREDENTIAL = "credential"
    EXTRACTED_HASH = "extracted_hash"
    EXTRACTED_DATA = "extracted_data"
    VULNERABILITY = "vulnerability"
    YARA_MATCH = "yara_match"
    PII = "pii"
    MISC = "misc"
    INFORMATIONAL = "informational"


class FindingOrigin(StrEnum):
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
    category: str | None = None  # finding category (optional)
    severity: int | None = None  # finding severity 0-10 (optional)
    file_path: str | None = None  # file path associated with the alert (optional)


##########################################
#
# .NET
#
##########################################


class DotNetInput(BaseModel):
    object_id: str


class DotNetMethodInfo(BaseModel):
    MethodName: str
    FilterLevel: str | None = None


class DotNetAssemblyAnalysis(BaseModel):
    AssemblyName: str
    Error: str | None = None
    RemotingChannels: list[str] | None = None
    IsWCFServer: bool = False
    IsWCFClient: bool = False
    SerializationGadgetCalls: dict[str, list[DotNetMethodInfo]] | None = None
    WcfServerCalls: dict[str, list[DotNetMethodInfo]] | None = None
    ClientCalls: dict[str, list[DotNetMethodInfo]] | None = None
    RemotingCalls: dict[str, list[DotNetMethodInfo]] | None = None
    ExecutionCalls: dict[str, list[DotNetMethodInfo]] | None = None

    @field_validator("RemotingChannels", mode="before")
    @classmethod
    def convert_null_to_empty_list(cls, v):
        """Convert null RemotingChannels to empty list."""
        return [] if v is None else v

    @field_validator(
        "SerializationGadgetCalls",
        "WcfServerCalls",
        "ClientCalls",
        "RemotingCalls",
        "ExecutionCalls",
        mode="before",
    )
    @classmethod
    def convert_null_to_empty_dict(cls, v):
        """Convert null dict fields to empty dict."""
        return {} if v is None else v


class DotNetOutput(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    object_id: str = Field(alias="objectId")
    decompilation: str | None = None
    analysis: DotNetAssemblyAnalysis | None = None

    @field_validator("analysis", mode="before")
    @classmethod
    def parse_analysis_json(cls, v):
        """Parse analysis from JSON string if needed"""
        if v is None:
            return None
        if isinstance(v, str):
            import json

            try:
                return json.loads(v)
            except Exception as e:
                logger.warning(f"Failed to parse DotNet analysis JSON: {e}")
                return None
        return v


##########################################
#
# NoseyParker Models
#
##########################################


class GitCommitInfo(BaseModel):
    commit_id: str
    author: str
    author_email: str
    commit_date: str
    message: str


class MatchLocation(BaseModel):
    line: int
    column: int


class MatchInfo(BaseModel):
    rule_name: str
    rule_type: str
    matched_content: str
    location: MatchLocation
    snippet: str
    file_path: str | None = None
    git_commit: GitCommitInfo | None = None


class ScanStats(BaseModel):
    blobs_seen: int
    blobs_scanned: int
    bytes_seen: int
    bytes_scanned: int
    matches_found: int


class ScanResults(BaseModel):
    scan_duration_ms: int
    bytes_scanned: int
    matches: list[MatchInfo]
    stats: ScanStats
    scan_type: str = "regular"  # "regular", "zip", "git_repo"


class NoseyParkerInput(BaseModel):
    object_id: str
    workflow_id: str


class NoseyParkerOutput(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    object_id: str
    workflow_id: str
    scan_result: ScanResults

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
                    scan_type=data.get("scan_result", {}).get("scan_type", "regular"),
                ),
            )


##########################################
#
# Bulk Enrichment
#
##########################################


class BulkEnrichmentEvent(BaseModel):
    enrichment_name: str
    object_id: str


class SingleEnrichmentWorkflowInput(BaseModel):
    """Input model for single enrichment workflows (bulk operations)."""

    enrichment_name: str
    object_id: str


##########################################
#
# Model for files submitted to the API
#
##########################################
class File(BaseModel):
    model_config = ConfigDict(
        exclude_none=True,
        exclude_unset=True,
    )

    object_id: str
    agent_id: str
    source: str | None = None
    project: str
    timestamp: datetime
    expiration: datetime
    path: str  # | None = None
    originating_object_id: str | None = None
    originating_container_id: str | None = None
    nesting_level: int | None = None
    creation_time: str | None = None
    access_time: str | None = None
    modification_time: str | None = None

    @field_validator("nesting_level")
    @classmethod
    def validate_nesting_level(cls, v):
        """Ensure nesting_level is non-negative when set."""
        if v is not None and v < 0:
            raise ValueError("nesting_level must be >= 0")
        return v

    @field_serializer("timestamp", "expiration")
    def serialize_datetime(self, dt: datetime, _info):
        return dt.isoformat()

    @classmethod
    def from_file_metadata(cls, metadata: "FileMetadata", object_id: str) -> "File":
        """
        Create a File instance from FileMetadata and object_id.

        Args:
            metadata: FileMetadata object containing upload metadata
            object_id: The object ID of the uploaded file

        Returns:
            File instance ready for submission
        """
        return cls(
            object_id=object_id,
            agent_id=metadata.agent_id,
            source=metadata.source,
            project=metadata.project,
            timestamp=metadata.timestamp,
            expiration=metadata.expiration,
            path=metadata.path,
        )

    def is_extracted_from_archive(self) -> bool:
        """
        Check if this file was extracted from a container/archive file.

        Returns:
            True if file has an originating_object_id and nesting_level > 0,
            False otherwise
        """
        return self.originating_object_id is not None and self.nesting_level is not None and self.nesting_level > 0

    def is_transform(self) -> bool:
        """
        Check if this file is a transform of another file.

        A transform is a file derived from another file through processing
        (e.g., decompilation, conversion) rather than extraction from an archive.

        Returns:
            True if file has an originating_object_id and nesting_level is None or 0,
            False otherwise
        """
        return self.originating_object_id is not None and (self.nesting_level is None or self.nesting_level == 0)


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


class CloudEvent[T](BaseModel):
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

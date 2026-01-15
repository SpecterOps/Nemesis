# Workflow models (DotNet, NoseyParker, Dapr helpers)
import json

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..logger import get_logger

logger = get_logger(__name__)


##########################################
#
# .NET Models
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
                workflow_id=data.get("workflow_id", ""),
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

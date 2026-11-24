import logging
import re
from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, BeforeValidator, Field, field_serializer, field_validator

logger = logging.getLogger(__name__)


class ErrorResponse(BaseModel):
    detail: str = Field(..., description="Error message details")


class FileWithMetadataResponse(BaseModel):
    """Response for combined file and metadata uploads"""

    object_id: UUID = Field(description="Unique identifier for the uploaded file")
    submission_id: UUID = Field(description="Unique identifier for the metadata submission")


# UploadResponse = Union[FileOnlyResponse, FileWithMetadataResponse]


class HealthResponse(BaseModel):
    """Model representing health check response"""

    status: str = Field(description="Health status of the service")


class YaraReloadResponse(BaseModel):
    """Model representing Yara rules reload response"""

    message: str = Field(description="Status message for Yara rules reload")


class APIInfo(BaseModel):
    """Model representing API information"""

    name: str = Field(description="API name")
    version: str = Field(description="API version")


def ensure_utc_datetime(value) -> datetime:
    """Parse an ISO 8601 string or datetime into an aware UTC datetime; naive values are rejected."""
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as e:
            raise ValueError(f"must be an ISO 8601 datetime with a timezone: {e}") from e
    elif isinstance(value, datetime):
        dt = value
    else:
        raise ValueError(f"must be an ISO 8601 datetime with a timezone, got {type(value).__name__}")

    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("datetime must include a timezone (e.g. 'Z' or '+00:00')")

    if dt.tzinfo != UTC:
        dt = dt.astimezone(UTC)

    return dt


UTCDatetime = Annotated[datetime, BeforeValidator(ensure_utc_datetime)]


class FileFilters(BaseModel):
    """File filtering configuration for container extraction"""

    include: list[str] | None = Field(
        default=None, description="Patterns for files to include. If empty/None, all files are included by default."
    )
    exclude: list[str] | None = Field(
        default=None, description="Patterns for files to exclude. Takes precedence over include patterns."
    )
    pattern_type: Literal["glob", "regex"] = Field(
        default="glob",
        description="Type of patterns to use: 'glob' for shell-style wildcards, 'regex' for regular expressions",
    )

    @field_validator("include", "exclude")
    @classmethod
    def validate_patterns(cls, v, info):
        """Validate that patterns can be compiled if regex type"""
        if v is None:
            return v

        # Access other field values through info.data
        pattern_type = info.data.get("pattern_type", "glob")

        if pattern_type == "regex":
            # Validate that all regex patterns compile
            for pattern in v:
                try:
                    re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    raise ValueError(f"Invalid regex pattern '{pattern}': {e}") from e

        return v


# Column sizes shared by the upload models and other writers (see infra/postgres/01-schema.sql)
MAX_AGENT_ID_LENGTH = 255
MAX_PROJECT_LENGTH = 255
MAX_SOURCE_LENGTH = 1000
SOURCE_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

# Every stored row belongs to a project: required, non-blank, and within the database column's 255 characters.
ProjectName = Annotated[str, Field(min_length=1, max_length=MAX_PROJECT_LENGTH, pattern=r"\S")]
# The agent/tool that submitted the file (VARCHAR(255)); required and non-blank.
AgentId = Annotated[str, Field(min_length=1, max_length=MAX_AGENT_ID_LENGTH, pattern=r"\S")]
# Where the file came from, e.g. "host://WS01" (VARCHAR(1000)); required and non-blank.
SourceName = Annotated[str, Field(min_length=1, max_length=MAX_SOURCE_LENGTH, pattern=r"\S")]

# Stored when an upload doesn't say where the file came from. Files with this source are never correlated with each
# other (registry hive pairing, Chromium key lookups, file listings/linkings, per-source reports), because they may
# come from different machines.
UNKNOWN_SOURCE = "unknown://unknown"


def is_known_source(source: str) -> bool:
    """True unless ``source`` is the unknown-origin placeholder."""
    return source != UNKNOWN_SOURCE


def _default_missing_source(value: Any) -> Any:
    """An omitted or null source means "origin unknown"."""
    return UNKNOWN_SOURCE if value is None else value


# Upload input: omitted/null becomes UNKNOWN_SOURCE; blank or too long is rejected.
SourceInput = Annotated[SourceName, BeforeValidator(_default_missing_source)]


class SecurityInfo(BaseModel):
    """Ownership and permissions of a collected file, as far as its producer knows them (stored as JSONB)."""

    model_config = {"extra": "forbid"}

    owner: str | None = Field(default=None, max_length=1000, description="Owner: user name, UID or SID")
    group: str | None = Field(default=None, max_length=1000, description="Group: name or GID")
    mode: int | None = Field(default=None, ge=0, le=0o177777, description="POSIX mode bits (st_mode)")
    extra: dict[str, Any] | None = Field(default=None, description="Producer-specific details")


class FileMetadata(BaseModel):
    """Metadata model for file uploads"""

    agent_id: AgentId
    source: SourceInput = Field(
        default=UNKNOWN_SOURCE,
        description=f"Where the file came from, e.g. 'host://WS01'. Omitted or null means '{UNKNOWN_SOURCE}'.",
    )
    project: ProjectName
    timestamp: UTCDatetime | None = Field(
        default=None,
        description="ISO 8601 timestamp with a timezone (e.g. 'Z') of when the data was collected",
    )
    expiration: UTCDatetime | None = Field(
        default=None,
        description="ISO 8601 expiration date with a timezone (e.g. 'Z'): when the data should be deleted",
    )
    path: str
    creation_time: UTCDatetime | None = Field(
        default=None, description="ISO 8601 time with a timezone when the file was created on its original system"
    )
    access_time: UTCDatetime | None = Field(
        default=None, description="ISO 8601 time with a timezone when the file was last accessed on its original system"
    )
    modification_time: UTCDatetime | None = Field(
        default=None, description="ISO 8601 time with a timezone when the file was last modified on its original system"
    )
    security_info: SecurityInfo | None = Field(
        default=None, description="Owner, group and permission bits of the file on its original system"
    )
    file_filters: FileFilters | None = Field(
        default=None, description="Optional file filtering configuration for container extraction"
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "agent_id": "beacon123",
                "source": "host://192.168.1.1",
                "project": "assess-test",
                "timestamp": "2025-01-06T23:48:46.925656Z",
                "expiration": "2026-01-06T23:48:46.925656Z",
                "path": "/path/to/file",
                "file_filters": {
                    "include": ["*.exe", "*/Users/**/*"],
                    "exclude": ["*/Windows/**/*", "*.tmp"],
                    "pattern_type": "glob",
                },
            }
        }
    }

    @field_serializer(
        "timestamp", "expiration", "creation_time", "access_time", "modification_time", when_used="unless-none"
    )
    def serialize_datetime(self, dt: datetime, _info):
        return dt.isoformat()


class ContainerFromMountRequest(BaseModel):
    """Request model for processing container files from mounted folder"""

    filename: str = Field(description="Name of the container file in the mounted folder")
    metadata: FileMetadata = Field(description="File metadata for processing")

    model_config = {
        "json_schema_extra": {
            "example": {
                "filename": "large_archive.zip",
                "metadata": {
                    "agent_id": "beacon123",
                    "source": "host://192.168.1.1",
                    "project": "assess-test",
                    "timestamp": "2025-01-06T23:48:46.925656Z",
                    "expiration": "2026-01-06T23:48:46.925656Z",
                    "path": "/mounted/large_archive.zip",
                    "file_filters": {
                        "include": ["*.exe", "*/Users/**/*"],
                        "exclude": ["*/Windows/**/*", "*.tmp"],
                        "pattern_type": "glob",
                    },
                },
            }
        }
    }


####################
# # OpenAPI Documentation Models
# class ErrorResponse(BaseModel):
#     detail: str = Field(..., description="Error message details")


# class MetadataOnlyRequest(BaseModel):
#     object_id: UUID = Field(..., description="Unique identifier of an existing file")
#     timestamp: Optional[str] = Field(None, description="Timestamp of the submission (ISO format)")
#     expiration: Optional[str] = Field(None, description="Expiration date of the file (ISO format)")
#     # Add other metadata fields as needed


# class FileUploadResponse(BaseModel):
#     object_id: Optional[str] = Field(None, description="Unique identifier for the uploaded file")
#     submission_id: Optional[str] = Field(None, description="Unique identifier for the metadata submission")

#     class Config:
#         json_schema_extra = {
#             "example": {
#                 "object_id": "550e8400-e29b-41d4-a716-446655440000",
#                 "submission_id": "123e4567-e89b-12d3-a456-426614174000",
#             }
#         }


# class MetadataSubmissionResponse(BaseModel):
#     submission_id: str = Field(..., description="Unique identifier for the metadata submission")


# class HealthResponse(BaseModel):
#     status: str = Field(..., description="Health status of the service")


# class APIInfo(BaseModel):
#     name: str = Field(..., description="API name")
#     version: str = Field(..., description="API version")
#     status: str = Field(..., description="API operational status")
#     endpoints: dict[str, str] = Field(..., description="Available API endpoints")


# class YaraReloadResponse(BaseModel):
#     message: str = Field(..., description="Status message for Yara rules reload")

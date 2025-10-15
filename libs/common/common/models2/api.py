import logging
import re
from datetime import UTC, datetime
from typing import Annotated, Literal, Union
from uuid import UUID

from pydantic import BaseModel, BeforeValidator, Field, field_validator

logger = logging.getLogger(__name__)


class ErrorResponse(BaseModel):
    detail: str = Field(..., description="Error message details")


class ValidationError(BaseModel):
    """Model representing a validation error"""

    loc: list[Union[str, int]]
    msg: str
    type: str


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
    if isinstance(value, str):
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        dt = value

    if dt.tzinfo is None:
        raise ValueError("Datetime must be timezone-aware")

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
                    raise ValueError(f"Invalid regex pattern '{pattern}': {e}")

        return v


class FileMetadata(BaseModel):
    """Metadata model for file uploads"""

    agent_id: str
    source: str | None = None
    project: str
    timestamp: datetime | None = Field(default=None, description="ISO 8601 formatted timestamp of when the data was collected")
    expiration: datetime | None = Field(default=None, description="ISO 8601 formatted expiration date (when the data should be deleted)")
    path: str
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

    model_config = {"json_encoders": {datetime: lambda dt: dt.isoformat()}}


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
#     object_id: str = Field(..., description="Unique identifier of an existing file")
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

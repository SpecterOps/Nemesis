# File-related API models
import re
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_serializer, field_validator


class FileWithMetadataResponse(BaseModel):
    """Response for combined file and metadata uploads"""

    object_id: UUID = Field(description="Unique identifier for the uploaded file")
    submission_id: UUID = Field(description="Unique identifier for the metadata submission")


class FileFilters(BaseModel):
    """File filtering configuration for container extraction"""

    include: list[str] | None = Field(
        default=None,
        description="Patterns for files to include. If empty/None, all files are included by default.",
    )
    exclude: list[str] | None = Field(
        default=None,
        description="Patterns for files to exclude. Takes precedence over include patterns.",
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


class FileMetadata(BaseModel):
    """Metadata model for file uploads"""

    agent_id: str
    source: str | None = None
    project: str
    timestamp: datetime | None = Field(
        default=None,
        description="ISO 8601 formatted timestamp of when the data was collected",
    )
    expiration: datetime | None = Field(
        default=None,
        description="ISO 8601 formatted expiration date (when the data should be deleted)",
    )
    path: str
    file_filters: FileFilters | None = Field(
        default=None,
        description="Optional file filtering configuration for container extraction",
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

    @field_serializer("timestamp", "expiration", when_used="unless-none")
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

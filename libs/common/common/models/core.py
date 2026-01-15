# Core file models
from datetime import datetime
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, field_serializer, field_validator

if TYPE_CHECKING:
    from .api.files import FileMetadata


class FileHashes(BaseModel):
    md5: str
    sha1: str
    sha256: str


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
    path: str
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


class FileEnriched(File):
    file_name: str
    extension: str | None = None
    size: int
    hashes: FileHashes
    magic_type: str
    mime_type: str
    is_plaintext: bool
    is_container: bool

# Common API models (ErrorResponse, HealthResponse, etc.)
from datetime import UTC, datetime
from typing import Annotated

from pydantic import BaseModel, BeforeValidator, Field


class ErrorResponse(BaseModel):
    detail: str = Field(..., description="Error message details")


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

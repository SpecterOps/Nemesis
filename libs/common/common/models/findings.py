# Finding models
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


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
    INFORMATIONAL = "informational"


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

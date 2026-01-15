# Enrichment models
from typing import Any

from pydantic import BaseModel

from .findings import FileObject, Finding


class Transform(FileObject):
    pass


class EnrichmentResult(BaseModel):
    module_name: str
    results: dict[str, Any] | None = None
    transforms: list[Transform] = []
    findings: list[Finding] = []
    dependencies: list[str] = []


class BulkEnrichmentEvent(BaseModel):
    enrichment_name: str
    object_id: str


class SingleEnrichmentWorkflowInput(BaseModel):
    """Input model for single enrichment workflows (bulk operations)."""

    enrichment_name: str
    object_id: str

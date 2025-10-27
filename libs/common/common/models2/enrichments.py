"""API models for the /enrichments route."""

from pydantic import BaseModel


class EnrichmentRequest(BaseModel):
    object_id: str


class EnrichmentResponse(BaseModel):
    status: str
    message: str
    object_id: str
    instance_id: str


class ModulesListResponse(BaseModel):
    modules: list[str]

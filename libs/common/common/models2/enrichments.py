"""API models for the /enrichments route."""

from uuid import UUID

from common.models2.base import NemesisModel
from pydantic import BaseModel


class EnrichmentRequest(NemesisModel):
    object_id: UUID


class EnrichmentResponse(NemesisModel):
    status: str
    message: str
    object_id: UUID
    instance_id: str


class ModulesListResponse(BaseModel):
    modules: list[str]

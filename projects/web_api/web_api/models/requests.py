from pydantic import BaseModel


class EnrichmentRequest(BaseModel):
    object_id: str

class CleanupRequest(BaseModel):
    expiration: str | None = None  # ISO datetime or "all"

from pydantic import BaseModel


class EnrichmentRequest(BaseModel):
    object_id: str


class CleanupRequest(BaseModel):
    expiration: str | None = None  # ISO datetime or "all"


class ChatbotMessage(BaseModel):
    """A single chat message."""

    role: str  # "user" or "assistant"
    content: str


class ChatbotRequest(BaseModel):
    """Request model for chatbot queries."""

    message: str
    history: list[ChatbotMessage] = []
    use_history: bool = True
    temperature: float = 0.7

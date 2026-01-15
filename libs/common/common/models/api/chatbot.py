"""API models for chatbot and cleanup operations."""

from pydantic import BaseModel


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


class CleanupRequest(BaseModel):
    expiration: str | None = None  # ISO datetime or "all"

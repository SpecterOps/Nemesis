# Alert models
from pydantic import BaseModel


class Alert(BaseModel):
    body: str
    title: str | None = None  # title is optional, will have a default
    tag: str | None = None  # optional
    service: str | None = None  # service that sent the message (optional)
    category: str | None = None  # finding category (optional)
    severity: int | None = None  # finding severity 0-10 (optional)
    file_path: str | None = None  # file path associated with the alert (optional)

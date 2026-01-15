"""API models for queue metrics."""

from pydantic import BaseModel


class QueueMetrics(BaseModel):
    total_messages: int
    ready_messages: int
    processing_messages: int
    consumers: int
    queue_exists: bool
    memory_bytes: int
    state: str
    message_stats: dict
    error: str | None = None


class QueueSummary(BaseModel):
    total_queued_messages: int
    total_processing_messages: int
    total_consumers: int
    healthy_queues: int
    total_queues_checked: int
    bottleneck_queues: list[str]
    queues_without_consumers: list[str]
    total_memory_bytes: int


class QueuesResponse(BaseModel):
    queue_details: dict[str, QueueMetrics]
    summary: QueueSummary
    timestamp: str


class SingleQueueResponse(BaseModel):
    topic: str
    metrics: QueueMetrics
    timestamp: str

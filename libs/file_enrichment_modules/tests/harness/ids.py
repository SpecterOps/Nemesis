"""Readable test labels ("test-uuid", "pq", ...) as stable UUIDs; modules only ever see uuid.UUID object IDs."""

from uuid import NAMESPACE_URL, UUID, uuid5


def label_uuid(value: str | UUID) -> UUID:
    """Return ``value`` as a UUID: UUIDs and UUID strings as-is, any other label as a deterministic uuid5."""
    if isinstance(value, UUID):
        return value
    try:
        return UUID(value)
    except ValueError:
        return uuid5(NAMESPACE_URL, f"nemesis-test:{value}")


def label_key(value: str | UUID) -> str:
    """Dict key used by the mock storage/pool for an object ID or label."""
    return str(label_uuid(value))

"""Shared helpers for building Nemesis file metadata from C2 download records."""

from datetime import UTC, datetime, timedelta


def as_utc(value: datetime | None) -> datetime:
    """Return ``value`` as an aware UTC datetime; naive values are taken to be UTC, and None means now."""
    if value is None:
        return datetime.now(UTC)
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def collection_times(collected_at: datetime | None, expiration_days: int) -> tuple[datetime, datetime]:
    """Return ``(timestamp, expiration)`` for an upload.

    The timestamp is the C2's collection time. Expiration counts ``expiration_days`` from that time, but never
    lands in the past (Nemesis rejects past expirations), so an old download still gets the full retention from now.
    """
    if expiration_days <= 0:
        raise ValueError("expiration_days must be positive")
    timestamp = as_utc(collected_at)
    now = datetime.now(UTC)
    expiration = max(timestamp, now) + timedelta(days=expiration_days)
    return timestamp, expiration


def join_remote_path(directory: str | None, name: str | None) -> str:
    """Join a C2-reported directory and file name using the directory's own separator.

    Windows directories (``C:\\dir`` or ``\\\\server\\share``) keep backslashes; everything else uses ``/``.
    Either part may be empty.
    """
    directory = directory or ""
    name = name or ""
    if not directory:
        return name
    if not name:
        return directory
    separator = "\\" if "\\" in directory and "/" not in directory else "/"
    if directory.endswith(("\\", "/")):
        return f"{directory}{name}"
    return f"{directory}{separator}{name}"

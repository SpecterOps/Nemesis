"""Download tracking, retry scheduling, and transfer helpers shared by the Cobalt Strike and Outflank connectors.

State lives in the connector's LevelDB database:

* ``download:{id}`` is written once a download is finished: uploaded, or failed permanently (``success: false``).
  Finished downloads are never queued again.
* ``retry:{id}`` holds ``{attempts, next_at, last_error}`` after a transient failure. The download is queued again
  once ``next_at`` has passed, with backoff of 5, 10, 20, 40, 80, 160, then 300 seconds.
"""

import json
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiohttp
import plyvel

RETRY_DELAYS_SEC = (5, 10, 20, 40, 80, 160, 300)

# Default inactivity limit for streaming a download body; there is no limit on total transfer time.
DOWNLOAD_READ_TIMEOUT_SEC = 300

# Nemesis/C2 statuses that are client errors yet worth retrying.
RETRYABLE_CLIENT_STATUSES = frozenset({401, 403, 408, 425, 429})

# C2 statuses that mean the download will never be available.
PERMANENT_C2_STATUSES = frozenset({400, 404, 410})

_NEMESIS_STATUS = re.compile(r"Error uploading file to Nemesis: (\d{3})\b")


class PermanentDownloadError(Exception):
    """The download can never succeed; record it as finished so it is not retried."""


class TransientDownloadError(Exception):
    """The download failed for a reason that may clear up; retry it later."""


class FileTooLargeError(PermanentDownloadError):
    """The download exceeds the configured Nemesis max_file_size."""


def retry_delay(attempts: int) -> int:
    """Seconds to wait before retry number ``attempts`` (1-based)."""
    index = min(max(attempts, 1), len(RETRY_DELAYS_SEC)) - 1
    return RETRY_DELAYS_SEC[index]


def download_timeout(connect_timeout: float, read_timeout: float = DOWNLOAD_READ_TIMEOUT_SEC) -> aiohttp.ClientTimeout:
    """Timeout for a file download: bounded connect and per-read inactivity, but no total limit."""
    return aiohttp.ClientTimeout(
        total=None, connect=connect_timeout, sock_connect=connect_timeout, sock_read=read_timeout
    )


async def stream_response_to_file(response: aiohttp.ClientResponse, output_path: str, max_bytes: int | None) -> int:
    """Write a download body to ``output_path``, enforcing ``max_bytes`` before and during the transfer."""
    if max_bytes is not None and response.content_length is not None and response.content_length > max_bytes:
        raise FileTooLargeError(f"Download is {response.content_length} bytes; the limit is {max_bytes}")
    written = 0
    with open(output_path, "wb") as f:
        async for chunk in response.content.iter_chunked(65536):
            written += len(chunk)
            if max_bytes is not None and written > max_bytes:
                raise FileTooLargeError(f"Download exceeded the {max_bytes}-byte limit while streaming")
            f.write(chunk)
    return written


def classify_download_error(exc: BaseException) -> type[Exception]:
    """Return PermanentDownloadError or TransientDownloadError for an exception raised while downloading."""
    if isinstance(exc, PermanentDownloadError):
        return PermanentDownloadError
    if isinstance(exc, aiohttp.ClientResponseError) and exc.status in PERMANENT_C2_STATUSES:
        return PermanentDownloadError
    return TransientDownloadError


def classify_upload_error(detail: str | None) -> type[Exception]:
    """Classify a failed Nemesis upload by its error detail; 4xx rejections are permanent, everything else retries."""
    match = _NEMESIS_STATUS.search(detail or "")
    if match:
        status = int(match.group(1))
        if 400 <= status < 500 and status not in RETRYABLE_CLIENT_STATUSES:
            return PermanentDownloadError
    return TransientDownloadError


def ensure_complete_size(path: Path, expected_size: int | None) -> None:
    """Raise TransientDownloadError if the fetched file is smaller than the C2-reported size (still being written)."""
    if isinstance(expected_size, int) and expected_size >= 0:
        actual = path.stat().st_size
        if actual < expected_size:
            raise TransientDownloadError(f"{path} has {actual} of {expected_size} bytes; the download is incomplete")


def remote_file_path(directory: str | None, name: str | None, join: Callable[[str | None, str | None], str]) -> str:
    """Full remote path for a download whose ``path`` may or may not already end with its file name."""
    directory = directory or ""
    if name and (directory == name or directory.endswith(("/" + name, "\\" + name))):
        return directory
    return join(directory, name)


class DownloadStateStore:
    """Finished and retry records for one collector instance's downloads."""

    def __init__(self, db: plyvel.DB, clock: Callable[[], float] = time.time):
        self.db = db
        self.clock = clock

    @staticmethod
    def _done_key(download_id: str) -> bytes:
        return f"download:{download_id}".encode()

    @staticmethod
    def _retry_key(download_id: str) -> bytes:
        return f"retry:{download_id}".encode()

    def is_finished(self, download_id: str) -> bool:
        return self.db.get(self._done_key(download_id)) is not None

    def retry_state(self, download_id: str) -> dict[str, Any] | None:
        raw = self.db.get(self._retry_key(download_id))
        return json.loads(raw) if raw is not None else None

    def is_due(self, download_id: str) -> bool:
        """True if the download is neither finished nor waiting out a retry delay."""
        if self.is_finished(download_id):
            return False
        state = self.retry_state(download_id)
        return state is None or float(state.get("next_at", 0)) <= self.clock()

    def mark_finished(self, download_id: str, record: dict[str, Any]) -> None:
        """Write the finished record and drop any retry state, atomically."""
        value = {"timestamp": datetime.now(UTC).isoformat(), **record}
        with self.db.write_batch(transaction=True) as batch:
            batch.put(self._done_key(download_id), json.dumps(value).encode())
            batch.delete(self._retry_key(download_id))

    def record_transient_failure(self, download_id: str, error: str) -> dict[str, Any]:
        """Schedule the next attempt and return the stored retry state."""
        previous = self.retry_state(download_id) or {}
        attempts = int(previous.get("attempts", 0)) + 1
        state = {"attempts": attempts, "next_at": self.clock() + retry_delay(attempts), "last_error": error[:1000]}
        self.db.put(self._retry_key(download_id), json.dumps(state).encode())
        return state

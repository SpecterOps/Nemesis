"""Console reporting for input that was rejected, truncated, sanitized, defaulted or reinterpreted.

Nemesis never silently fixes up data: every such event is logged once as a structured WARNING with
``event="data_issue"`` so operators can find it in the service logs.
"""

from enum import StrEnum
from typing import Any
from uuid import UUID

from common.logger import get_logger

logger = get_logger("nemesis.data_issues")


class DataIssueKind(StrEnum):
    EXTENSION_TOO_LONG = "extension_too_long"
    JSONB_SANITIZED = "jsonb_sanitized"
    TRIAGE_TEXT_TRUNCATED = "triage_text_truncated"
    FILE_TIME_ASSUMED_UTC = "file_time_assumed_utc"
    SOURCE_DEFAULTED = "source_defaulted"
    REJECTED_INPUT = "rejected_input"


def log_data_issue(kind: DataIssueKind, *, field: str, object_id: UUID | None = None, **detail: Any) -> None:
    """Log one data issue.

    Args:
        kind: What happened to the data.
        field: The field or column affected (e.g. ``files_enriched.extension``).
        object_id: The file the data belongs to; None only for rejections that happen before a file exists.
        detail: Context such as the original length or counts of removed characters.
    """
    logger.warning(
        "data_issue",
        kind=kind.value,
        field=field,
        object_id=str(object_id) if object_id is not None else None,
        **detail,
    )

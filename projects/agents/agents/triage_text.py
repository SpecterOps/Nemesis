"""Fit LLM triage text into the findings_triage_history columns without losing the triage."""

from agents.schemas import TRIAGE_TEXT_MAX_LENGTH
from common.data_issues import DataIssueKind, log_data_issue


def fit_triage_text(value: str | None, field: str, finding_id: int) -> str | None:
    """Truncate LLM text to the column size (VARCHAR(5000)), logging a data issue when it had to be cut."""
    if value is None or len(value) <= TRIAGE_TEXT_MAX_LENGTH:
        return value
    log_data_issue(
        DataIssueKind.TRIAGE_TEXT_TRUNCATED,
        field=f"findings_triage_history.{field}",
        finding_id=finding_id,
        length=len(value),
        limit=TRIAGE_TEXT_MAX_LENGTH,
    )
    return value[:TRIAGE_TEXT_MAX_LENGTH]

"""Helpers for findings.data, which is an array of objects (one per FileObject)."""

from agents.schemas import TriageRequest


def extract_summary_from_triage_request(triage_request: TriageRequest) -> str | None:
    """Return the summary from the first findings.data object's metadata, if there is one."""
    if not triage_request.data:
        return None
    metadata = triage_request.data[0].get("metadata")
    return metadata.get("summary") if isinstance(metadata, dict) else None

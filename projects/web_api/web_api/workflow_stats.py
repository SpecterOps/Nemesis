"""Aggregate statistics over the `workflows` table for /workflows/status.

The workflows table keeps one row per enrichment workflow (rows are only flagged is_purged), so it
grows to millions of rows. The dashboard polls /workflows/status every few seconds, so:
- counts, min/max/avg runtime and per-status counts come from ONE grouped scan;
- runtime percentiles need a full sort, so they are computed with a single ordered-set aggregate
  and cached for PERCENTILE_TTL_SECONDS (they move slowly).
"""

import time
from typing import Any

PERCENTILE_TTL_SECONDS = 30.0
FAILED_STATUSES = ("FAILED", "ERROR", "TIMEOUT")

_percentile_cache: dict[str, Any] = {"at": None, "value": {}}


def _clear_percentile_cache() -> None:
    _percentile_cache["at"] = None
    _percentile_cache["value"] = {}


def _percentiles(cur, samples_count: int, now: float) -> dict[str, float | None]:
    if samples_count < 5:
        return {}
    cached_at = _percentile_cache["at"]
    if cached_at is not None and now - cached_at < PERCENTILE_TTL_SECONDS:
        return _percentile_cache["value"]

    cur.execute(
        """
        SELECT percentile_cont(ARRAY[0.5, 0.9, 0.95, 0.99]) WITHIN GROUP (ORDER BY runtime_seconds)
        FROM workflows
        WHERE runtime_seconds IS NOT NULL
        """
    )
    row = cur.fetchone()
    values = row[0] if row and row[0] else [None, None, None, None]
    result = {
        f"{name}_seconds": round(float(v), 2) if v is not None else None
        for name, v in zip(("p50", "p90", "p95", "p99"), values, strict=True)
    }
    _percentile_cache["at"] = now
    _percentile_cache["value"] = result
    return result


def get_workflow_metrics(cur, now: float | None = None) -> tuple[dict[str, Any], dict[str, int]]:
    """Return (metrics, status_counts) in the /workflows/status response shape."""
    now = time.monotonic() if now is None else now
    cur.execute(
        """
        SELECT status, COUNT(*), COUNT(runtime_seconds), SUM(runtime_seconds),
               MIN(runtime_seconds), MAX(runtime_seconds)
        FROM workflows
        GROUP BY status
        """
    )
    status_counts: dict[str, int] = {}
    samples_count = 0
    runtime_sum = 0.0
    min_time: float | None = None
    max_time: float | None = None
    for status, count, samples, total, low, high in cur.fetchall():
        status_counts[status] = count
        samples_count += samples or 0
        runtime_sum += float(total or 0)
        if low is not None:
            min_time = low if min_time is None else min(min_time, low)
        if high is not None:
            max_time = high if max_time is None else max(max_time, high)

    completed_count = status_counts.get("COMPLETED", 0)
    failed_count = sum(status_counts.get(s, 0) for s in FAILED_STATUSES)
    running_count = status_counts.get("RUNNING", 0)
    avg_time = runtime_sum / samples_count if samples_count else None
    finished = completed_count + failed_count

    metrics = {
        "completed_count": completed_count,
        "failed_count": failed_count,
        "running_count": running_count,
        "total_processed": finished,
        "success_rate": round(completed_count / finished * 100, 2) if finished > 0 else None,
        "processing_times": {
            "avg_seconds": round(avg_time, 2) if avg_time else None,
            "min_seconds": round(min_time, 2) if min_time else None,
            "max_seconds": round(max_time, 2) if max_time else None,
            "samples_count": samples_count,
            **_percentiles(cur, samples_count, now),
        },
    }
    return metrics, status_counts

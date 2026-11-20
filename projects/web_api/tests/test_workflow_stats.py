"""Tests for /workflows/status aggregation (web_api.workflow_stats) with a fake cursor."""

import pytest
from fake_db import FakeCursor
from web_api import workflow_stats as ws


@pytest.fixture(autouse=True)
def _reset_cache():
    ws._clear_percentile_cache()
    yield
    ws._clear_percentile_cache()


GROUPED = [
    # status, count, count(runtime), sum(runtime), min, max
    ("COMPLETED", 90, 90, 900.0, 1.0, 30.0),
    ("FAILED", 6, 6, 30.0, 0.5, 10.0),
    ("TIMEOUT", 2, 2, 20.0, 9.0, 11.0),
    ("RUNNING", 2, 0, None, None, None),
]


def test_metrics_from_single_grouped_scan():
    cur = FakeCursor([GROUPED, [([10.0, 20.0, 25.0, 29.5],)]])
    metrics, status_counts = ws.get_workflow_metrics(cur, now=100.0)
    assert status_counts == {"COMPLETED": 90, "FAILED": 6, "TIMEOUT": 2, "RUNNING": 2}
    assert metrics["completed_count"] == 90
    assert metrics["failed_count"] == 8
    assert metrics["running_count"] == 2
    assert metrics["total_processed"] == 98
    assert metrics["success_rate"] == round(90 / 98 * 100, 2)
    times = metrics["processing_times"]
    assert times["samples_count"] == 98
    assert times["avg_seconds"] == round(950 / 98, 2)
    assert times["min_seconds"] == 0.5
    assert times["max_seconds"] == 30.0
    assert times["p50_seconds"] == 10.0
    assert times["p99_seconds"] == 29.5
    assert len(cur.executed) == 2


def test_percentiles_are_cached_between_polls():
    cur = FakeCursor([GROUPED, [([1.0, 2.0, 3.0, 4.0],)], GROUPED, GROUPED, [([5.0, 6.0, 7.0, 8.0],)]])
    first, _ = ws.get_workflow_metrics(cur, now=100.0)
    second, _ = ws.get_workflow_metrics(cur, now=100.0 + ws.PERCENTILE_TTL_SECONDS - 1)
    assert second["processing_times"]["p50_seconds"] == 1.0  # cached, no percentile query
    third, _ = ws.get_workflow_metrics(cur, now=100.0 + ws.PERCENTILE_TTL_SECONDS + 1)
    assert third["processing_times"]["p50_seconds"] == 5.0  # refreshed
    assert first["processing_times"]["p90_seconds"] == 2.0


def test_empty_table():
    cur = FakeCursor([[]])
    metrics, status_counts = ws.get_workflow_metrics(cur, now=1.0)
    assert status_counts == {}
    assert metrics["success_rate"] is None
    assert metrics["total_processed"] == 0
    assert metrics["processing_times"] == {
        "avg_seconds": None,
        "min_seconds": None,
        "max_seconds": None,
        "samples_count": 0,
    }
    assert len(cur.executed) == 1  # no percentile query for < 5 samples


def test_percentiles_with_null_result():
    cur = FakeCursor([GROUPED, [(None,)]])
    metrics, _ = ws.get_workflow_metrics(cur, now=1.0)
    assert metrics["processing_times"]["p50_seconds"] is None

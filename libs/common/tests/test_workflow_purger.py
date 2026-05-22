from datetime import UTC, datetime, timedelta

from common.workflows.workflow_purger import WorkflowPurger


def test_completed_workflow_waits_for_purge_grace_after_completion():
    now = datetime(2026, 5, 21, tzinfo=UTC)
    purger = WorkflowPurger("test", None, None, purge_grace_seconds=60)

    record = {
        "status": "COMPLETED",
        "start_time": now - timedelta(seconds=120),
        "runtime_seconds": 90,
    }

    assert not purger._is_ready_for_purge(record, now)


def test_completed_workflow_is_ready_after_purge_grace():
    now = datetime(2026, 5, 21, tzinfo=UTC)
    purger = WorkflowPurger("test", None, None, purge_grace_seconds=60)

    record = {
        "status": "COMPLETED",
        "start_time": now - timedelta(seconds=180),
        "runtime_seconds": 90,
    }

    assert purger._is_ready_for_purge(record, now)


def test_running_workflow_remains_ready_for_timeout_checks():
    now = datetime(2026, 5, 21, tzinfo=UTC)
    purger = WorkflowPurger("test", None, None, purge_grace_seconds=60)

    record = {
        "status": "RUNNING",
        "start_time": now,
        "runtime_seconds": None,
    }

    assert purger._is_ready_for_purge(record, now)

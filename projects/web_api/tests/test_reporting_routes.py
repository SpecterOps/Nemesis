"""Tests for the reporting queries (web_api.reporting_routes) with a fake database."""

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from unittest.mock import patch

import pytest
from fake_db import FakePool
from web_api import reporting_routes as rr

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
TODAY = date(2026, 11, 19)


# ---------------------------------------------------------------- sources list


def _source_rows():
    # (source, file_count, total_size, last_activity, finding_count, verified_findings)
    return [
        ("HOST-B", 10, Decimal(1000), NOW, 4, 1),
        ("HOST-A", 5, Decimal(500), NOW - timedelta(days=1), 0, 0),
        (None, 3, None, NOW - timedelta(days=2), 2, 0),
    ]


def test_sources_list_maps_rows_and_drops_null_source():
    pool = FakePool([_source_rows()])
    sources = rr.get_sources_list(pool)
    assert [s.source for s in sources] == ["HOST-B", "HOST-A"]
    assert sources[0].file_count == 10
    assert sources[0].finding_count == 4
    assert sources[0].verified_findings == 1
    # one statement, no filters
    sql, params = pool.executed[0]
    assert "GROUP BY 1" in sql
    assert params == []


def test_sources_list_applies_filters_to_both_scans():
    pool = FakePool([[]])
    start = NOW - timedelta(days=7)
    assert rr.get_sources_list(pool, project="p1", start_date=start, end_date=NOW) == []
    sql, params = pool.executed[0]
    assert sql.count("fe.project = %s") == 2
    assert sql.count("fe.created_at >= %s") == 2
    # filter params are repeated for the files scan and the findings scan
    assert params == ["p1", start, NOW, "p1", start, NOW]


def test_sources_list_empty_database():
    assert rr.get_sources_list(FakePool([[]])) == []


# ---------------------------------------------------------------- dashboard stats


def test_dashboard_stats_combines_file_and_triage_counts():
    pool = FakePool(
        [
            [(100, 80, 7, 60)],  # files scan
            [("true_positive", 3), ("false_positive", 2), ("needs_review", 1), ("custom", 4)],  # latest triage
            [(50,)],  # untriaged
        ]
    )
    stats = rr.get_dashboard_stats(pool)
    assert stats["files"] == {"total": 100, "submitted": 80, "derived": 20, "containers": 7, "unviewed": 60}
    assert stats["triage"]["true_positive"] == 3
    assert stats["triage"]["false_positive"] == 2
    assert stats["triage"]["needs_review"] == 1
    assert stats["triage"]["untriaged"] == 50
    assert stats["triage"]["by_value"]["custom"] == 4


def test_triage_summary_with_no_findings():
    summary = rr.get_triage_summary(FakePool([[], [(0,)]]))
    assert summary == {"true_positive": 0, "false_positive": 0, "needs_review": 0, "untriaged": 0, "by_value": {}}


# ---------------------------------------------------------------- source report


def _source_report_results(file_rows, finding_rows, top=None):
    return [
        file_rows,
        finding_rows,
        [(10, 4)],  # chromium logins
        [(20, 5)],  # chromium cookies
        [(3, 1)],  # dpapi masterkeys
        top or [],  # top findings
        [(12, 10, 1, 2.5, 9.0)],  # workflows
        [(TODAY,)],  # CURRENT_DATE
    ]


def test_source_report_parses_grouping_sets():
    day = TODAY - timedelta(days=1)
    file_rows = [
        # (grp, extension, day, count, sum(size), min, max)
        (3, None, None, 6, Decimal(600), NOW - timedelta(days=1), NOW),
        (1, "txt", None, 4, None, None, None),
        (1, None, None, 2, None, None, None),
        (2, None, day, 5, None, None, None),
        (2, None, TODAY, 1, None, None, None),
    ]
    finding_rows = [
        # (grp, category, severity_level, origin_name, triage_value, day, count)
        (0b11111, None, None, None, None, None, 7),
        (0b01111, "credential", None, None, None, None, 5),
        (0b01111, "pii", None, None, None, None, 2),
        (0b10111, None, "high", None, None, None, 4),
        (0b10111, None, "low", None, None, None, 3),
        (0b11011, None, None, "titus", None, None, 2),
        (0b11011, None, None, "yara_scanner", None, None, 1),
        (0b11011, None, None, "other", None, None, 4),
        (0b11101, None, None, None, "true_positive", None, 2),
        (0b11101, None, None, None, "false_positive", None, 1),
        (0b11101, None, None, None, None, None, 4),  # never triaged
        (0b11110, None, None, None, None, day, 6),
    ]
    top = [(1, "f1", "credential", 9, "true_positive", "/a/b.txt", NOW)]
    pool = FakePool(_source_report_results(file_rows, finding_rows, top))

    report = rr.get_source_report_data(pool, "host-a")

    assert report.source == "HOST-A"
    s = report.summary
    assert s["total_files"] == 6
    assert s["total_size_bytes"] == Decimal(600)
    assert s["unique_extensions"] == 1  # NULL extension is not counted
    assert s["file_types"] == {"txt": 4, "unknown": 2}
    assert s["total_findings"] == 7
    assert s["verified_true_positives"] == 2
    assert s["verified_false_positives"] == 1
    assert s["needs_review_findings"] == 0
    assert s["untriaged_findings"] == 4
    fd = report.findings_detail
    assert fd["by_category"] == {"credential": 5, "pii": 2}
    assert list(fd["by_severity"]) == ["high", "low"]
    assert fd["by_origin"]["titus"] == 2
    assert report.risk_indicators.credentials["titus_findings"] == 2
    assert report.risk_indicators.sensitive_data["yara_matches"] == 1
    assert report.risk_indicators.credentials["chromium_logins"] == 10
    assert report.enrichment_performance["workflows_total"] == 12
    assert report.top_findings[0].triage_state == "true_positive"

    timeline = report.timeline["daily_activity"]
    assert len(timeline) == rr.TIMELINE_DAYS
    assert timeline[-1] == {"date": TODAY.isoformat(), "files_submitted": 1, "findings_created": 0}
    assert timeline[-2] == {"date": day.isoformat(), "files_submitted": 5, "findings_created": 6}
    assert timeline[0]["date"] == (TODAY - timedelta(days=13)).isoformat()

    # the source filter is case-insensitive and goes through UPPER(source)
    sql, params = pool.executed[0]
    assert "UPPER(fe.source) = %s" in sql
    assert params == ["HOST-A"]


def test_source_report_unknown_source_is_all_zero():
    file_rows = [(3, None, None, 0, None, None, None)]
    finding_rows = [(0b11111, None, None, None, None, None, 0)]
    report = rr.get_source_report_data(FakePool(_source_report_results(file_rows, finding_rows)), "nope")
    assert report.summary["total_files"] == 0
    assert report.summary["first_seen"] is None
    assert report.summary["file_types"] == {}
    assert report.findings_detail["triage_breakdown"] == {
        "true_positive": 0,
        "false_positive": 0,
        "needs_review": 0,
        "untriaged": 0,
    }
    assert report.top_findings == []
    assert all(d["files_submitted"] == 0 for d in report.timeline["daily_activity"])


def test_source_report_file_types_capped_at_20():
    file_rows = [(3, None, None, 300, 0, NOW, NOW)] + [(1, f"e{i}", None, i + 1, None, None, None) for i in range(25)]
    finding_rows = [(0b11111, None, None, None, None, None, 0)]
    report = rr.get_source_report_data(FakePool(_source_report_results(file_rows, finding_rows)), "x")
    assert len(report.summary["file_types"]) == 20
    assert report.summary["unique_extensions"] == 25
    assert next(iter(report.summary["file_types"])) == "e24"  # most common first


def test_source_report_date_filters_are_passed():
    file_rows = [(3, None, None, 0, None, None, None)]
    finding_rows = [(0b11111, None, None, None, None, None, 0)]
    pool = FakePool(_source_report_results(file_rows, finding_rows))
    start = NOW - timedelta(days=3)
    rr.get_source_report_data(pool, "x", start_date=start, end_date=NOW)
    sql, params = pool.executed[0]
    assert "fe.created_at >= %s" in sql and "fe.created_at <= %s" in sql
    assert params == ["X", start, NOW]


def test_source_report_propagates_db_errors():
    class Boom(FakePool):
        pass

    pool = Boom([])
    with pytest.raises(AssertionError):
        rr.get_source_report_data(pool, "x")


# ---------------------------------------------------------------- system report


def _system_results(source_rows):
    return [
        source_rows,
        [(100, 40)],  # chromium logins
        [(0b01, "credential", None, 5), (0b01, "pii", None, 9), (0b10, None, "high", 14)],
        [(TODAY, 8)],  # files per day
        [(TODAY, 6)],  # findings per day
        [(TODAY,)],  # CURRENT_DATE
        [(20, 18, 2, 1.5)],  # workflows
    ]


def test_system_report_totals_and_breakdowns():
    pool = FakePool(_system_results(_source_rows()))
    report = rr.get_system_report_data(pool)
    s = report.summary
    assert s["total_sources"] == 2  # NULL source not counted as a source
    assert s["total_files"] == 18  # but its files are
    assert s["total_size_bytes"] == Decimal(1500)
    assert s["total_findings"] == 6
    assert s["verified_true_positives"] == 1
    assert s["total_credentials"] == 100
    assert [x.source for x in report.sources] == ["HOST-B", "HOST-A"]
    assert report.findings_by_category == {"pii": 9, "credential": 5}
    assert report.findings_by_severity == {"high": 14}
    assert report.timeline["daily_activity"][-1] == {
        "date": TODAY.isoformat(),
        "files_submitted": 8,
        "findings_created": 6,
    }
    assert report.enrichment_stats["total_workflows"] == 20
    # without file filters the category/severity scan does not join files_enriched
    category_sql = pool.executed[2][0]
    assert "JOIN files_enriched" not in category_sql


def test_system_report_limits_sources_to_50():
    rows = [(f"H{i}", 1, 1, NOW - timedelta(minutes=i), 0, 0) for i in range(80)]
    report = rr.get_system_report_data(FakePool(_system_results(rows)))
    assert len(report.sources) == 50
    assert report.summary["total_sources"] == 80


def test_system_report_with_filters_qualifies_columns():
    """Date/project filters used to fail with an ambiguous created_at column; they are now qualified."""
    pool = FakePool(_system_results([]))
    start = NOW - timedelta(days=1)
    report = rr.get_system_report_data(pool, start_date=start, project="p")
    assert report.summary["total_files"] == 0
    for sql, _params in pool.executed:
        assert " created_at >=" not in sql.replace("fe.created_at >=", "")
    category_sql, category_params = pool.executed[2]
    assert "JOIN files_enriched" in category_sql
    assert category_params == ["p", start]


def test_system_report_all_sources_when_limit_is_none():
    rows = [(f"H{i}", 1, 1, NOW - timedelta(minutes=i), 0, 0) for i in range(80)]
    report = rr.get_system_report_data(FakePool(_system_results(rows)), sources_limit=None)
    assert len(report.sources) == 80


def test_system_report_endpoint_sources_limit(client):
    with (
        patch("web_api.main.get_db_pool"),
        patch("web_api.reporting_routes.get_system_report_data", side_effect=RuntimeError("x")) as mock_report,
    ):
        client.get("/reports/system", params={"sources_limit": 0})
        assert mock_report.call_args.args[-1] is None  # 0 means all sources
        client.get("/reports/system")
        assert mock_report.call_args.args[-1] == 50
    assert client.get("/reports/system", params={"sources_limit": -1}).status_code == 422


# ---------------------------------------------------------------- endpoint


def test_dashboard_stats_endpoint(client):
    payload = {"files": {"total": 1}, "triage": {"untriaged": 0}}
    with patch("web_api.main.get_db_pool"), patch("web_api.reporting_routes.get_dashboard_stats", return_value=payload):
        response = client.get("/reports/dashboard-stats")
    assert response.status_code == 200
    assert response.json() == payload


def test_dashboard_stats_endpoint_error(client):
    with (
        patch("web_api.main.get_db_pool"),
        patch("web_api.reporting_routes.get_dashboard_stats", side_effect=RuntimeError("db down")),
    ):
        response = client.get("/reports/dashboard-stats")
    assert response.status_code == 500
    assert "db down" in response.json()["detail"]


# ---------------------------------------------------------------- PDF HTML templates


def test_source_report_template_renders_report_data():
    from web_api.pdf_generator import render_source_report_html

    file_rows = [(3, None, None, 2, Decimal(10), NOW, NOW), (1, "txt", None, 2, None, None, None)]
    finding_rows = [(0b11111, None, None, None, None, None, 1), (0b11011, None, None, "titus", None, None, 1)]
    top = [(1, "aws_key", "credential", 9, None, "/a/b.txt", NOW)]
    report = rr.get_source_report_data(FakePool(_source_report_results(file_rows, finding_rows, top)), "host")
    html = render_source_report_html(report.model_dump())
    assert "Titus Findings" in html
    assert "aws_key" in html


def test_system_report_template_renders_report_data():
    from web_api.pdf_generator import render_system_report_html

    report = rr.get_system_report_data(FakePool(_system_results(_source_rows())))
    html = render_system_report_html(report.model_dump())
    assert "HOST-B" in html


# ---------------------------------------------------------------- report consistency fixes (#169, #170)


def test_end_date_at_midnight_includes_whole_day():
    """A date-only end date ("2026-11-19" parses to midnight) must keep the whole end day."""
    end = datetime(2026, 11, 19, tzinfo=UTC)
    conditions, params = rr._file_filters(end_date=end)
    assert conditions == ["fe.created_at < %s"]
    assert params == [end + timedelta(days=1)]


def test_end_date_naive_midnight_and_plain_date_include_whole_day():
    assert rr._end_date_condition("c", datetime(2026, 11, 19)) == ("c < %s", datetime(2026, 11, 20))
    assert rr._end_date_condition("c", date(2026, 11, 19)) == ("c < %s", date(2026, 11, 20))


def test_end_date_with_time_is_inclusive_instant():
    end = datetime(2026, 11, 19, 0, 0, 1, tzinfo=UTC)
    assert rr._file_filters(end_date=end) == (["fe.created_at <= %s"], [end])


def test_source_report_date_only_end_date_is_inclusive():
    file_rows = [(3, None, None, 0, None, None, None)]
    finding_rows = [(0b11111, None, None, None, None, None, 0)]
    pool = FakePool(_source_report_results(file_rows, finding_rows))
    end = datetime(2026, 11, 19, tzinfo=UTC)
    rr.get_source_report_data(pool, "x", end_date=end)
    sql, params = pool.executed[0]
    assert "fe.created_at < %s" in sql and "fe.created_at <= %s" not in sql
    assert params == ["X", datetime(2026, 11, 20, tzinfo=UTC)]


def test_source_report_findings_timeline_uses_finding_created_at():
    file_rows = [(3, None, None, 0, None, None, None)]
    finding_rows = [(0b11111, None, None, None, None, None, 0)]
    pool = FakePool(_source_report_results(file_rows, finding_rows))
    rr.get_source_report_data(pool, "x")
    findings_sql = pool.executed[1][0]
    assert "DATE(f.created_at) AS day" in findings_sql
    assert "DATE(fe.created_at)" not in findings_sql


def test_source_and_system_reports_count_timeout_as_failed():
    file_rows = [(3, None, None, 0, None, None, None)]
    finding_rows = [(0b11111, None, None, None, None, None, 0)]
    source_pool = FakePool(_source_report_results(file_rows, finding_rows))
    rr.get_source_report_data(source_pool, "x")
    system_pool = FakePool(_system_results([]))
    rr.get_system_report_data(system_pool)
    source_workflow_sql = source_pool.executed[6][0]
    system_workflow_sql = system_pool.executed[6][0]
    for sql in (source_workflow_sql, system_workflow_sql):
        assert "FROM workflows w" in sql
        assert "'TIMEOUT', 'timeout'" in sql
        assert "{FAILED_WORKFLOW_STATUSES_SQL}" not in sql  # f-string actually interpolated


def test_system_report_findings_timeline_uses_finding_created_at():
    pool = FakePool(_system_results([]))
    rr.get_system_report_data(pool, project="p")
    files_sql, files_params = pool.executed[3]
    findings_sql, findings_params = pool.executed[4]
    assert "fe.created_at >= CURRENT_DATE" in files_sql
    assert "DATE(f.created_at) AS day" in findings_sql
    assert "f.created_at >= CURRENT_DATE" in findings_sql
    assert "DATE(fe.created_at)" not in findings_sql
    # the file filters still apply to the findings timeline
    assert "fe.project = %s" in findings_sql
    assert files_params == findings_params == ["p"]


def test_system_report_sources_with_findings_counts_all_sources():
    """The counts cover every source, not only the `sources_limit` most recent ones."""
    rows = [(f"H{i}", 1, 1, NOW - timedelta(minutes=i), 1 if i >= 60 else 0, 1 if i >= 75 else 0) for i in range(80)]
    rows.append((None, 3, 0, NOW - timedelta(days=9), 5, 5))  # NULL source is not a source
    report = rr.get_system_report_data(FakePool(_system_results(rows)))
    assert len(report.sources) == 50
    assert all(s.finding_count == 0 for s in report.sources)  # the listed 50 have no findings
    assert report.summary["sources_with_findings"] == 20
    assert report.summary["sources_with_verified_findings"] == 5


def test_system_report_sources_with_findings_empty():
    report = rr.get_system_report_data(FakePool(_system_results([])))
    assert report.summary["sources_with_findings"] == 0
    assert report.summary["sources_with_verified_findings"] == 0


def test_system_report_template_uses_summary_source_counts():
    from web_api.pdf_generator import render_system_report_html

    rows = [(f"H{i}", 1, 1, NOW - timedelta(minutes=i), 1 if i >= 60 else 0, 1 if i >= 77 else 0) for i in range(80)]
    report = rr.get_system_report_data(FakePool(_system_results(rows)))
    html = render_system_report_html(report.model_dump())
    assert '<div class="stat-value">20</div>' in html
    assert '<div class="stat-value danger">3</div>' in html


def test_system_report_template_falls_back_to_listed_sources_without_summary_counts():
    from web_api.pdf_generator import render_system_report_html

    data = rr.get_system_report_data(FakePool(_system_results(_source_rows()))).model_dump()
    del data["summary"]["sources_with_findings"]
    del data["summary"]["sources_with_verified_findings"]
    html = render_system_report_html(data)
    assert "Sources with Findings" in html
    assert '<div class="stat-value">1</div>' in html  # only HOST-B has findings


def test_source_report_template_shows_untriaged_count():
    from web_api.pdf_generator import render_source_report_html

    file_rows = [(3, None, None, 2, Decimal(10), NOW, NOW)]
    finding_rows = [(0b11111, None, None, None, None, None, 9), (0b11101, None, None, None, None, None, 7)]
    report = rr.get_source_report_data(FakePool(_source_report_results(file_rows, finding_rows)), "host")
    assert report.summary["untriaged_findings"] == 7
    html = render_source_report_html(report.model_dump())
    assert '<div class="stat-value warning">7</div>' in html


def test_source_report_template_untriaged_zero_is_shown_not_blank():
    from web_api.pdf_generator import render_source_report_html

    file_rows = [(3, None, None, 0, None, None, None)]
    finding_rows = [(0b11111, None, None, None, None, None, 0)]
    report = rr.get_source_report_data(FakePool(_source_report_results(file_rows, finding_rows)), "host")
    html = render_source_report_html(report.model_dump())
    assert '<div class="stat-value warning">0</div>' in html
    assert '<div class="stat-value warning"></div>' not in html


def test_source_report_dpapi_counts_are_scoped_to_the_sources_projects():
    """DPAPI masterkeys have a project but no source: only the projects this source has files in are counted."""
    file_rows = [(3, None, None, 0, None, None, None)]
    finding_rows = [(0b11111, None, None, None, None, None, 0)]
    pool = FakePool(_source_report_results(file_rows, finding_rows))
    rr.get_source_report_data(pool, "host-a")
    sql, params = pool.executed[4]
    assert "FROM dpapi.masterkeys" in sql
    assert "project IN (SELECT DISTINCT project FROM files_enriched WHERE UPPER(source) = %s)" in sql
    assert params == ["HOST-A"]

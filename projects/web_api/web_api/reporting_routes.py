"""
Reporting routes for Nemesis web API.

These routes provide comprehensive reporting and analytics for files, findings, and sources.

Scale notes: these reports run against tables with millions of files and hundreds of thousands
of findings, so every query here is written to make a single pass over each table it touches:
- the "latest triage value" of a finding is looked up once per finding (DISTINCT ON / LATERAL on
  idx_findings_triage_history_composite) instead of via correlated EXISTS + MAX() subqueries;
- per-source/category/severity/... breakdowns are computed with GROUPING SETS in one scan;
- source filters use UPPER(source), which is backed by idx_files_enriched_upper_source.
"""

from datetime import UTC, date, datetime, timedelta
from typing import Any

from common.logger import get_logger
from psycopg import Connection
from psycopg.rows import TupleRow
from psycopg_pool import ConnectionPool
from web_api.models.responses import (
    RiskIndicators,
    SourceReport,
    SourceSummary,
    SystemReport,
    TopFinding,
)

logger = get_logger(__name__)

TIMELINE_DAYS = 14

# Latest triage value per finding (ties on timestamp broken by the newest history row).
LATEST_TRIAGE_CTE = """
    latest_triage AS (
        SELECT DISTINCT ON (finding_id) finding_id, value
        FROM findings_triage_history
        ORDER BY finding_id, timestamp DESC, id DESC
    )
"""

# Latest triage value for one finding `f`, for use in a LEFT JOIN LATERAL.
LATEST_TRIAGE_LATERAL = """
    LEFT JOIN LATERAL (
        SELECT fth.value
        FROM findings_triage_history fth
        WHERE fth.finding_id = f.finding_id
        ORDER BY fth.timestamp DESC, fth.id DESC
        LIMIT 1
    ) lt ON true
"""

SEVERITY_LEVEL_SQL = """
    CASE
        WHEN f.severity >= 9 THEN 'critical'
        WHEN f.severity >= 7 THEN 'high'
        WHEN f.severity >= 4 THEN 'medium'
        WHEN f.severity >= 2 THEN 'low'
        ELSE 'informational'
    END
"""


def _file_filters(
    project: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> tuple[list[str], list[Any]]:
    """Build WHERE conditions (on alias `fe` = files_enriched) for the common report filters."""
    conditions: list[str] = []
    params: list[Any] = []
    if project:
        conditions.append("fe.project = %s")
        params.append(project)
    if start_date:
        conditions.append("fe.created_at >= %s")
        params.append(start_date)
    if end_date:
        conditions.append("fe.created_at <= %s")
        params.append(end_date)
    return conditions, params


def _where(conditions: list[str]) -> str:
    return " AND ".join(conditions) if conditions else "TRUE"


def _timeline_days(today: date) -> list[date]:
    return [today - timedelta(days=offset) for offset in range(TIMELINE_DAYS - 1, -1, -1)]


def _source_stats(
    cur, conditions: list[str], params: list[Any]
) -> list[tuple[str | None, int, int | None, Any, int, int]]:
    """Per-source (UPPER(source), NULL included) file and finding statistics in two table scans.

    Returns rows of (source, file_count, total_size, last_activity, finding_count, verified_findings).
    """
    where = _where(conditions)
    # Join key that is never NULL (so the two aggregates hash-join; IS NOT DISTINCT FROM would force
    # a nested loop over sources x sources) while keeping NULL and '' sources apart.
    source_key = "CASE WHEN fe.source IS NULL THEN 'N' ELSE 'S' || UPPER(fe.source) END"
    cur.execute(
        f"""
        WITH {LATEST_TRIAGE_CTE},
        file_stats AS (
            SELECT {source_key} AS source_key,
                   MIN(UPPER(fe.source)) AS source,
                   COUNT(*) AS file_count,
                   SUM(fe.size) AS total_size,
                   MAX(fe.created_at) AS last_activity
            FROM files_enriched fe
            WHERE {where}
            GROUP BY 1
        ),
        finding_stats AS (
            SELECT {source_key} AS source_key,
                   COUNT(*) AS finding_count,
                   COUNT(*) FILTER (WHERE lt.value = 'true_positive') AS verified_findings
            FROM findings f
            JOIN files_enriched fe ON fe.object_id = f.object_id
            LEFT JOIN latest_triage lt ON lt.finding_id = f.finding_id
            WHERE {where}
            GROUP BY 1
        )
        SELECT fs.source, fs.file_count, fs.total_size, fs.last_activity,
               COALESCE(fi.finding_count, 0), COALESCE(fi.verified_findings, 0)
        FROM file_stats fs
        LEFT JOIN finding_stats fi ON fi.source_key = fs.source_key
        ORDER BY fs.last_activity DESC NULLS LAST, fs.source
        """,
        params + params,
    )
    return cur.fetchall()


def _to_source_summaries(rows, limit: int | None = None) -> list[SourceSummary]:
    sources = [
        SourceSummary(
            source=row[0],
            file_count=row[1],
            finding_count=row[4],
            verified_findings=row[5],
            last_activity=row[3],
        )
        for row in rows
        if row[0] is not None
    ]
    return sources[:limit] if limit is not None else sources


def get_sources_list(
    pool: ConnectionPool[Connection[TupleRow]],
    project: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> list[SourceSummary]:
    """Get list of all sources with summary statistics (most recently active first)."""
    conditions, params = _file_filters(project, start_date, end_date)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            return _to_source_summaries(_source_stats(cur, conditions, params))


def get_dashboard_stats(pool: ConnectionPool[Connection[TupleRow]]) -> dict[str, Any]:
    """File counts and findings triage counts for the dashboard, each computed in a single scan.

    (Separate Hasura aggregates scanned files_enriched four times; the latest-triage breakdown
    previously required downloading every finding's latest triage row to the browser.)
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    COUNT(*),
                    COUNT(*) FILTER (WHERE fe.originating_object_id IS NULL),
                    COUNT(*) FILTER (WHERE fe.is_container),
                    COUNT(*) FILTER (
                        WHERE (fe.originating_object_id IS NULL OR fe.nesting_level > 0) AND viewed.object_id IS NULL
                    )
                FROM files_enriched fe
                LEFT JOIN (SELECT DISTINCT object_id FROM files_view_history) viewed
                    ON viewed.object_id = fe.object_id
                """
            )
            file_row = cur.fetchone() or (0, 0, 0, 0)

    return {
        "files": {
            "total": file_row[0],
            "submitted": file_row[1],
            "derived": file_row[0] - file_row[1],
            "containers": file_row[2],
            "unviewed": file_row[3],
        },
        "triage": get_triage_summary(pool),
    }


def get_triage_summary(pool: ConnectionPool[Connection[TupleRow]]) -> dict[str, Any]:
    """Count findings by their latest triage value (plus the number never triaged)."""
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                WITH {LATEST_TRIAGE_CTE}
                SELECT value, COUNT(*) FROM latest_triage GROUP BY value
                """
            )
            counts: dict[str, int] = {row[0]: row[1] for row in cur.fetchall()}
            cur.execute(
                """
                SELECT COUNT(*) FROM findings f
                WHERE NOT EXISTS (SELECT 1 FROM findings_triage_history h WHERE h.finding_id = f.finding_id)
                """
            )
            row = cur.fetchone()
            untriaged = row[0] if row else 0

    return {
        "true_positive": counts.get("true_positive", 0),
        "false_positive": counts.get("false_positive", 0),
        "needs_review": counts.get("needs_review", 0),
        "untriaged": untriaged,
        "by_value": counts,
    }


def get_source_report_data(
    pool: ConnectionPool[Connection[TupleRow]],
    source_name: str,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> SourceReport:
    """Get detailed report for a specific source."""
    # Normalize source name to uppercase for matching
    source_name_upper = source_name.upper()

    date_conditions, date_params = _file_filters(None, start_date, end_date)
    conditions = ["UPPER(fe.source) = %s", *date_conditions]
    params: list[Any] = [source_name_upper, *date_params]
    where = _where(conditions)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            # --- Files: totals, per-extension and per-day counts in one scan ---
            cur.execute(
                f"""
                SELECT GROUPING(fe.extension, DATE(fe.created_at)) AS grp,
                       fe.extension,
                       DATE(fe.created_at) AS day,
                       COUNT(*),
                       SUM(fe.size),
                       MIN(fe.created_at),
                       MAX(fe.created_at)
                FROM files_enriched fe
                WHERE {where}
                GROUP BY GROUPING SETS ((), (fe.extension), (DATE(fe.created_at)))
                """,
                params,
            )
            total_files, total_size, first_seen, last_seen = 0, 0, None, None
            extension_counts: list[tuple[str | None, int]] = []
            files_per_day: dict[date, int] = {}
            for grp, extension, day, count, size_sum, min_created, max_created in cur.fetchall():
                if grp == 3:  # grand total
                    total_files, total_size, first_seen, last_seen = count, size_sum, min_created, max_created
                elif grp == 1:  # grouped by extension
                    extension_counts.append((extension, count))
                else:  # grouped by day
                    files_per_day[day] = count
            extension_counts.sort(key=lambda item: item[1], reverse=True)
            unique_extensions = sum(1 for extension, _ in extension_counts if extension is not None)
            file_types = {(extension or "unknown"): count for extension, count in extension_counts[:20]}

            # --- Findings: totals and breakdowns in one scan ---
            cur.execute(
                f"""
                SELECT GROUPING(x.category, x.severity_level, x.origin_name, x.triage_value, x.day) AS grp,
                       x.category, x.severity_level, x.origin_name, x.triage_value, x.day, COUNT(*)
                FROM (
                    SELECT f.category,
                           {SEVERITY_LEVEL_SQL} AS severity_level,
                           f.origin_name,
                           lt.value AS triage_value,
                           DATE(fe.created_at) AS day
                    FROM files_enriched fe
                    JOIN findings f ON f.object_id = fe.object_id
                    {LATEST_TRIAGE_LATERAL}
                    WHERE {where}
                ) x
                GROUP BY GROUPING SETS ((), (x.category), (x.severity_level), (x.origin_name), (x.triage_value), (x.day))
                """,
                params,
            )
            total_findings = 0
            by_category: list[tuple[str, int]] = []
            by_severity: list[tuple[str, int]] = []
            by_origin: list[tuple[str, int]] = []
            triage_counts: dict[str | None, int] = {}
            findings_per_day: dict[date, int] = {}
            # GROUPING() bitmask: bit set = column NOT part of the grouping set (category is the MSB).
            for grp, category, severity_level, origin_name, triage_value, day, count in cur.fetchall():
                if grp == 0b11111:
                    total_findings = count
                elif grp == 0b01111:
                    by_category.append((category, count))
                elif grp == 0b10111:
                    by_severity.append((severity_level, count))
                elif grp == 0b11011:
                    by_origin.append((origin_name, count))
                elif grp == 0b11101:
                    triage_counts[triage_value] = count
                elif grp == 0b11110:
                    findings_per_day[day] = count
            findings_by_category = dict(sorted(by_category, key=lambda item: item[1], reverse=True))
            findings_by_severity = dict(sorted(by_severity, key=lambda item: item[1], reverse=True))
            findings_by_origin = dict(sorted(by_origin, key=lambda item: item[1], reverse=True))
            true_positives = triage_counts.get("true_positive", 0)
            false_positives = triage_counts.get("false_positive", 0)
            needs_review = triage_counts.get("needs_review", 0)
            untriaged = triage_counts.get(None, 0)
            titus_count = findings_by_origin.get("titus", 0)
            yara_count = findings_by_origin.get("yara_scanner", 0)

            # --- Credential risk indicators ---
            cur.execute(
                """
                SELECT
                    COUNT(*) as total_logins,
                    COUNT(CASE WHEN is_decrypted = true THEN 1 END) as decrypted_logins
                FROM chromium.logins
                WHERE UPPER(source) = %s
            """,
                [source_name_upper],
            )
            chromium_row = cur.fetchone() or (0, 0)

            cur.execute(
                """
                SELECT
                    COUNT(*) as total_cookies,
                    COUNT(CASE WHEN is_decrypted = true THEN 1 END) as decrypted_cookies
                FROM chromium.cookies
                WHERE UPPER(source) = %s
            """,
                [source_name_upper],
            )
            cookies_row = cur.fetchone() or (0, 0)

            # DPAPI masterkeys (not source-specific in current schema)
            cur.execute(
                """
                SELECT
                    COUNT(*) as total_keys,
                    COUNT(CASE WHEN plaintext_key IS NOT NULL THEN 1 END) as decrypted_keys
                FROM dpapi.masterkeys
            """,
            )
            dpapi_row = cur.fetchone() or (0, 0)

            # --- Top findings (verified true positives first, then by severity, then newest) ---
            cur.execute(
                f"""
                SELECT f.finding_id, f.finding_name, f.category, f.severity, lt.value, fe.path, f.created_at
                FROM files_enriched fe
                JOIN findings f ON f.object_id = fe.object_id
                {LATEST_TRIAGE_LATERAL}
                WHERE {where}
                ORDER BY (lt.value = 'true_positive') IS NOT TRUE, f.severity DESC, f.created_at DESC
                LIMIT 20
                """,
                params,
            )
            top_findings = cur.fetchall()

            # --- Enrichment performance ---
            cur.execute(
                """
                SELECT
                    COUNT(*) as total_workflows,
                    COUNT(CASE WHEN status IN ('COMPLETED', 'completed') THEN 1 END) as completed,
                    COUNT(CASE WHEN status IN ('FAILED', 'failed', 'ERROR', 'error', 'TIMEOUT', 'timeout') THEN 1 END) as failed,
                    AVG(runtime_seconds) as avg_processing_time,
                    MAX(runtime_seconds) as max_processing_time
                FROM workflows w
                JOIN files_enriched fe ON w.object_id = fe.object_id
                WHERE UPPER(fe.source) = %s
            """,
                [source_name_upper],
            )
            workflow_row = cur.fetchone() or (0, 0, 0, None, None)

            cur.execute("SELECT CURRENT_DATE")
            today_row = cur.fetchone()
            today = today_row[0] if today_row else datetime.now(UTC).date()

    # Timeline data (last 14 days)
    daily_activity = [
        {
            "date": day.isoformat(),
            "files_submitted": files_per_day.get(day, 0),
            "findings_created": findings_per_day.get(day, 0),
        }
        for day in _timeline_days(today)
    ]

    return SourceReport(
        report_type="source",
        source=source_name_upper,
        generated_at=datetime.now(UTC),
        summary={
            "total_files": total_files or 0,
            "unique_extensions": unique_extensions,
            "total_size_bytes": total_size or 0,
            "first_seen": first_seen.isoformat() if first_seen else None,
            "last_seen": last_seen.isoformat() if last_seen else None,
            "file_types": file_types,
            "total_findings": total_findings,
            "verified_true_positives": true_positives,
            "verified_false_positives": false_positives,
            "needs_review_findings": needs_review,
            "untriaged_findings": untriaged,
        },
        risk_indicators=RiskIndicators(
            credentials={
                "chromium_logins": chromium_row[0] or 0,
                "chromium_logins_decrypted": chromium_row[1] or 0,
                "chromium_cookies": cookies_row[0] or 0,
                "chromium_cookies_decrypted": cookies_row[1] or 0,
                "dpapi_masterkeys": dpapi_row[0] or 0,
                "dpapi_masterkeys_decrypted": dpapi_row[1] or 0,
                "titus_findings": titus_count,
            },
            sensitive_data={
                "yara_matches": yara_count,
            },
        ),
        findings_detail={
            "by_category": findings_by_category,
            "by_severity": findings_by_severity,
            "by_origin": findings_by_origin,
            "triage_breakdown": {
                "true_positive": true_positives,
                "false_positive": false_positives,
                "needs_review": needs_review,
                "untriaged": untriaged,
            },
        },
        timeline={"daily_activity": daily_activity},
        enrichment_performance={
            "workflows_total": workflow_row[0] or 0,
            "workflows_completed": workflow_row[1] or 0,
            "workflows_failed": workflow_row[2] or 0,
            "avg_processing_time": float(workflow_row[3]) if workflow_row[3] else 0.0,
            "max_processing_time": float(workflow_row[4]) if workflow_row[4] else 0.0,
        },
        top_findings=[
            TopFinding(
                finding_id=row[0],
                finding_name=row[1],
                category=row[2],
                severity=row[3],
                triage_state=row[4],
                file_path=row[5],
                created_at=row[6],
            )
            for row in top_findings
        ],
    )


def get_system_report_data(
    pool: ConnectionPool[Connection[TupleRow]],
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    project: str | None = None,
) -> SystemReport:
    """Get system-wide statistics and findings."""
    conditions, params = _file_filters(project, start_date, end_date)
    where = _where(conditions)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            # Per-source stats (NULL source included) -> overall summary + top 50 sources
            source_rows = _source_stats(cur, conditions, params)
            total_sources = sum(1 for row in source_rows if row[0] is not None)
            total_files = sum(row[1] for row in source_rows)
            total_size = sum(row[2] or 0 for row in source_rows)
            total_findings = sum(row[4] for row in source_rows)
            verified_true_positives = sum(row[5] for row in source_rows)

            # Credentials summary
            cur.execute(
                """
                SELECT
                    COUNT(*) as total_chromium_logins,
                    COUNT(CASE WHEN is_decrypted = true THEN 1 END) as decrypted_logins
                FROM chromium.logins
            """,
            )
            creds_row = cur.fetchone() or (0, 0)

            # Findings by category and severity in one scan. Every finding references a
            # files_enriched row (FK), so the join is only needed when filtering on file columns.
            findings_from = (
                "findings f JOIN files_enriched fe ON fe.object_id = f.object_id" if conditions else "findings f"
            )
            cur.execute(
                f"""
                SELECT GROUPING(x.category, x.severity_level) AS grp, x.category, x.severity_level, COUNT(*)
                FROM (
                    SELECT f.category, {SEVERITY_LEVEL_SQL} AS severity_level
                    FROM {findings_from}
                    WHERE {where}
                ) x
                GROUP BY GROUPING SETS ((x.category), (x.severity_level))
                """,
                params,
            )
            by_category: list[tuple[str, int]] = []
            findings_by_severity: dict[str, int] = {}
            for grp, category, severity_level, count in cur.fetchall():
                if grp == 0b01:
                    by_category.append((category, count))
                else:
                    findings_by_severity[severity_level] = count
            findings_by_category = dict(sorted(by_category, key=lambda item: item[1], reverse=True))

            # Timeline data (last 14 days): files submitted per day and findings on those files
            # (two plain GROUP BYs are much cheaper than one join of all recent files to findings)
            recent = f"fe.created_at >= CURRENT_DATE - {TIMELINE_DAYS - 1} AND {where}"
            cur.execute(
                f"""
                SELECT DATE(fe.created_at) AS day, COUNT(*)
                FROM files_enriched fe
                WHERE {recent}
                GROUP BY 1
                """,
                params,
            )
            files_per_day: dict[date, int] = dict(cur.fetchall())
            cur.execute(
                f"""
                SELECT DATE(fe.created_at) AS day, COUNT(*)
                FROM findings f
                JOIN files_enriched fe ON fe.object_id = f.object_id
                WHERE {recent}
                GROUP BY 1
                """,
                params,
            )
            findings_per_day: dict[date, int] = dict(cur.fetchall())
            cur.execute("SELECT CURRENT_DATE")
            today_row = cur.fetchone()
            today = today_row[0] if today_row else datetime.now(UTC).date()

            # Enrichment stats
            cur.execute(
                f"""
                SELECT
                    COUNT(*) as total_workflows,
                    COUNT(CASE WHEN w.status IN ('COMPLETED', 'completed') THEN 1 END) as successful,
                    COUNT(CASE WHEN w.status IN ('FAILED', 'failed', 'ERROR', 'error') THEN 1 END) as failed,
                    AVG(w.runtime_seconds) as avg_processing_time
                FROM workflows w
                JOIN files_enriched fe ON w.object_id = fe.object_id
                WHERE {where}
            """,
                params,
            )
            enrichment_row = cur.fetchone() or (0, 0, 0, None)

    # Determine time range
    if start_date and end_date:
        time_range = {"start": start_date, "end": end_date}
    elif start_date:
        time_range = {"start": start_date, "end": datetime.now(UTC)}
    elif end_date:
        time_range = {"start": datetime.min.replace(tzinfo=UTC), "end": end_date}
    else:
        time_range = {"start": datetime.min.replace(tzinfo=UTC), "end": datetime.now(UTC)}

    return SystemReport(
        report_type="system",
        generated_at=datetime.now(UTC),
        time_range=time_range,
        summary={
            "total_sources": total_sources,
            "total_files": total_files,
            "total_size_bytes": total_size,
            "total_findings": total_findings,
            "verified_true_positives": verified_true_positives,
            "total_credentials": creds_row[0] or 0,
            "decrypted_credentials": creds_row[1] or 0,
        },
        sources=_to_source_summaries(source_rows, limit=50),
        findings_by_category=findings_by_category,
        findings_by_severity=findings_by_severity,
        timeline={
            "daily_activity": [
                {
                    "date": day.isoformat(),
                    "files_submitted": files_per_day.get(day, 0),
                    "findings_created": findings_per_day.get(day, 0),
                }
                for day in _timeline_days(today)
            ]
        },
        enrichment_stats={
            "total_workflows": enrichment_row[0] or 0,
            "successful": enrichment_row[1] or 0,
            "failed": enrichment_row[2] or 0,
            "avg_processing_time": float(enrichment_row[3]) if enrichment_row[3] else 0.0,
        },
    )

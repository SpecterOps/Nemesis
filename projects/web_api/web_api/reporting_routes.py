"""
Reporting routes for Nemesis web API.

These routes provide comprehensive reporting and analytics for files, findings, and sources.
"""

import asyncio
from datetime import UTC, datetime

from common.logger import get_logger
from fastapi import HTTPException, Query
from psycopg_pool import ConnectionPool
from web_api.models.responses import (
    RiskIndicators,
    SourceReport,
    SourceSummary,
    SystemReport,
    TopFinding,
)

logger = get_logger(__name__)


def get_sources_list(
    pool: ConnectionPool,
    project: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> list[SourceSummary]:
    """Get list of all sources with summary statistics."""
    with pool.connection() as conn:
        with conn.cursor() as cur:
            # Build WHERE clause conditions
            conditions = []
            params = []

            if project:
                conditions.append("fe.project = %s")
                params.append(project)

            if start_date:
                conditions.append("fe.created_at >= %s")
                params.append(start_date)

            if end_date:
                conditions.append("fe.created_at <= %s")
                params.append(end_date)

            where_clause = " AND ".join(conditions) if conditions else "1=1"

            # Query to get source summaries
            # Normalize source to uppercase for consistency
            # Use LEFT JOINs to include sources even if they have no findings or triage data
            query = f"""
                SELECT
                    UPPER(fe.source) as source,
                    COUNT(DISTINCT fe.object_id) as file_count,
                    COUNT(DISTINCT f.finding_id) as finding_count,
                    COUNT(DISTINCT CASE
                        WHEN EXISTS (
                            SELECT 1 FROM findings_triage_history fth
                            WHERE fth.finding_id = f.finding_id
                            AND fth.value = 'true_positive'
                            AND fth.timestamp = (
                                SELECT MAX(timestamp) FROM findings_triage_history
                                WHERE finding_id = f.finding_id
                            )
                        ) THEN f.finding_id
                    END) as verified_findings,
                    MAX(fe.created_at) as last_activity
                FROM files_enriched fe
                LEFT JOIN findings f ON fe.object_id = f.object_id
                WHERE {where_clause} AND fe.source IS NOT NULL
                GROUP BY UPPER(fe.source)
                ORDER BY last_activity DESC NULLS LAST
            """

            cur.execute(query, params)
            results = cur.fetchall()

            sources = []
            for row in results:
                sources.append(
                    SourceSummary(
                        source=row[0],
                        file_count=row[1],
                        finding_count=row[2],
                        verified_findings=row[3],
                        last_activity=row[4],
                    )
                )

            return sources


def get_source_report_data(
    pool: ConnectionPool,
    source_name: str,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> SourceReport:
    """Get detailed report for a specific source."""
    # Normalize source name to uppercase for matching
    source_name_upper = source_name.upper()

    with pool.connection() as conn:
        with conn.cursor() as cur:
            # Build WHERE clause for date filtering
            date_conditions = []
            date_params = [source_name_upper]

            if start_date:
                date_conditions.append("fe.created_at >= %s")
                date_params.append(start_date)

            if end_date:
                date_conditions.append("fe.created_at <= %s")
                date_params.append(end_date)

            date_where = " AND ".join(date_conditions) if date_conditions else "1=1"

            # Summary statistics
            cur.execute(
                f"""
                SELECT
                    COUNT(DISTINCT object_id) as total_files,
                    COUNT(DISTINCT CASE WHEN extension IS NOT NULL THEN extension END) as unique_extensions,
                    SUM(size) as total_size,
                    MIN(created_at) as first_seen,
                    MAX(created_at) as last_seen
                FROM files_enriched
                WHERE UPPER(source) = %s AND {date_where}
            """,
                date_params,
            )
            summary_row = cur.fetchone()

            # File type breakdown
            cur.execute(
                f"""
                SELECT extension, COUNT(*) as count
                FROM files_enriched
                WHERE UPPER(source) = %s AND {date_where}
                GROUP BY extension
                ORDER BY count DESC
                LIMIT 20
            """,
                date_params,
            )
            file_types = {row[0] or "unknown": row[1] for row in cur.fetchall()}

            # Findings statistics with triage breakdown
            # Use LEFT JOIN and subquery to get latest triage value per finding
            cur.execute(
                f"""
                SELECT
                    COUNT(DISTINCT f.finding_id) as total_findings,
                    COUNT(DISTINCT CASE
                        WHEN EXISTS (
                            SELECT 1 FROM findings_triage_history fth
                            WHERE fth.finding_id = f.finding_id
                            AND fth.value = 'true_positive'
                            AND fth.timestamp = (SELECT MAX(timestamp) FROM findings_triage_history WHERE finding_id = f.finding_id)
                        ) THEN f.finding_id
                    END) as true_positives,
                    COUNT(DISTINCT CASE
                        WHEN EXISTS (
                            SELECT 1 FROM findings_triage_history fth
                            WHERE fth.finding_id = f.finding_id
                            AND fth.value = 'false_positive'
                            AND fth.timestamp = (SELECT MAX(timestamp) FROM findings_triage_history WHERE finding_id = f.finding_id)
                        ) THEN f.finding_id
                    END) as false_positives,
                    COUNT(DISTINCT CASE
                        WHEN EXISTS (
                            SELECT 1 FROM findings_triage_history fth
                            WHERE fth.finding_id = f.finding_id
                            AND fth.value = 'needs_review'
                            AND fth.timestamp = (SELECT MAX(timestamp) FROM findings_triage_history WHERE finding_id = f.finding_id)
                        ) THEN f.finding_id
                    END) as needs_review,
                    COUNT(DISTINCT CASE
                        WHEN NOT EXISTS (
                            SELECT 1 FROM findings_triage_history fth
                            WHERE fth.finding_id = f.finding_id
                        ) THEN f.finding_id
                    END) as untriaged
                FROM files_enriched fe
                LEFT JOIN findings f ON fe.object_id = f.object_id
                WHERE UPPER(fe.source) = %s AND {date_where} AND f.finding_id IS NOT NULL
            """,
                date_params,
            )
            findings_row = cur.fetchone()

            # Handle case where there are no findings at all
            if not findings_row or findings_row[0] is None:
                findings_row = (0, 0, 0, 0, 0)

            # Findings by category
            cur.execute(
                f"""
                SELECT f.category, COUNT(*) as count
                FROM files_enriched fe
                JOIN findings f ON fe.object_id = f.object_id
                WHERE UPPER(fe.source) = %s AND {date_where}
                GROUP BY f.category
                ORDER BY count DESC
            """,
                date_params,
            )
            findings_by_category = {row[0]: row[1] for row in cur.fetchall()}

            # Findings by severity
            cur.execute(
                f"""
                SELECT
                    CASE
                        WHEN f.severity >= 9 THEN 'critical'
                        WHEN f.severity >= 7 THEN 'high'
                        WHEN f.severity >= 4 THEN 'medium'
                        WHEN f.severity >= 2 THEN 'low'
                        ELSE 'informational'
                    END as severity_level,
                    COUNT(*) as count
                FROM files_enriched fe
                JOIN findings f ON fe.object_id = f.object_id
                WHERE UPPER(fe.source) = %s AND {date_where}
                GROUP BY severity_level
                ORDER BY count DESC
            """,
                date_params,
            )
            findings_by_severity = {row[0]: row[1] for row in cur.fetchall()}

            # Findings by origin
            cur.execute(
                f"""
                SELECT f.origin_name, COUNT(*) as count
                FROM files_enriched fe
                JOIN findings f ON fe.object_id = f.object_id
                WHERE UPPER(fe.source) = %s AND {date_where}
                GROUP BY f.origin_name
                ORDER BY count DESC
            """,
                date_params,
            )
            findings_by_origin = {row[0]: row[1] for row in cur.fetchall()}

            # Credential risk indicators
            # Chromium logins
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
            chromium_row = cur.fetchone()

            # Chromium cookies
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
            cookies_row = cur.fetchone()

            # DPAPI masterkeys (not source-specific in current schema)
            cur.execute(
                """
                SELECT
                    COUNT(*) as total_keys,
                    COUNT(CASE WHEN plaintext_key IS NOT NULL THEN 1 END) as decrypted_keys
                FROM dpapi.masterkeys
            """,
            )
            dpapi_row = cur.fetchone()

            # NoseyParker findings
            cur.execute(
                f"""
                SELECT COUNT(*)
                FROM files_enriched fe
                JOIN findings f ON fe.object_id = f.object_id
                WHERE UPPER(fe.source) = %s AND f.origin_name = 'noseyparker' AND {date_where}
            """,
                date_params,
            )
            noseyparker_count = cur.fetchone()[0]

            # YARA matches
            cur.execute(
                f"""
                SELECT COUNT(*)
                FROM files_enriched fe
                JOIN findings f ON fe.object_id = f.object_id
                WHERE UPPER(fe.source) = %s AND f.origin_name = 'yara_scanner' AND {date_where}
            """,
                date_params,
            )
            yara_count = cur.fetchone()[0]

            # Top findings (verified true positives first, then by severity)
            cur.execute(
                f"""
                SELECT
                    f.finding_id,
                    f.finding_name,
                    f.category,
                    f.severity,
                    (SELECT fth.value FROM findings_triage_history fth
                     WHERE fth.finding_id = f.finding_id
                     ORDER BY fth.timestamp DESC LIMIT 1) as triage_state,
                    fe.path,
                    f.created_at
                FROM files_enriched fe
                JOIN findings f ON fe.object_id = f.object_id
                WHERE UPPER(fe.source) = %s AND {date_where}
                ORDER BY
                    CASE WHEN (SELECT fth.value FROM findings_triage_history fth
                               WHERE fth.finding_id = f.finding_id
                               ORDER BY fth.timestamp DESC LIMIT 1) = 'true_positive' THEN 0
                         ELSE 1 END,
                    f.severity DESC,
                    f.created_at DESC
                LIMIT 20
            """,
                date_params,
            )
            top_findings = cur.fetchall()

            # Timeline data (last 14 days)
            cur.execute(
                f"""
                WITH date_series AS (
                    SELECT generate_series(
                        CURRENT_DATE - INTERVAL '13 days',
                        CURRENT_DATE,
                        '1 day'::interval
                    )::date as date
                )
                SELECT
                    ds.date,
                    COUNT(DISTINCT fe.object_id) as files_submitted,
                    COUNT(DISTINCT f.finding_id) as findings_created
                FROM date_series ds
                LEFT JOIN files_enriched fe ON DATE(fe.created_at) = ds.date AND UPPER(fe.source) = %s
                LEFT JOIN findings f ON fe.object_id = f.object_id
                GROUP BY ds.date
                ORDER BY ds.date
            """,
                [source_name_upper],
            )
            timeline_data = cur.fetchall()

            # Enrichment performance
            cur.execute(
                f"""
                SELECT
                    COUNT(*) as total_workflows,
                    COUNT(CASE WHEN status IN ('COMPLETED', 'completed') THEN 1 END) as completed,
                    COUNT(CASE WHEN status IN ('FAILED', 'failed', 'ERROR', 'error', 'TERMINATED', 'terminated') THEN 1 END) as failed,
                    AVG(runtime_seconds) as avg_processing_time,
                    MAX(runtime_seconds) as max_processing_time
                FROM workflows w
                JOIN files_enriched fe ON w.object_id = fe.object_id
                WHERE UPPER(fe.source) = %s
            """,
                [source_name_upper],
            )
            workflow_row = cur.fetchone()

            # Build the response
            report = SourceReport(
                report_type="source",
                source=source_name_upper,
                generated_at=datetime.now(UTC),
                summary={
                    "total_files": summary_row[0] or 0,
                    "unique_extensions": summary_row[1] or 0,
                    "total_size_bytes": summary_row[2] or 0,
                    "first_seen": summary_row[3].isoformat() if summary_row[3] else None,
                    "last_seen": summary_row[4].isoformat() if summary_row[4] else None,
                    "file_types": file_types,
                    "total_findings": findings_row[0] or 0,
                    "verified_true_positives": findings_row[1] or 0,
                    "verified_false_positives": findings_row[2] or 0,
                    "needs_review_findings": findings_row[3] or 0,
                    "untriaged_findings": findings_row[4] or 0,
                },
                risk_indicators=RiskIndicators(
                    credentials={
                        "chromium_logins": chromium_row[0] or 0,
                        "chromium_logins_decrypted": chromium_row[1] or 0,
                        "chromium_cookies": cookies_row[0] or 0,
                        "chromium_cookies_decrypted": cookies_row[1] or 0,
                        "dpapi_masterkeys": dpapi_row[0] or 0,
                        "dpapi_masterkeys_decrypted": dpapi_row[1] or 0,
                        "noseyparker_findings": noseyparker_count,
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
                        "true_positive": findings_row[1] or 0,
                        "false_positive": findings_row[2] or 0,
                        "needs_review": findings_row[3] or 0,
                        "untriaged": findings_row[4] or 0,
                    },
                },
                timeline={
                    "daily_activity": [
                        {"date": row[0].isoformat(), "files_submitted": row[1] or 0, "findings_created": row[2] or 0}
                        for row in timeline_data
                    ]
                },
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

            return report


def get_system_report_data(
    pool: ConnectionPool,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    project: str | None = None,
) -> SystemReport:
    """Get system-wide statistics and findings."""
    with pool.connection() as conn:
        with conn.cursor() as cur:
            # Build WHERE clause
            conditions = []
            params = []

            if project:
                conditions.append("project = %s")
                params.append(project)

            if start_date:
                conditions.append("created_at >= %s")
                params.append(start_date)

            if end_date:
                conditions.append("created_at <= %s")
                params.append(end_date)

            where_clause = " AND ".join(conditions) if conditions else "1=1"

            # Overall summary
            cur.execute(
                f"""
                SELECT
                    COUNT(DISTINCT UPPER(source)) as total_sources,
                    COUNT(DISTINCT object_id) as total_files,
                    SUM(size) as total_size
                FROM files_enriched
                WHERE {where_clause}
            """,
                params,
            )
            summary_row = cur.fetchone()

            # Findings summary
            cur.execute(
                f"""
                SELECT
                    COUNT(DISTINCT f.finding_id) as total_findings,
                    COUNT(DISTINCT CASE
                        WHEN EXISTS (
                            SELECT 1 FROM findings_triage_history fth
                            WHERE fth.finding_id = f.finding_id
                            AND fth.value = 'true_positive'
                            AND fth.timestamp = (SELECT MAX(timestamp) FROM findings_triage_history WHERE finding_id = f.finding_id)
                        ) THEN f.finding_id
                    END) as verified_true_positives
                FROM files_enriched fe
                LEFT JOIN findings f ON fe.object_id = f.object_id
                WHERE {where_clause} AND f.finding_id IS NOT NULL
            """,
                params,
            )
            findings_summary_row = cur.fetchone()

            # Handle case where there are no findings
            if not findings_summary_row or findings_summary_row[0] is None:
                findings_summary = (0, 0)
            else:
                findings_summary = findings_summary_row

            # Credentials summary
            cur.execute(
                """
                SELECT
                    COUNT(*) as total_chromium_logins,
                    COUNT(CASE WHEN is_decrypted = true THEN 1 END) as decrypted_logins
                FROM chromium.logins
            """,
            )
            creds_row = cur.fetchone()

            # Sources list (top 50 by activity)
            cur.execute(
                f"""
                SELECT
                    UPPER(fe.source) as source,
                    COUNT(DISTINCT fe.object_id) as file_count,
                    COUNT(DISTINCT f.finding_id) as finding_count,
                    COUNT(DISTINCT CASE
                        WHEN EXISTS (
                            SELECT 1 FROM findings_triage_history fth
                            WHERE fth.finding_id = f.finding_id
                            AND fth.value = 'true_positive'
                            AND fth.timestamp = (
                                SELECT MAX(timestamp) FROM findings_triage_history
                                WHERE finding_id = f.finding_id
                            )
                        ) THEN f.finding_id
                    END) as verified_findings,
                    MAX(fe.created_at) as last_activity
                FROM files_enriched fe
                LEFT JOIN findings f ON fe.object_id = f.object_id
                WHERE {where_clause} AND fe.source IS NOT NULL
                GROUP BY UPPER(fe.source)
                ORDER BY last_activity DESC NULLS LAST
                LIMIT 50
            """,
                params,
            )
            sources_data = cur.fetchall()

            # Findings by category
            cur.execute(
                f"""
                SELECT f.category, COUNT(*) as count
                FROM files_enriched fe
                JOIN findings f ON fe.object_id = f.object_id
                WHERE {where_clause}
                GROUP BY f.category
                ORDER BY count DESC
            """,
                params,
            )
            findings_by_category = dict(cur.fetchall())

            # Findings by severity
            cur.execute(
                f"""
                SELECT
                    CASE
                        WHEN f.severity >= 9 THEN 'critical'
                        WHEN f.severity >= 7 THEN 'high'
                        WHEN f.severity >= 4 THEN 'medium'
                        WHEN f.severity >= 2 THEN 'low'
                        ELSE 'informational'
                    END as severity_level,
                    COUNT(*) as count
                FROM files_enriched fe
                JOIN findings f ON fe.object_id = f.object_id
                WHERE {where_clause}
                GROUP BY severity_level
            """,
                params,
            )
            findings_by_severity = dict(cur.fetchall())

            # Timeline data (last 14 days)
            cur.execute(
                f"""
                WITH date_series AS (
                    SELECT generate_series(
                        CURRENT_DATE - INTERVAL '13 days',
                        CURRENT_DATE,
                        '1 day'::interval
                    )::date as date
                )
                SELECT
                    ds.date,
                    COUNT(DISTINCT fe.object_id) as files_submitted,
                    COUNT(DISTINCT f.finding_id) as findings_created
                FROM date_series ds
                LEFT JOIN files_enriched fe ON DATE(fe.created_at) = ds.date
                LEFT JOIN findings f ON fe.object_id = f.object_id
                WHERE {where_clause}
                GROUP BY ds.date
                ORDER BY ds.date
            """,
                params,
            )
            timeline_data = cur.fetchall()

            # Enrichment stats
            cur.execute(
                f"""
                SELECT
                    COUNT(*) as total_workflows,
                    COUNT(CASE WHEN status IN ('COMPLETED', 'completed') THEN 1 END) as successful,
                    COUNT(CASE WHEN status IN ('FAILED', 'failed', 'ERROR', 'error') THEN 1 END) as failed,
                    AVG(runtime_seconds) as avg_processing_time
                FROM workflows w
                JOIN files_enriched fe ON w.object_id = fe.object_id
                WHERE {where_clause}
            """,
                params,
            )
            enrichment_row = cur.fetchone()

            # Determine time range
            if start_date and end_date:
                time_range = {"start": start_date, "end": end_date}
            elif start_date:
                time_range = {"start": start_date, "end": datetime.now(UTC)}
            elif end_date:
                time_range = {"start": datetime.min.replace(tzinfo=UTC), "end": end_date}
            else:
                time_range = {"start": datetime.min.replace(tzinfo=UTC), "end": datetime.now(UTC)}

            report = SystemReport(
                report_type="system",
                generated_at=datetime.now(UTC),
                time_range=time_range,
                summary={
                    "total_sources": summary_row[0] or 0,
                    "total_files": summary_row[1] or 0,
                    "total_size_bytes": summary_row[2] or 0,
                    "total_findings": findings_summary[0] or 0,
                    "verified_true_positives": findings_summary[1] or 0,
                    "total_credentials": creds_row[0] or 0,
                    "decrypted_credentials": creds_row[1] or 0,
                },
                sources=[
                    SourceSummary(
                        source=row[0],
                        file_count=row[1],
                        finding_count=row[2],
                        verified_findings=row[3],
                        last_activity=row[4],
                    )
                    for row in sources_data
                ],
                findings_by_category=findings_by_category,
                findings_by_severity=findings_by_severity,
                timeline={
                    "daily_activity": [
                        {"date": row[0].isoformat(), "files_submitted": row[1] or 0, "findings_created": row[2] or 0}
                        for row in timeline_data
                    ]
                },
                enrichment_stats={
                    "total_workflows": enrichment_row[0] or 0,
                    "successful": enrichment_row[1] or 0,
                    "failed": enrichment_row[2] or 0,
                    "avg_processing_time": float(enrichment_row[3]) if enrichment_row[3] else 0.0,
                },
            )

            return report

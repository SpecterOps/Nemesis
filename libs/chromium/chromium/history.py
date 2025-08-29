"""Chromium History file parsing and database operations."""

import sqlite3

import psycopg
import structlog
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio

from .helpers import convert_chromium_timestamp, get_postgres_connection_str, parse_chromium_file_path

logger = structlog.get_logger(module=__name__)


def process_chromium_history(object_id: str, file_path: str | None = None) -> None:
    """Process Chromium History file and insert URLs and downloads into database.

    Args:
        object_id: The object ID of the History file
        file_path: Optional path to already downloaded file
    """
    logger.info("Processing Chromium History file", object_id=object_id)

    file_enriched = get_file_enriched(object_id)

    # Extract username and browser from file path
    username, browser = parse_chromium_file_path(file_enriched.path or "")
    logger.debug("[process_chromium_history]", username=username, browser=browser)

    # Get database file
    if file_path:
        db_path = file_path
    else:
        storage = StorageMinio()
        with storage.download(file_enriched.object_id) as temp_file:
            db_path = temp_file.name

    # Process both tables
    _insert_history_urls(object_id, file_enriched, username, browser, db_path)
    _insert_history_downloads(object_id, file_enriched, username, browser, db_path)

    logger.debug("Completed processing Chromium History", object_id=object_id)


def _insert_history_urls(object_id: str, file_enriched, username: str | None, browser: str, db_path: str) -> None:
    """Extract URLs from History and insert into chromium.history table."""
    try:
        # Read from SQLite
        with sqlite3.connect(db_path) as conn:
            conn.text_factory = lambda x: x.decode("utf-8", errors="replace")
            cursor = conn.cursor()

            cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls")
            rows = cursor.fetchall()

        if not rows:
            return

        # Prepare data for PostgreSQL
        urls_data = []
        for url, title, visit_count, last_visit_time in rows:
            urls_data.append(
                {
                    "originating_object_id": file_enriched.object_id,
                    "agent_id": file_enriched.agent_id,
                    "source": file_enriched.source,
                    "project": file_enriched.project,
                    "username": username,
                    "browser": browser,
                    "url": url,
                    "title": title,
                    "visit_count": visit_count,
                    "last_visit_time": convert_chromium_timestamp(last_visit_time),
                }
            )

        # Insert into PostgreSQL
        conn_str = get_postgres_connection_str()
        with psycopg.connect(conn_str) as pg_conn:
            with pg_conn.cursor() as cur:
                insert_sql = """
                    INSERT INTO chromium.history
                    (originating_object_id, agent_id, source, project, username, browser,
                     url, title, visit_count, last_visit_time)
                    VALUES (%(originating_object_id)s, %(agent_id)s, %(source)s, %(project)s,
                            %(username)s, %(browser)s, %(url)s, %(title)s, %(visit_count)s, %(last_visit_time)s)
                    ON CONFLICT (source, username, browser, url, title, last_visit_time)
                    DO UPDATE SET
                        url = EXCLUDED.url,
                        title = EXCLUDED.title,
                        visit_count = EXCLUDED.visit_count,
                        last_visit_time = EXCLUDED.last_visit_time
                """

                cur.executemany(insert_sql, urls_data)
                pg_conn.commit()

        logger.info("Inserted URLs into database", count=len(urls_data))

    except Exception as e:
        logger.exception("Error processing History URLs", error=str(e))
        raise


def _insert_history_downloads(object_id: str, file_enriched, username: str | None, browser: str, db_path: str) -> None:
    """Extract downloads from History and insert into chromium_downloads table."""
    try:
        # Read from SQLite
        with sqlite3.connect(db_path) as conn:
            conn.text_factory = lambda x: x.decode("utf-8", errors="replace")
            cursor = conn.cursor()

            cursor.execute("SELECT tab_url, target_path, start_time, end_time, total_bytes FROM downloads")
            rows = cursor.fetchall()

        if not rows:
            return

        # Prepare data for PostgreSQL
        downloads_data = []
        for tab_url, target_path, start_time, end_time, total_bytes in rows:
            downloads_data.append(
                {
                    "originating_object_id": file_enriched.object_id,
                    "agent_id": file_enriched.agent_id,
                    "source": file_enriched.source,
                    "project": file_enriched.project,
                    "username": username,
                    "browser": browser,
                    "url": tab_url,
                    "download_path": target_path,
                    "start_time": convert_chromium_timestamp(start_time),
                    "end_time": convert_chromium_timestamp(end_time),
                    "total_bytes": total_bytes,
                }
            )

        # Insert into PostgreSQL
        conn_str = get_postgres_connection_str()
        with psycopg.connect(conn_str) as pg_conn:
            with pg_conn.cursor() as cur:
                insert_sql = """
                    INSERT INTO chromium.downloads
                    (originating_object_id, agent_id, source, project, username, browser,
                     url, download_path, start_time, end_time, total_bytes)
                    VALUES (%(originating_object_id)s, %(agent_id)s, %(source)s, %(project)s,
                            %(username)s, %(browser)s, %(url)s, %(download_path)s,
                            %(start_time)s, %(end_time)s, %(total_bytes)s)
                    ON CONFLICT (source, username, browser, url, download_path, start_time)
                    DO UPDATE SET
                        url = EXCLUDED.url,
                        download_path = EXCLUDED.download_path,
                        start_time = EXCLUDED.start_time,
                        end_time = EXCLUDED.end_time,
                        total_bytes = EXCLUDED.total_bytes
                """

                cur.executemany(insert_sql, downloads_data)
                pg_conn.commit()

        logger.info("Inserted downloads into database", count=len(downloads_data))

    except Exception as e:
        logger.exception("Error processing History downloads", error=str(e))
        raise

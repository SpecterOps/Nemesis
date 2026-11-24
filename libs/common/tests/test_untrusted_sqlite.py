"""Tests for common.untrusted_sqlite: collected SQLite files must not stall file enrichment."""

import asyncio
import sqlite3
import time

import pytest
from common.untrusted_sqlite import (
    SqliteTimeBudgetExceeded,
    UnexpectedSqliteSchema,
    read_untrusted_sqlite,
    read_untrusted_sqlite_async,
    require_tables,
)

# A recursive query that returns no row and never terminates, as in the crafted Cookies file
ENDLESS = "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) SELECT n FROM r WHERE n < 0"


def make_db(path, *statements):
    conn = sqlite3.connect(path)
    for statement in statements:
        conn.execute(statement)
    conn.commit()
    conn.close()
    return str(path)


@pytest.fixture
def cookies_table(tmp_path):
    return make_db(
        tmp_path / "Cookies",
        "CREATE TABLE cookies (host_key TEXT, name TEXT)",
        "INSERT INTO cookies VALUES ('example.com', 'sid'), ('example.org', 'token')",
    )


@pytest.fixture
def cookies_view(tmp_path):
    return make_db(
        tmp_path / "Cookies",
        "CREATE TABLE real_cookies (host_key TEXT, name TEXT)",
        f"CREATE VIEW cookies(host_key, name) AS {ENDLESS.replace('SELECT n FROM', 'SELECT n, n FROM')}",
    )


def read_cookies(conn):
    require_tables(conn, "cookies")
    return conn.execute("SELECT host_key, name FROM cookies ORDER BY host_key").fetchall()


def run_endless(conn):
    return conn.execute(ENDLESS).fetchall()


# --- happy path ---


def test_reads_a_real_table(cookies_table):
    assert read_untrusted_sqlite(cookies_table, read_cookies) == [("example.com", "sid"), ("example.org", "token")]


@pytest.mark.asyncio
async def test_async_reads_a_real_table(cookies_table):
    rows = await read_untrusted_sqlite_async(cookies_table, read_cookies)
    assert len(rows) == 2


def test_connect_kwargs_are_passed_through(cookies_table):
    def read_with_types(conn):
        return conn.execute('SELECT 1 AS "x [INTEGER]"').fetchone()[0]

    assert read_untrusted_sqlite(cookies_table, read_with_types, detect_types=sqlite3.PARSE_COLNAMES) == 1


def test_path_with_uri_special_characters(tmp_path):
    path = make_db(tmp_path / "odd ?name#100%.db", "CREATE TABLE t (x)", "INSERT INTO t VALUES (7)")
    assert read_untrusted_sqlite(path, lambda c: c.execute("SELECT x FROM t").fetchone()[0]) == 7


def test_require_tables_accepts_several(tmp_path):
    path = make_db(tmp_path / "History", "CREATE TABLE urls (x)", "CREATE TABLE downloads (x)")
    read_untrusted_sqlite(path, lambda c: require_tables(c, "urls", "downloads"))


def read_as_bytes(conn):
    conn.text_factory = bytes
    return read_cookies(conn)


def test_require_tables_with_bytes_text_factory(cookies_table):
    assert read_untrusted_sqlite(cookies_table, read_as_bytes)[0] == (b"example.com", b"sid")


def test_view_refused_with_bytes_text_factory(cookies_view):
    with pytest.raises(UnexpectedSqliteSchema, match="found view"):
        read_untrusted_sqlite(cookies_view, read_as_bytes)


# --- crafted databases ---


def test_view_in_place_of_table_is_refused_without_running_it(cookies_view):
    start = time.monotonic()
    with pytest.raises(UnexpectedSqliteSchema, match="'cookies' to be a table, found view"):
        read_untrusted_sqlite(cookies_view, read_cookies)
    assert time.monotonic() - start < 2


def test_view_with_different_case_is_refused(tmp_path):
    path = make_db(tmp_path / "Cookies", "CREATE VIEW COOKIES AS SELECT 1 AS host_key, 2 AS name")
    with pytest.raises(UnexpectedSqliteSchema, match="found view"):
        read_untrusted_sqlite(path, read_cookies)


def test_missing_table_is_refused(tmp_path):
    path = make_db(tmp_path / "Cookies", "CREATE TABLE other (x)")
    with pytest.raises(UnexpectedSqliteSchema, match="found nothing"):
        read_untrusted_sqlite(path, read_cookies)


def test_endless_query_is_aborted_at_the_time_budget(cookies_table):
    start = time.monotonic()
    with pytest.raises(SqliteTimeBudgetExceeded, match="0.3s budget"):
        read_untrusted_sqlite(cookies_table, run_endless, time_budget=0.3)
    assert time.monotonic() - start < 5


def test_endless_view_is_aborted_when_the_schema_check_is_skipped(cookies_view):
    with pytest.raises(SqliteTimeBudgetExceeded):
        read_untrusted_sqlite(cookies_view, lambda c: c.execute("SELECT * FROM cookies").fetchall(), time_budget=0.3)


@pytest.mark.asyncio
async def test_endless_query_does_not_block_the_event_loop(cookies_table):
    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0.01)

    task = asyncio.create_task(ticker())
    try:
        with pytest.raises(SqliteTimeBudgetExceeded):
            await read_untrusted_sqlite_async(cookies_table, run_endless, time_budget=1.0)
    finally:
        task.cancel()
    # The loop kept running while the query ran in its worker thread (about 100 ticks in 1 s)
    assert ticks > 20


def test_database_is_opened_read_only(cookies_table):
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        read_untrusted_sqlite(cookies_table, lambda c: c.execute("DELETE FROM cookies"))
    assert len(read_untrusted_sqlite(cookies_table, read_cookies)) == 2


def test_other_sqlite_errors_are_not_reported_as_timeouts(cookies_table):
    with pytest.raises(sqlite3.OperationalError, match="no such column") as excinfo:
        read_untrusted_sqlite(cookies_table, lambda c: c.execute("SELECT missing FROM cookies"))
    assert not isinstance(excinfo.value, SqliteTimeBudgetExceeded)


def test_not_a_database(tmp_path):
    path = tmp_path / "Cookies"
    path.write_bytes(b"not a database" * 100)
    with pytest.raises(sqlite3.DatabaseError):
        read_untrusted_sqlite(path, read_cookies)


def test_missing_file_is_not_created(tmp_path):
    path = tmp_path / "missing.db"
    with pytest.raises(sqlite3.OperationalError):
        read_untrusted_sqlite(path, read_cookies)
    assert not path.exists()

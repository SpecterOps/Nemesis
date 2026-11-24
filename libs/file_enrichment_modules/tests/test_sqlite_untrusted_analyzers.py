"""SQLite-based analyzers must survive crafted databases without stalling the shared event loop."""

import asyncio
import csv
import io
import sqlite3
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from file_enrichment_modules.chromium_cookies.analyzer import ChromeCookiesParser
from file_enrichment_modules.chromium_history.analyzer import ChromeHistoryParser
from file_enrichment_modules.chromium_logins.analyzer import ChromeLoginsParser
from file_enrichment_modules.sqlite.analyzer import SqliteParser, get_table_data

from tests.harness import FileEnrichedFactory, ModuleTestHarness

ENDLESS = "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) SELECT {cols} FROM r WHERE n < 0"
COOKIE_COLUMNS = (
    "host_key, name, path, creation_utc, expires_utc, last_access_utc, last_update_utc, "
    "is_secure, is_httponly, is_persistent, samesite, source_port, encrypted_value"
)


def make_db(path, *statements):
    conn = sqlite3.connect(path)
    for statement in statements:
        conn.execute(statement)
    conn.commit()
    conn.close()
    return str(path)


def crafted_cookies(path):
    """The shape from the report: passes the module's checks, but cookies is an endless VIEW."""
    cols = COOKIE_COLUMNS.split(", ")
    return make_db(
        path,
        # Keeps "CREATE TABLE cookies" and the index name in the file so the YARA rule matches
        "CREATE TABLE cookies_meta (x)",
        "CREATE UNIQUE INDEX cookies_unique_index ON cookies_meta (x)",
        f"CREATE VIEW cookies({', '.join(cols)}) AS {ENDLESS.format(cols=', '.join('n' for _ in cols))}",
    )


def real_cookies(path):
    return make_db(
        path,
        f"CREATE TABLE cookies ({COOKIE_COLUMNS})",
        "CREATE UNIQUE INDEX cookies_unique_index ON cookies (host_key, name, path)",
        "INSERT INTO cookies VALUES ('a.example', 'sid', '/', 13300000000000000, 0, 13300000000000000, 0, "
        "1, 1, 1, 1, 443, x'')",
        "INSERT INTO cookies VALUES ('b|pipe.example', 'tok', '/', 0, 0, 13200000000000000, 0, 0, 0, 0, 0, 80, x'')",
    )


def register(harness, object_id, path, file_name):
    harness.register_file(
        object_id=object_id,
        local_path=path,
        file_enriched=FileEnrichedFactory.create_sqlite_file(object_id=object_id, file_name=file_name),
    )


def capture_uploads(harness) -> dict[str, str]:
    """Record the text of each uploaded file; the module deletes its temp files right after."""
    captured: dict[str, str] = {}
    original = harness.storage.upload_file

    def upload_file(file_path):
        object_id = original(file_path)
        captured[str(object_id)] = Path(file_path).read_text(encoding="utf-8")
        return object_id

    harness.storage.upload_file = upload_file
    return captured


# --- Chromium Cookies: the case from the report ---


@pytest.mark.asyncio
async def test_crafted_cookies_view_passes_detection(tmp_path):
    harness = ModuleTestHarness()
    path = crafted_cookies(tmp_path / "Cookies")
    register(harness, "crafted", path, "Cookies")
    async with harness.create_module(ChromeCookiesParser) as module:
        assert await module.should_process("crafted", path) is True


@pytest.mark.asyncio
async def test_crafted_cookies_view_fails_fast_and_keeps_the_loop_running(tmp_path):
    harness = ModuleTestHarness()
    path = crafted_cookies(tmp_path / "Cookies")
    register(harness, "crafted", path, "Cookies")

    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0.01)

    task = asyncio.create_task(ticker())
    try:
        async with harness.create_module(ChromeCookiesParser) as module:
            start = time.monotonic()
            result = await asyncio.wait_for(module.process("crafted", path), timeout=10)
            elapsed = time.monotonic() - start
    finally:
        task.cancel()

    assert result is None  # the module logs the error and gives up on this file
    assert elapsed < 5
    assert ticks > 0
    assert harness.get_uploaded_files() == {}


@pytest.mark.asyncio
async def test_real_cookies_report_and_csv(tmp_path):
    harness = ModuleTestHarness()
    files = capture_uploads(harness)
    path = real_cookies(tmp_path / "Cookies")
    register(harness, "real", path, "Cookies")
    with patch(
        "file_enrichment_modules.chromium_cookies.analyzer.process_chromium_cookies", new=AsyncMock()
    ) as process_db:
        async with harness.create_module(ChromeCookiesParser) as module:
            result = await module.process("real", path)

    process_db.assert_awaited_once()
    assert result is not None
    assert [t.type for t in result.transforms] == ["finding_summary", "chromium_cookies"]
    report = files[result.transforms[0].object_id]
    assert "Total cookies: 2" in report
    assert "Non-expired cookies (at time of processing): 2" in report
    # Most recent first, and pipes escaped
    assert report.index("a.example") < report.index("b\\|pipe.example")
    rows = list(csv.reader(io.StringIO(files[result.transforms[1].object_id])))
    assert rows[0][:3] == ["creation_utc", "host_key", "source_port"]
    assert {r[1] for r in rows[1:]} == {"a.example", "b|pipe.example"}


# --- Chromium Login Data and History ---


@pytest.mark.asyncio
async def test_logins_view_is_refused(tmp_path):
    harness = ModuleTestHarness()
    cols = "origin_url, username_value, signon_realm, date_created, date_last_used, date_password_modified, times_used, password_value"
    path = make_db(
        tmp_path / "Login Data",
        f"CREATE VIEW logins({cols}) AS {ENDLESS.format(cols=', '.join('n' for _ in cols.split(', ')))}",
    )
    register(harness, "crafted", path, "Login Data")
    with patch("file_enrichment_modules.chromium_logins.analyzer.process_chromium_logins", new=AsyncMock()):
        async with harness.create_module(ChromeLoginsParser) as module:
            result = await asyncio.wait_for(module.process("crafted", path), timeout=10)
    assert result is None


@pytest.mark.asyncio
async def test_real_logins_report(tmp_path):
    harness = ModuleTestHarness()
    files = capture_uploads(harness)
    path = make_db(
        tmp_path / "Login Data",
        "CREATE TABLE logins (origin_url, username_value, signon_realm, date_created, date_last_used, "
        "date_password_modified, times_used, password_value)",
        "INSERT INTO logins VALUES ('https://example.com', 'alice', 'https://example.com', 0, 13300000000000000, 0, 3, x'01')",
    )
    register(harness, "real", path, "Login Data")
    with patch("file_enrichment_modules.chromium_logins.analyzer.process_chromium_logins", new=AsyncMock()):
        async with harness.create_module(ChromeLoginsParser) as module:
            result = await module.process("real", path)
    assert [t.type for t in result.transforms] == ["finding_summary", "chromium_logins"]
    report = files[result.transforms[0].object_id]
    assert "Total logins: 1" in report
    assert "Logins with saved passwords: 1" in report
    assert "| alice |" in report


@pytest.mark.asyncio
async def test_history_downloads_view_is_refused(tmp_path):
    harness = ModuleTestHarness()
    path = make_db(
        tmp_path / "History",
        "CREATE TABLE urls (url, title, visit_count, last_visit_time)",
        "CREATE VIEW downloads(target_path, tab_url, end_time, total_bytes, mime_type, start_time) AS "
        + ENDLESS.format(cols="n, n, n, n, n, n"),
    )
    register(harness, "crafted", path, "History")
    with patch("file_enrichment_modules.chromium_history.analyzer.process_chromium_history", new=AsyncMock()):
        async with harness.create_module(ChromeHistoryParser) as module:
            result = await asyncio.wait_for(module.process("crafted", path), timeout=10)
    assert result is None


@pytest.mark.asyncio
async def test_real_history_report(tmp_path):
    harness = ModuleTestHarness()
    files = capture_uploads(harness)
    path = make_db(
        tmp_path / "History",
        "CREATE TABLE urls (url, title, visit_count, last_visit_time)",
        "CREATE TABLE downloads (target_path, tab_url, start_time, end_time, total_bytes, mime_type)",
        "INSERT INTO urls VALUES ('https://example.com', 'Example', 5, 0)",
        "INSERT INTO downloads VALUES ('C:\\f.exe', 'https://example.com/f', 0, 13300000000000000, 10, 'app/x')",
    )
    register(harness, "real", path, "History")
    with patch("file_enrichment_modules.chromium_history.analyzer.process_chromium_history", new=AsyncMock()):
        async with harness.create_module(ChromeHistoryParser) as module:
            result = await module.process("real", path)
    assert [t.type for t in result.transforms] == ["finding_summary", "chromium_urls", "chromium_downloads"]
    report = files[result.transforms[0].object_id]
    assert "Total URLs visited: 1" in report and "Total Downloads: 1" in report
    downloads = list(csv.reader(io.StringIO(files[result.transforms[2].object_id])))
    assert downloads[1][0] == "C:\\f.exe" and downloads[1][4] == "app/x"


# --- generic SQLite analyzer ---


@pytest.mark.asyncio
async def test_sqlite_analyzer_reads_tables_and_skips_views(tmp_path):
    harness = ModuleTestHarness()
    path = make_db(
        tmp_path / "data.db",
        'CREATE TABLE "odd ""name"" ; x" (a, b)',
        """INSERT INTO "odd ""name"" ; x" VALUES (1, 'one')""",
        f"CREATE VIEW endless AS {ENDLESS.format(cols='n')}",
    )
    register(harness, "db", path, "data.db")
    async with harness.create_module(SqliteParser) as module:
        result = await asyncio.wait_for(module.process("db", path), timeout=10)
    assert list(result.results) == ['odd "name" ; x']
    assert result.results['odd "name" ; x']["data"] == [["1", "one"]]


@pytest.mark.asyncio
async def test_sqlite_analyzer_gives_up_when_over_budget(tmp_path):
    harness = ModuleTestHarness()
    path = make_db(tmp_path / "data.db", "CREATE TABLE t (x)")
    register(harness, "db", path, "data.db")

    def endless(conn):
        return conn.execute(ENDLESS.format(cols="n")).fetchall()

    from common.untrusted_sqlite import read_untrusted_sqlite_async

    async def short_budget(path, reader, **kw):
        return await read_untrusted_sqlite_async(path, endless, time_budget=0.3)

    with patch("file_enrichment_modules.sqlite.analyzer.read_untrusted_sqlite_async", new=short_budget):
        async with harness.create_module(SqliteParser) as module:
            result = await asyncio.wait_for(module.process("db", path), timeout=10)
    assert result is None


def test_get_table_data_reraises_interrupts():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE t (x)")
    conn.set_progress_handler(lambda: 1, 1)
    try:
        with pytest.raises(sqlite3.OperationalError, match="interrupted"):
            get_table_data(conn.cursor(), "t")
    finally:
        conn.close()


def test_get_table_data_reports_other_errors():
    conn = sqlite3.connect(":memory:")
    try:
        # A missing table has no columns; the SELECT then fails and is reported, not raised
        data = get_table_data(conn.cursor(), "missing")
    finally:
        conn.close()
    assert "no such table" in data["error"]

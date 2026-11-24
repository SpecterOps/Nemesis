"""Collected Chromium databases are untrusted: a VIEW posing as a table must not stall the parsers."""

import sqlite3
import time
from types import SimpleNamespace

import pytest
from chromium.cookies import _insert_cookies
from chromium.history import _insert_history_downloads, _insert_history_urls
from chromium.logins import _insert_logins
from common.untrusted_sqlite import UnexpectedSqliteSchema

ENDLESS = "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) SELECT {cols} FROM r WHERE n < 0"

COOKIE_COLUMNS = [
    "host_key",
    "name",
    "path",
    "creation_utc",
    "expires_utc",
    "last_access_utc",
    "last_update_utc",
    "is_secure",
    "is_httponly",
    "is_persistent",
    "samesite",
    "source_port",
    "encrypted_value",
]
LOGIN_COLUMNS = [
    "origin_url",
    "username_value",
    "signon_realm",
    "date_created",
    "date_last_used",
    "date_password_modified",
    "times_used",
    "password_value",
]
URL_COLUMNS = ["url", "title", "visit_count", "last_visit_time"]
DOWNLOAD_COLUMNS = ["tab_url", "target_path", "start_time", "end_time", "total_bytes"]

FILE = SimpleNamespace(object_id="obj-1", agent_id="agent", source="host", project="proj", path="/Cookies")


class FakeConn:
    def __init__(self, log):
        self.log = log

    async def executemany(self, query, rows):
        self.log.extend(rows)


class FakePool:
    """Stands in for asyncpg.Pool; records the rows the parser inserts."""

    def __init__(self):
        self.inserted = []

    def acquire(self):
        pool = self

        class _Ctx:
            async def __aenter__(self):
                return FakeConn(pool.inserted)

            async def __aexit__(self, *exc):
                return False

        return _Ctx()


def make_db(path, *statements):
    conn = sqlite3.connect(path)
    for statement in statements:
        conn.execute(statement)
    conn.commit()
    conn.close()
    return str(path)


def endless_view(name, columns):
    cols = ", ".join("n" for _ in columns)
    return f"CREATE VIEW {name}({', '.join(columns)}) AS {ENDLESS.format(cols=cols)}"


def table(name, columns):
    return f"CREATE TABLE {name} ({', '.join(columns)})"


# --- crafted files are refused quickly ---


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("insert", "view", "columns"),
    [
        (_insert_cookies, "cookies", COOKIE_COLUMNS),
        (_insert_logins, "logins", LOGIN_COLUMNS),
    ],
)
async def test_view_posing_as_table_is_refused(tmp_path, insert, view, columns):
    db = make_db(tmp_path / "db", "CREATE TABLE cookies_decoy (x)", endless_view(view, columns))
    pool = FakePool()
    start = time.monotonic()
    with pytest.raises(UnexpectedSqliteSchema):
        await insert(FILE, "alice", "chrome", db, None, pool)
    assert time.monotonic() - start < 5
    assert pool.inserted == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("insert", "view", "columns"),
    [
        (_insert_history_urls, "urls", URL_COLUMNS),
        (_insert_history_downloads, "downloads", DOWNLOAD_COLUMNS),
    ],
)
async def test_history_view_posing_as_table_is_refused(tmp_path, insert, view, columns):
    db = make_db(tmp_path / "History", endless_view(view, columns))
    pool = FakePool()
    with pytest.raises(UnexpectedSqliteSchema):
        await insert("obj-1", FILE, "alice", "chrome", db, pool)
    assert pool.inserted == []


# --- real databases are still parsed ---


@pytest.mark.asyncio
async def test_cookies_table_is_parsed(tmp_path):
    db = make_db(
        tmp_path / "Cookies",
        table("cookies", COOKIE_COLUMNS),
        "INSERT INTO cookies VALUES ('example.com', 'sid', '/', 13300000000000000, 0, 0, 0, 1, 1, 1, 1, 443, x'')",
    )
    pool = FakePool()
    await _insert_cookies(FILE, None, "chrome", db, None, pool)
    assert len(pool.inserted) == 1
    row = pool.inserted[0]
    assert row[6:9] == ("example.com", "sid", "/")
    assert row[16] == "Lax"


@pytest.mark.asyncio
async def test_logins_table_is_parsed(tmp_path):
    db = make_db(
        tmp_path / "Login Data",
        table("logins", LOGIN_COLUMNS),
        "INSERT INTO logins VALUES ('https://example.com', 'alice', 'https://example.com', 0, 0, 0, 3, x'')",
    )
    pool = FakePool()
    await _insert_logins(FILE, None, "chrome", db, None, pool)
    assert len(pool.inserted) == 1
    assert pool.inserted[0][6:8] == ("https://example.com", "alice")


@pytest.mark.asyncio
async def test_history_tables_are_parsed(tmp_path):
    db = make_db(
        tmp_path / "History",
        table("urls", URL_COLUMNS),
        table("downloads", DOWNLOAD_COLUMNS),
        "INSERT INTO urls VALUES ('https://example.com', 'Example', 2, 0)",
        "INSERT INTO downloads VALUES ('https://example.com/f', 'C:\\f.exe', 0, 0, 10)",
    )
    pool = FakePool()
    await _insert_history_urls("obj-1", FILE, "alice", "chrome", db, pool)
    await _insert_history_downloads("obj-1", FILE, "alice", "chrome", db, pool)
    assert [r[6] for r in pool.inserted] == ["https://example.com", "https://example.com/f"]


@pytest.mark.asyncio
async def test_empty_cookies_table_inserts_nothing(tmp_path):
    db = make_db(tmp_path / "Cookies", table("cookies", COOKIE_COLUMNS))
    pool = FakePool()
    await _insert_cookies(FILE, None, "chrome", db, None, pool)
    assert pool.inserted == []

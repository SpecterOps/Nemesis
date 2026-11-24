"""Chromium key lookups and linking never treat unknown://unknown rows as one profile."""

import pytest
from chromium import helpers
from chromium.retry import _pending_rows_query

EXCLUDE = "source <> 'unknown://unknown'"


class FakeConn:
    def __init__(self):
        self.queries = []

    async def fetchrow(self, query, *args):
        self.queries.append(query)
        return None

    async def fetch(self, query, *args):
        self.queries.append(query)
        return []


class FakePool:
    def __init__(self):
        self.conn = FakeConn()

    def acquire(self):
        conn = self.conn

        class Ctx:
            async def __aenter__(self):
                return conn

            async def __aexit__(self, *exc):
                return False

        return Ctx()


@pytest.mark.asyncio
async def test_state_key_lookup_excludes_unknown_source():
    pool = FakePool()
    assert await helpers.get_state_key_id("unknown://unknown", "bob", "chrome", pool, project="p") is None
    assert all(EXCLUDE in q for q in pool.conn.queries) and pool.conn.queries


@pytest.mark.asyncio
async def test_all_state_keys_lookup_excludes_unknown_source():
    pool = FakePool()
    assert await helpers.get_all_state_keys_from_source("unknown://unknown", pool, project="p") == []
    assert all(EXCLUDE in q for q in pool.conn.queries) and pool.conn.queries


@pytest.mark.parametrize("table,column", [("chromium.cookies", "value_enc"), ("chromium.logins", "password_value_enc")])
def test_profile_scoped_retry_excludes_unknown_source(table, column):
    query = _pending_rows_query(table, column, state_key_scope=("s", "u", "b"))
    assert EXCLUDE in query

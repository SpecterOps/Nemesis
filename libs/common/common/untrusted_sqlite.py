"""Read SQLite databases collected from assessed hosts without letting them stall file enrichment.

A collected database is attacker-controlled. A VIEW can stand in for an expected table and run a
query that never ends, and every workflow activity shares one event loop, so a single such file
would stop all enrichment. Reads here are read-only, bounded by a time budget, and the async entry
point runs them in a worker thread so the event loop keeps serving other files and /healthz.
"""

import asyncio
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

# Generous for real browser databases (a full read of a large History file takes about a second)
DEFAULT_TIME_BUDGET_SECONDS = 30.0
# SQLite VM instructions between deadline checks; cheap at any realistic query speed
_PROGRESS_CHECK_INTERVAL = 10_000


class UntrustedSqliteError(Exception):
    """A collected SQLite database could not be read safely."""


class SqliteTimeBudgetExceeded(UntrustedSqliteError):
    """Reading the database took longer than its time budget, so the query was aborted."""


class UnexpectedSqliteSchema(UntrustedSqliteError):
    """The database does not have the tables the parser expects."""


def require_tables(conn: sqlite3.Connection, *names: str) -> None:
    """Raise UnexpectedSqliteSchema unless every name is a real table (not a view, not missing)."""
    # Names come back as bytes when the caller set text_factory = bytes
    found = {
        (name.decode("utf-8", errors="replace") if isinstance(name, bytes) else str(name)).lower(): (
            kind.decode() if isinstance(kind, bytes) else kind
        )
        for name, kind in conn.execute("SELECT name, type FROM sqlite_master WHERE type IN ('table', 'view')")
    }
    for name in names:
        kind = found.get(name.lower())
        if kind != "table":
            raise UnexpectedSqliteSchema(f"expected {name!r} to be a table, found {kind or 'nothing'}")


def read_untrusted_sqlite[T](
    path: str | Path,
    reader: Callable[[sqlite3.Connection], T],
    *,
    time_budget: float = DEFAULT_TIME_BUDGET_SECONDS,
    **connect_kwargs: Any,
) -> T:
    """Open a collected database read-only and return reader(conn), aborting after time_budget seconds.

    The budget covers everything the reader does, so it must fetch its rows before returning.
    Blocks the calling thread; from async code use read_untrusted_sqlite_async.
    """
    # immutable=1 also skips locking and journal/WAL files, which a lone collected file can't have
    uri = Path(path).resolve().as_uri() + "?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True, **connect_kwargs)
    deadline = time.monotonic() + time_budget
    try:
        # Schema objects (views, triggers, generated columns) may not call functions with side effects
        conn.execute("PRAGMA trusted_schema = OFF")
        conn.set_progress_handler(lambda: time.monotonic() > deadline, _PROGRESS_CHECK_INTERVAL)
        try:
            return reader(conn)
        except sqlite3.OperationalError as e:
            if time.monotonic() > deadline:
                raise SqliteTimeBudgetExceeded(f"SQLite read exceeded its {time_budget:g}s budget") from e
            raise
    finally:
        conn.close()


async def read_untrusted_sqlite_async[T](
    path: str | Path,
    reader: Callable[[sqlite3.Connection], T],
    *,
    time_budget: float = DEFAULT_TIME_BUDGET_SECONDS,
    **connect_kwargs: Any,
) -> T:
    """read_untrusted_sqlite in a worker thread, so a slow database never blocks the event loop."""
    return await asyncio.to_thread(read_untrusted_sqlite, path, reader, time_budget=time_budget, **connect_kwargs)

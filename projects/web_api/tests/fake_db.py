"""Minimal fake psycopg pool/connection/cursor for unit tests (no real PostgreSQL)."""

from contextlib import contextmanager


class FakeCursor:
    """Returns scripted results, one entry per execute() call, and records the SQL/params seen."""

    def __init__(self, results):
        self._results = list(results)
        self._current = []
        self.executed: list[tuple[str, object]] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        if not self._results:
            raise AssertionError(f"Unexpected query: {sql[:200]}")
        self._current = list(self._results.pop(0))

    def fetchall(self):
        rows, self._current = self._current, []
        return rows

    def fetchone(self):
        return self._current.pop(0) if self._current else None


class FakePool:
    """Pool whose connections all share one FakeCursor."""

    def __init__(self, results):
        self.cursor_obj = FakeCursor(results)

    @contextmanager
    def connection(self):
        pool = self

        class _Conn:
            def cursor(self):
                return pool.cursor_obj

        yield _Conn()

    @property
    def executed(self):
        return self.cursor_obj.executed

from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from cli import c2_metadata
from cli.c2_metadata import as_utc, collection_times, join_remote_path


def test_as_utc_naive_is_utc():
    assert as_utc(datetime(2026, 1, 2, 3, 4, 5)) == datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def test_as_utc_converts_aware():
    eastern = timezone(timedelta(hours=-5))
    assert as_utc(datetime(2026, 1, 2, 3, tzinfo=eastern)) == datetime(2026, 1, 2, 8, tzinfo=UTC)


def test_as_utc_none_is_now():
    assert abs(as_utc(None) - datetime.now(UTC)) < timedelta(seconds=5)


def test_collection_times_uses_expiration_days():
    collected = datetime.now(UTC) - timedelta(minutes=5)
    timestamp, expiration = collection_times(collected, 100)
    assert timestamp == collected
    assert timedelta(days=99, hours=23) < expiration - datetime.now(UTC) <= timedelta(days=100)


@pytest.mark.parametrize("now", [datetime(2028, 2, 29, 12, tzinfo=UTC), datetime(2026, 12, 31, 23, 59, tzinfo=UTC)])
def test_collection_times_leap_day_and_new_year(now):
    class FakeDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return now

    with patch.object(c2_metadata, "datetime", FakeDatetime):
        timestamp, expiration = collection_times(now, 365)
    assert timestamp == now
    assert expiration == now + timedelta(days=365)


def test_collection_times_old_download_still_expires_in_future():
    _, expiration = collection_times(datetime(2020, 1, 1, tzinfo=UTC), 10)
    assert expiration > datetime.now(UTC) + timedelta(days=9)


def test_collection_times_rejects_nonpositive_days():
    with pytest.raises(ValueError):
        collection_times(None, 0)


@pytest.mark.parametrize(
    ("directory", "name", "expected"),
    [
        ("C:\\Users\\bob", "a.txt", "C:\\Users\\bob\\a.txt"),
        ("C:\\Users\\bob\\", "a.txt", "C:\\Users\\bob\\a.txt"),
        ("\\\\srv\\share", "a.txt", "\\\\srv\\share\\a.txt"),
        ("/home/bob", "a.txt", "/home/bob/a.txt"),
        ("/home/bob/", "a.txt", "/home/bob/a.txt"),
        ("", "a.txt", "a.txt"),
        (None, "a.txt", "a.txt"),
        ("/home/bob", "", "/home/bob"),
        ("C:/mixed\\path", "a.txt", "C:/mixed\\path/a.txt"),
    ],
)
def test_join_remote_path(directory, name, expected):
    assert join_remote_path(directory, name) == expected

"""get_postgres_connection_str must survive any characters in the credentials (Dapr mocked)."""

from unittest.mock import MagicMock

import pytest
from common import db
from psycopg.conninfo import conninfo_to_dict


def _client(secrets: dict) -> MagicMock:
    client = MagicMock()
    client.get_secret.side_effect = lambda store_name, key: MagicMock(secret={key: secrets[key]})
    return client


def _secrets(user="nemesis", password="Qwerty12345"):
    return {
        "POSTGRES_USER": user,
        "POSTGRES_PASSWORD": password,
        "POSTGRES_HOST": "pgbouncer",
        "POSTGRES_PORT": "5432",
        "POSTGRES_DB": "enrichment",
        "POSTGRES_PARAMETERS": "sslmode=disable",
    }


@pytest.fixture(autouse=True)
def _no_cache():
    db.get_postgres_connection_str.cache_clear()
    yield
    db.get_postgres_connection_str.cache_clear()


@pytest.mark.parametrize(
    "password",
    ["Qwerty12345", "p@ss:w/rd", "with space", "plus+sign", 'quo"te', "per%cent", "h#sh?q=1&x", "ünïcødé"],
)
def test_password_round_trips_through_libpq(password):
    url = db.get_postgres_connection_str(_client(_secrets(password=password)))
    parsed = conninfo_to_dict(url)
    assert parsed["password"] == password
    assert parsed["user"] == "nemesis"
    assert parsed["host"] == "pgbouncer"
    assert parsed["dbname"] == "enrichment"
    assert parsed["sslmode"] == "disable"


def test_user_is_encoded_too():
    url = db.get_postgres_connection_str(_client(_secrets(user="svc@corp")))
    assert conninfo_to_dict(url)["user"] == "svc@corp"


def test_missing_secret_is_reported():
    client = MagicMock()
    client.get_secret.side_effect = RuntimeError("store down")
    with pytest.raises(ValueError, match="Failed to fetch POSTGRES_USER"):
        db.get_postgres_connection_str(client)

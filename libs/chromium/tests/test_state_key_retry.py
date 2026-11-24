"""#109: once a profile's state key decrypts (Local State processed late, or an ABE key unlocked by a chromekey),
its pending key/abe cookies and logins are decrypted immediately instead of waiting for a masterkey event."""

import base64
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from chromium import local_state, retry
from nemesis_dpapi import MasterKeyNotFoundError

SOURCE, USER, BROWSER = "host://WS01", "bob", "chrome"
STATE_KEY = b"k" * 32


class FakeConn:
    def __init__(self, cookies=(), logins=(), state_key_id=7):
        self.cookies = list(cookies)
        self.logins = list(logins)
        self.state_key_id = state_key_id
        self.fetch_calls = []
        self.executed = []

    async def fetch(self, query, *params):
        self.fetch_calls.append((query, params))
        return self.cookies if "chromium.cookies" in query else self.logins

    async def fetchrow(self, query, *params):
        return {"id": self.state_key_id} if self.state_key_id else None

    async def execute(self, query, *params):
        self.executed.append((" ".join(query.split()), params))
        return "UPDATE 1"


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        conn = self.conn

        class Ctx:
            async def __aenter__(self):
                return conn

            async def __aexit__(self, *exc):
                return False

        return Ctx()


def pending(row_id, column, encryption_type="key", state_key_id=7):
    return {
        "id": row_id,
        "encryption_type": encryption_type,
        "masterkey_guid": None,
        "state_key_id": state_key_id,
        column: b"ciphertext",
        "source": SOURCE,
        "username": USER,
        "browser": BROWSER,
    }


def decrypted_updates(conn, table):
    return [
        e for e in conn.executed if e[0].startswith(f"UPDATE chromium.{table} SET") and "is_decrypted = TRUE" in e[0]
    ]


@pytest.fixture
def decrypts(monkeypatch):
    monkeypatch.setattr(retry, "get_state_key_bytes", AsyncMock(return_value=STATE_KEY))
    decrypt = MagicMock(return_value=b"secret-value")
    monkeypatch.setattr(retry, "decrypt_chrome_string", decrypt)
    return decrypt


# --- retry_decrypt_chromium_data_for_state_key ---


@pytest.mark.asyncio
async def test_pending_cookies_and_logins_are_decrypted(decrypts):
    conn = FakeConn(cookies=[pending(1, "value_enc")], logins=[pending(2, "password_value_enc", "abe")])
    result = await retry.retry_decrypt_chromium_data_for_state_key(SOURCE, USER, BROWSER, FakePool(conn))
    assert (result["cookies_decrypted"], result["logins_decrypted"]) == (1, 1)
    assert len(decrypted_updates(conn, "cookies")) == 1
    assert len(decrypted_updates(conn, "logins")) == 1


@pytest.mark.asyncio
async def test_query_is_scoped_to_profile_and_undecrypted_key_rows(decrypts):
    conn = FakeConn()
    await retry.retry_decrypt_chromium_data_for_state_key(SOURCE, USER, BROWSER, FakePool(conn))
    assert len(conn.fetch_calls) == 2
    for query, params in conn.fetch_calls:
        assert params == (SOURCE, USER, BROWSER)
        assert "is_decrypted = FALSE" in query
        assert "encryption_type IN ('key', 'abe')" in query
        assert "dpapi" not in query  # DPAPI rows wait for their masterkey


@pytest.mark.asyncio
async def test_no_pending_rows_is_a_noop(decrypts):
    conn = FakeConn()
    result = await retry.retry_decrypt_chromium_data_for_state_key(SOURCE, USER, BROWSER, FakePool(conn))
    assert result["cookies_attempted"] == result["logins_attempted"] == 0
    assert conn.executed == []
    decrypts.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(("username", "browser"), [(None, BROWSER), (USER, None)])
async def test_unknown_profile_is_a_noop(username, browser):
    pool = MagicMock()
    result = await retry.retry_decrypt_chromium_data_for_state_key(SOURCE, username, browser, pool)
    assert result["cookies_attempted"] == 0
    pool.acquire.assert_not_called()


@pytest.mark.asyncio
async def test_row_that_still_fails_stays_pending(monkeypatch):
    monkeypatch.setattr(retry, "get_state_key_bytes", AsyncMock(return_value=STATE_KEY))
    monkeypatch.setattr(retry, "decrypt_chrome_string", MagicMock(side_effect=ValueError("bad tag")))
    conn = FakeConn(cookies=[pending(1, "value_enc")])
    result = await retry.retry_decrypt_chromium_data_for_state_key(SOURCE, USER, BROWSER, FakePool(conn))
    assert result["cookies_decrypted"] == 0
    assert decrypted_updates(conn, "cookies") == []


@pytest.mark.asyncio
async def test_database_error_is_reported_not_raised():
    pool = MagicMock()
    pool.acquire.side_effect = RuntimeError("db down")
    result = await retry.retry_decrypt_chromium_data_for_state_key(SOURCE, USER, BROWSER, pool)
    assert result["errors"]


# --- Local State processed after Cookies / Login Data ---


def local_state_json() -> str:
    # "DPAPI" header + bytes that detect_encryption_type sees as a DPAPI blob (Blob parsing is patched).
    blob = b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf\x01\x15\xd1\x11\x8c\x7a\x00\xc0\x4f\xc2\x97\xeb" + b"\x00" * 40
    return json.dumps({"os_crypt": {"encrypted_key": base64.b64encode(b"DPAPI" + blob).decode()}})


@pytest.fixture
def local_state_env(monkeypatch):
    blob = SimpleNamespace(masterkey_guid="11111111-2222-3333-4444-555555555555")
    monkeypatch.setattr(local_state.Blob, "from_bytes", MagicMock(return_value=blob))
    monkeypatch.setattr(local_state, "_get_chromekey_from_source", AsyncMock(return_value=None))
    retry_mock = AsyncMock()
    monkeypatch.setattr(local_state, "retry_decrypt_chromium_data_for_state_key", retry_mock)
    file_enriched = SimpleNamespace(object_id="obj", agent_id="agent", source=SOURCE, project="proj", path="x")
    return file_enriched, retry_mock


@pytest.mark.asyncio
async def test_local_state_with_available_masterkey_decrypts_pending_rows(local_state_env):
    file_enriched, retry_mock = local_state_env
    dpapi = MagicMock()
    dpapi.decrypt_blob = AsyncMock(return_value=STATE_KEY)
    pool = FakePool(FakeConn())
    await local_state._insert_state_keys(file_enriched, USER, BROWSER, local_state_json(), pool, dpapi)
    retry_mock.assert_awaited_once_with(SOURCE, USER, BROWSER, pool)


@pytest.mark.asyncio
async def test_local_state_key_not_decrypted_leaves_rows_alone(local_state_env):
    file_enriched, retry_mock = local_state_env
    dpapi = MagicMock()
    dpapi.decrypt_blob = AsyncMock(side_effect=MasterKeyNotFoundError("missing"))
    await local_state._insert_state_keys(file_enriched, USER, BROWSER, local_state_json(), FakePool(FakeConn()), dpapi)
    retry_mock.assert_not_awaited()


def test_scoped_retry_is_exported():
    import chromium

    assert chromium.retry_decrypt_chromium_data_for_state_key is retry.retry_decrypt_chromium_data_for_state_key


@pytest.mark.asyncio
async def test_masterkey_retry_query_unchanged(decrypts):
    """The masterkey path still retries DPAPI rows for that masterkey plus all key/abe rows."""
    conn = FakeConn()
    await retry._retry_decrypt_cookies("guid-1", MagicMock(), FakePool(conn))
    query, params = conn.fetch_calls[0]
    assert params == ("guid-1",)
    assert "encryption_type = 'dpapi' AND masterkey_guid = $1" in query


def test_patch_targets_exist():
    """Guards the monkeypatch targets above against renames."""
    assert hasattr(local_state, "Blob") and hasattr(local_state, "_get_chromekey_from_source")

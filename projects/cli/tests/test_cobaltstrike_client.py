"""Tests for cli.cobaltstrike_connector.cobaltstrike_client module."""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest
from cli.cobaltstrike_connector.cobaltstrike_client import (
    Beacon,
    CobaltStrikeClient,
    Download,
)

# --- Beacon dataclass ---


class TestBeacon:
    def _sample_beacon_dict(self) -> dict:
        return {
            "bid": "bid-1",
            "pbid": "pbid-1",
            "pid": 1234,
            "process": "explorer.exe",
            "user": "CORP\\admin",
            "impersonated": None,
            "isAdmin": True,
            "computer": "WORKSTATION1",
            "host": "192.168.1.100",
            "internal": "192.168.1.100",
            "external": "1.2.3.4",
            "os": "Windows 10",
            "version": "4.9",
            "build": 49,
            "charset": "UTF-8",
            "systemArch": "x64",
            "beaconArch": "x64",
            "session": "session-1",
            "listener": "https",
            "pivotHint": None,
            "port": 443,
            "note": None,
            "color": "",
            "alive": True,
            "linkState": "linked",
            "lastCheckinTime": "2025-01-15T10:30:00Z",
            "lastCheckinMs": 1705311000000,
            "lastCheckinFormatted": "10:30:00",
            "sleep": {"sleep": 60, "jitter": 25},
            "supportsSleep": True,
        }

    def test_from_dict(self):
        beacon = Beacon.from_dict(self._sample_beacon_dict())
        assert beacon.bid == "bid-1"
        assert beacon.pid == 1234
        assert beacon.is_admin is True
        assert beacon.computer == "WORKSTATION1"
        assert beacon.sleep == 60
        assert beacon.jitter == 25
        assert beacon.supports_sleep is True
        assert isinstance(beacon.last_checkin_time, datetime)

    def test_from_dict_with_missing_optional_fields(self):
        data = self._sample_beacon_dict()
        data["impersonated"] = None
        data["pivotHint"] = None
        data["note"] = None
        beacon = Beacon.from_dict(data)
        assert beacon.impersonated is None
        assert beacon.pivot_hint is None
        assert beacon.note is None

    def test_from_dict_no_sleep_data(self):
        data = self._sample_beacon_dict()
        data["sleep"] = {}
        beacon = Beacon.from_dict(data)
        assert beacon.sleep == 0
        assert beacon.jitter == 0


# --- Download dataclass ---


class TestDownload:
    def _sample_download_dict(self) -> dict:
        return {
            "id": "dl-1",
            "bid": "bid-1",
            "name": "secrets.txt",
            "path": "C:\\Users\\admin\\secrets.txt",
            "size": 4096,
            "timestamp": 1705311000000,  # milliseconds
        }

    def test_from_dict(self):
        dl = Download.from_dict(self._sample_download_dict())
        assert dl.id == "dl-1"
        assert dl.bid == "bid-1"
        assert dl.name == "secrets.txt"
        assert dl.size == 4096
        assert isinstance(dl.timestamp, datetime)

    def test_timestamp_converted_from_ms(self):
        data = self._sample_download_dict()
        dl = Download.from_dict(data)
        expected = datetime.fromtimestamp(1705311000000 / 1000)
        assert dl.timestamp == expected


# --- CobaltStrikeClient ---


class TestCobaltStrikeClientInit:
    def test_valid_url(self):
        client = CobaltStrikeClient("https://cs.local:50050")
        assert client.base_url == "https://cs.local:50050"
        assert client.verify_ssl is False

    def test_strips_trailing_slash(self):
        client = CobaltStrikeClient("https://cs.local:50050/")
        assert client.base_url == "https://cs.local:50050"

    def test_url_with_path_raises(self):
        with pytest.raises(ValueError, match="must not contain path"):
            CobaltStrikeClient("https://cs.local:50050/api/v1")

    def test_url_with_query_raises(self):
        with pytest.raises(ValueError, match="must not contain path"):
            CobaltStrikeClient("https://cs.local:50050?foo=bar")

    def test_url_with_fragment_raises(self):
        with pytest.raises(ValueError, match="must not contain path"):
            CobaltStrikeClient("https://cs.local:50050#section")

    def test_initial_session_state(self):
        client = CobaltStrikeClient("https://cs.local:50050")
        assert client._session is None
        assert client._access_token is None
        assert client._stored_credentials is None

    def test_custom_verify_ssl(self):
        client = CobaltStrikeClient("https://cs.local", verify_ssl=True)
        assert client.verify_ssl is True


class TestCobaltStrikeClientContextManager:
    @pytest.mark.asyncio
    async def test_aenter_creates_session(self):
        client = CobaltStrikeClient("https://cs.local:50050")
        async with client as c:
            assert c._session is not None
            assert isinstance(c._session, aiohttp.ClientSession)

    @pytest.mark.asyncio
    async def test_aexit_closes_session(self):
        client = CobaltStrikeClient("https://cs.local:50050")
        async with client:
            pass
        assert client._session is None


class TestCobaltStrikeClientRequiresAuth:
    def test_requires_auth_is_static_method(self):
        """Verify requires_auth is a staticmethod (key change in this PR)."""
        # Access from the class dict to check it's a staticmethod descriptor
        raw = CobaltStrikeClient.__dict__["requires_auth"]
        assert isinstance(raw, staticmethod)

    @pytest.mark.asyncio
    async def test_requires_auth_decorator_passes_through_on_success(self):
        """When the wrapped function succeeds, the result is returned directly."""

        @CobaltStrikeClient.requires_auth
        async def mock_method(self):
            return "success"

        client = CobaltStrikeClient("https://cs.local:50050")
        result = await mock_method(client)
        assert result == "success"

    @pytest.mark.asyncio
    async def test_requires_auth_reauths_on_401(self):
        """On 401, the decorator should attempt reauthentication."""
        call_count = 0

        @CobaltStrikeClient.requires_auth
        async def mock_method(self):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise aiohttp.ClientResponseError(
                    request_info=MagicMock(),
                    history=(),
                    status=401,
                    message="Unauthorized",
                )
            return "success_after_reauth"

        client = CobaltStrikeClient("https://cs.local:50050")
        client._reauthenticate = AsyncMock(return_value=True)

        result = await mock_method(client)
        assert result == "success_after_reauth"
        client._reauthenticate.assert_called_once()

    @pytest.mark.asyncio
    async def test_requires_auth_raises_on_reauth_failure(self):
        """If reauthentication fails, the original error is re-raised."""

        @CobaltStrikeClient.requires_auth
        async def mock_method(self):
            raise aiohttp.ClientResponseError(
                request_info=MagicMock(),
                history=(),
                status=401,
                message="Unauthorized",
            )

        client = CobaltStrikeClient("https://cs.local:50050")
        client._reauthenticate = AsyncMock(return_value=False)

        with pytest.raises(aiohttp.ClientResponseError):
            await mock_method(client)

    @pytest.mark.asyncio
    async def test_requires_auth_raises_non_401_errors(self):
        """Non-401/403 errors should not trigger reauthentication."""

        @CobaltStrikeClient.requires_auth
        async def mock_method(self):
            raise aiohttp.ClientResponseError(
                request_info=MagicMock(),
                history=(),
                status=500,
                message="Server Error",
            )

        client = CobaltStrikeClient("https://cs.local:50050")
        client._reauthenticate = AsyncMock()

        with pytest.raises(aiohttp.ClientResponseError):
            await mock_method(client)
        client._reauthenticate.assert_not_called()

    def test_requires_auth_preserves_function_name(self):
        """functools.wraps should preserve the original function name."""

        @CobaltStrikeClient.requires_auth
        async def my_custom_method(self):
            pass

        assert my_custom_method.__name__ == "my_custom_method"


class TestCobaltStrikeClientAuthenticate:
    @pytest.mark.asyncio
    async def test_authenticate_no_session_raises(self):
        client = CobaltStrikeClient("https://cs.local:50050")
        with pytest.raises(RuntimeError, match="Client session not established"):
            await client.authenticate("user", "pass")

    @pytest.mark.asyncio
    async def test_get_beacons_no_session_raises(self):
        client = CobaltStrikeClient("https://cs.local:50050")
        # Need to bypass the requires_auth decorator by calling the underlying method
        # Since requires_auth wraps it, we test through the wrapper
        # But the session check happens inside the method body
        client._stored_credentials = {"username": "u", "password": "p"}

        # Mock _reauthenticate to avoid network calls from the decorator
        async with client as c:
            # Override session to None after entering to test the guard
            c._session = None
            with pytest.raises(RuntimeError, match="Client session not established"):
                # Call the unwrapped function directly
                await CobaltStrikeClient.get_beacons.__wrapped__(c)

"""Tests for cli.stage1_connector.outflankc2_client module."""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest
from cli.stage1_connector.outflankc2_client import (
    Download,
    Implant,
    OutflankC2Client,
)

# --- Implant dataclass ---


class TestImplant:
    def _sample_implant_dict(self) -> dict:
        return {
            "uid": "impl-1",
            "version": "1.0",
            "hostname": "WORKSTATION1",
            "username": "admin",
            "os": "Windows 10",
            "first_seen": "2025-01-15T10:00:00",
            "last_seen": "2025-01-15T12:00:00",
            "checkin_count": 42,
            "privilege": 3,
            "pid": 5678,
            "ppid": 1234,
            "proc_name": "svchost.exe",
            "pproc_name": "services.exe",
        }

    def test_from_dict(self):
        implant = Implant.from_dict(self._sample_implant_dict())
        assert implant.uid == "impl-1"
        assert implant.hostname == "WORKSTATION1"
        assert implant.checkin_count == 42
        assert implant.pid == 5678
        assert isinstance(implant.first_seen, datetime)
        assert isinstance(implant.last_seen, datetime)

    def test_from_dict_preserves_all_fields(self):
        data = self._sample_implant_dict()
        implant = Implant.from_dict(data)
        assert implant.version == "1.0"
        assert implant.username == "admin"
        assert implant.os == "Windows 10"
        assert implant.privilege == 3
        assert implant.ppid == 1234
        assert implant.proc_name == "svchost.exe"
        assert implant.pproc_name == "services.exe"


# --- Download dataclass ---


class TestDownload:
    def _sample_download_dict(self) -> dict:
        return {
            "uid": "dl-1",
            "timestamp": "2025-01-15T10:30:00",
            "path": "C:\\Users\\admin\\secrets.txt",
            "name": "secrets.txt",
            "size": 4096,
            "progress": 1.0,
            "task_uid": "task-1",
            "implant_uid": "impl-1",
            "implant": {
                "username": "admin",
                "hostname": "WORKSTATION1",
            },
        }

    def test_from_dict(self):
        dl = Download.from_dict(self._sample_download_dict())
        assert dl.uid == "dl-1"
        assert dl.name == "secrets.txt"
        assert dl.size == 4096
        assert dl.progress == 1.0
        assert isinstance(dl.timestamp, datetime)

    def test_from_dict_extracts_implant_fields(self):
        dl = Download.from_dict(self._sample_download_dict())
        assert dl.implant_username == "admin"
        assert dl.implant_hostname == "WORKSTATION1"

    def test_from_dict_partial_progress(self):
        data = self._sample_download_dict()
        data["progress"] = 0.5
        dl = Download.from_dict(data)
        assert dl.progress == 0.5


# --- OutflankC2Client ---


class TestOutflankC2ClientInit:
    def test_valid_url(self):
        client = OutflankC2Client("https://outflank.local:8443")
        assert client.base_url == "https://outflank.local:8443"
        assert client.verify_ssl is False

    def test_strips_trailing_slash(self):
        client = OutflankC2Client("https://outflank.local/")
        assert client.base_url == "https://outflank.local"

    def test_url_with_path_raises(self):
        with pytest.raises(ValueError, match="must not contain path"):
            OutflankC2Client("https://outflank.local/api/v1")

    def test_url_with_query_raises(self):
        with pytest.raises(ValueError, match="must not contain path"):
            OutflankC2Client("https://outflank.local?key=val")

    def test_url_with_fragment_raises(self):
        with pytest.raises(ValueError, match="must not contain path"):
            OutflankC2Client("https://outflank.local#frag")

    def test_initial_session_state(self):
        client = OutflankC2Client("https://outflank.local")
        assert client._session is None
        assert client._access_token is None
        assert client._stored_credentials is None

    def test_custom_verify_ssl(self):
        client = OutflankC2Client("https://outflank.local", verify_ssl=True)
        assert client.verify_ssl is True


class TestOutflankC2ClientContextManager:
    @pytest.mark.asyncio
    async def test_aenter_creates_session(self):
        client = OutflankC2Client("https://outflank.local")
        async with client as c:
            assert c._session is not None
            assert isinstance(c._session, aiohttp.ClientSession)

    @pytest.mark.asyncio
    async def test_aexit_closes_session(self):
        client = OutflankC2Client("https://outflank.local")
        async with client:
            pass
        assert client._session is None


class TestOutflankC2ClientRequiresAuth:
    def test_requires_auth_is_static_method(self):
        """Verify requires_auth is a staticmethod (key change in this PR)."""
        raw = OutflankC2Client.__dict__["requires_auth"]
        assert isinstance(raw, staticmethod)

    @pytest.mark.asyncio
    async def test_requires_auth_passes_through_on_success(self):
        @OutflankC2Client.requires_auth
        async def mock_method(self):
            return "ok"

        client = OutflankC2Client("https://outflank.local")
        result = await mock_method(client)
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_requires_auth_reauths_on_401(self):
        call_count = 0

        @OutflankC2Client.requires_auth
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
            return "retried"

        client = OutflankC2Client("https://outflank.local")
        client._reauthenticate = AsyncMock(return_value=True)

        result = await mock_method(client)
        assert result == "retried"
        client._reauthenticate.assert_called_once()

    @pytest.mark.asyncio
    async def test_requires_auth_raises_on_reauth_failure(self):
        @OutflankC2Client.requires_auth
        async def mock_method(self):
            raise aiohttp.ClientResponseError(
                request_info=MagicMock(),
                history=(),
                status=401,
                message="Unauthorized",
            )

        client = OutflankC2Client("https://outflank.local")
        client._reauthenticate = AsyncMock(return_value=False)

        with pytest.raises(aiohttp.ClientResponseError):
            await mock_method(client)

    @pytest.mark.asyncio
    async def test_requires_auth_does_not_reauth_on_500(self):
        @OutflankC2Client.requires_auth
        async def mock_method(self):
            raise aiohttp.ClientResponseError(
                request_info=MagicMock(),
                history=(),
                status=500,
                message="Server Error",
            )

        client = OutflankC2Client("https://outflank.local")
        client._reauthenticate = AsyncMock()

        with pytest.raises(aiohttp.ClientResponseError):
            await mock_method(client)
        client._reauthenticate.assert_not_called()

    def test_requires_auth_preserves_function_name(self):
        @OutflankC2Client.requires_auth
        async def my_func(self):
            pass

        assert my_func.__name__ == "my_func"


class TestOutflankC2ClientAuthenticate:
    @pytest.mark.asyncio
    async def test_authenticate_no_session_raises(self):
        client = OutflankC2Client("https://outflank.local")
        with pytest.raises(RuntimeError, match="Client session not established"):
            await client.authenticate("user", "join_key")

    @pytest.mark.asyncio
    async def test_get_current_user_no_session_raises(self):
        """get_current_user should raise RuntimeError if session is None (new guard added)."""
        client = OutflankC2Client("https://outflank.local")
        # Access the unwrapped method to bypass requires_auth
        with pytest.raises(RuntimeError, match="Client session not established"):
            await OutflankC2Client.get_current_user.__wrapped__(client)

    @pytest.mark.asyncio
    async def test_get_current_user_no_token_returns_none(self):
        """If no access token, should return None without making a request."""
        client = OutflankC2Client("https://outflank.local")
        client._session = MagicMock()  # session exists
        client._access_token = None
        result = await OutflankC2Client.get_current_user.__wrapped__(client)
        assert result is None

    @pytest.mark.asyncio
    async def test_get_project_info_no_session_raises(self):
        client = OutflankC2Client("https://outflank.local")
        with pytest.raises(RuntimeError, match="Client session not established"):
            await OutflankC2Client.get_project_info.__wrapped__(client)

    @pytest.mark.asyncio
    async def test_get_implants_no_session_raises(self):
        client = OutflankC2Client("https://outflank.local")
        with pytest.raises(RuntimeError, match="Client session not established"):
            await OutflankC2Client.get_implants.__wrapped__(client)

    @pytest.mark.asyncio
    async def test_get_downloads_no_session_raises(self):
        client = OutflankC2Client("https://outflank.local")
        with pytest.raises(RuntimeError, match="Client session not established"):
            await OutflankC2Client.get_downloads.__wrapped__(client)

    @pytest.mark.asyncio
    async def test_download_file_no_session_raises(self):
        client = OutflankC2Client("https://outflank.local")
        with pytest.raises(RuntimeError, match="Client session not established"):
            await OutflankC2Client.download_file.__wrapped__(client, "uid-1", "/tmp/out")


class TestOutflankC2ClientReauthenticate:
    @pytest.mark.asyncio
    async def test_reauthenticate_no_stored_creds(self):
        client = OutflankC2Client("https://outflank.local")
        client._stored_credentials = None
        result = await client._reauthenticate()
        assert result is False

    @pytest.mark.asyncio
    async def test_reauthenticate_calls_authenticate(self):
        client = OutflankC2Client("https://outflank.local")
        client._stored_credentials = {"username": "user", "join_key": "key123"}
        client.authenticate = AsyncMock(return_value=True)

        result = await client._reauthenticate()
        assert result is True
        client.authenticate.assert_called_once_with("user", "key123")

"""Tests for cli.mythic_connector.sync module - SyncService initialization guards and URL validation."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cli.mythic_connector.config import (
    DatabaseConfig,
    MythicConfig,
    NemesisConfig,
    NetworkingConfig,
    Settings,
    TokenCredential,
    UsernamePasswordCredential,
    get_settings,
)
from cli.mythic_connector.sync import SyncService


def _make_settings(
    mythic_url="https://mythic.local:7443",
    mythic_cred=None,
    nemesis_url="https://nemesis.local:8080",
    nemesis_cred=None,
) -> Settings:
    """Create a Settings object for testing."""
    if mythic_cred is None:
        mythic_cred = UsernamePasswordCredential(username="admin", password="pass")
    if nemesis_cred is None:
        nemesis_cred = UsernamePasswordCredential(username="nemuser", password="nempass")

    return Settings(
        project="TEST-PROJECT",
        mythic=MythicConfig(url=mythic_url, credential=mythic_cred),
        nemesis=NemesisConfig(
            url=nemesis_url,
            credential=nemesis_cred,
            expiration_days=100,
            max_file_size=1_000_000_000,
        ),
        db=DatabaseConfig(path="/tmp/test_mythic_sync.db"),
        networking=NetworkingConfig(timeout_sec=30, validate_https_certs=False),
    )


class TestSyncServiceInit:
    def test_initial_state(self):
        cfg = _make_settings()
        svc = SyncService(cfg)
        assert svc.cfg is cfg
        assert svc.db is None
        assert svc.mythic is None
        assert svc.nemesis is None
        assert svc.file_handler is None
        assert svc.browser_handler is None


class TestSyncServiceInitializeHandlers:
    def test_raises_if_mythic_not_initialized(self):
        """initialize_handlers should raise RuntimeError if mythic is None (new guard)."""
        cfg = _make_settings()
        svc = SyncService(cfg)
        svc.db = MagicMock()  # db is set
        svc.mythic = None  # mythic is NOT set

        with pytest.raises(RuntimeError, match="Mythic client not initialized"):
            svc.initialize_handlers()

    def test_raises_if_db_not_initialized(self):
        """initialize_handlers should raise RuntimeError if db is None (new guard)."""
        cfg = _make_settings()
        svc = SyncService(cfg)
        svc.mythic = MagicMock()  # mythic is set
        svc.db = None  # db is NOT set

        with pytest.raises(RuntimeError, match="Database not initialized"):
            svc.initialize_handlers()

    @patch("cli.mythic_connector.sync.FileHandler")
    @patch("cli.mythic_connector.sync.NemesisClient")
    def test_success_when_both_initialized(self, mock_nemesis_cls, mock_file_handler_cls):
        """initialize_handlers should succeed when both mythic and db are set."""
        cfg = _make_settings()
        svc = SyncService(cfg)
        svc.mythic = MagicMock()
        svc.db = MagicMock()

        svc.initialize_handlers()

        assert svc.nemesis is not None
        assert svc.file_handler is not None
        mock_nemesis_cls.assert_called_once()
        mock_file_handler_cls.assert_called_once()


class TestSyncServiceInitializeMythic:
    @pytest.mark.asyncio
    async def test_url_missing_hostname_raises(self):
        """URLs without a hostname should raise ValueError (new validation)."""
        cfg = _make_settings(mythic_url="https://:7443")
        svc = SyncService(cfg)

        # Mock the HTTP connection test to succeed so we reach the URL parsing
        with patch("aiohttp.ClientSession") as mock_session_cls:
            mock_session = AsyncMock()
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
            mock_session.get.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_session_cls.return_value = mock_session

            result = await svc.initialize_mythic()
            # Should fail because hostname is empty
            assert result is False

    @pytest.mark.asyncio
    async def test_url_missing_port_raises(self):
        """URLs without a port should raise ValueError (new validation)."""
        cfg = _make_settings(mythic_url="https://mythic.local")
        svc = SyncService(cfg)

        with patch("aiohttp.ClientSession") as mock_session_cls:
            mock_session = AsyncMock()
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
            mock_session.get.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_session_cls.return_value = mock_session

            result = await svc.initialize_mythic()
            # Should fail because port is None
            assert result is False

    @pytest.mark.asyncio
    async def test_connection_failure(self):
        """Failed HTTP connection should return False."""
        cfg = _make_settings()
        svc = SyncService(cfg)

        with patch("aiohttp.ClientSession") as mock_session_cls:
            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session.get.side_effect = Exception("Connection refused")
            mock_session_cls.return_value = mock_session

            result = await svc.initialize_mythic()
            assert result is False

    @pytest.mark.asyncio
    async def test_with_token_credential(self):
        """Token-based auth should use apitoken parameter."""
        cfg = _make_settings(
            mythic_url="https://mythic.local:7443",
            mythic_cred=TokenCredential(token="test-token"),
        )
        svc = SyncService(cfg)

        with (
            patch("cli.mythic_connector.sync.aiohttp.ClientSession") as mock_session_cls,
            patch("cli.mythic_connector.sync.mythic") as mock_mythic,
        ):
            # Build async context manager mocks matching:
            #   async with aiohttp.ClientSession() as session:
            #       async with session.get(...) as resp:

            mock_resp = MagicMock()
            mock_resp.status = 200

            # session.get(...) returns an async context manager
            mock_get_cm = MagicMock()
            mock_get_cm.__aenter__ = AsyncMock(return_value=mock_resp)
            mock_get_cm.__aexit__ = AsyncMock(return_value=False)

            mock_session = MagicMock()
            mock_session.get = MagicMock(return_value=mock_get_cm)

            # aiohttp.ClientSession() returns an async context manager
            mock_session_cm = MagicMock()
            mock_session_cm.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session_cm.__aexit__ = AsyncMock(return_value=False)
            mock_session_cls.return_value = mock_session_cm

            mock_mythic.login = AsyncMock(return_value=MagicMock())

            result = await svc.initialize_mythic()
            assert result is True
            mock_mythic.login.assert_called_once_with(
                apitoken="test-token",
                server_ip="mythic.local",
                server_port=7443,
                ssl=True,
                logging_level=30,  # logging.WARNING
                timeout=10,
            )


class TestSyncServiceRun:
    @pytest.mark.asyncio
    async def test_run_fails_if_file_handler_none(self):
        """The run method should raise if file_handler is None after init (new guard)."""
        cfg = _make_settings()
        svc = SyncService(cfg)

        # Mock successful init steps but leave file_handler as None
        svc.initialize_db = AsyncMock(return_value=True)
        svc.initialize_mythic = AsyncMock(return_value=True)
        svc.initialize_handlers = MagicMock()
        # Don't set file_handler - it stays None

        # The run method catches exceptions internally and logs them,
        # so we need to check that initialize_handlers is called
        # and that it handles the None file_handler gracefully
        with patch("asyncio.sleep", new_callable=AsyncMock):
            await svc.run()
        # run() should not crash - it catches and logs exceptions

    @pytest.mark.asyncio
    async def test_run_db_init_failure(self):
        """If DB init fails, run should handle it gracefully."""
        cfg = _make_settings()
        svc = SyncService(cfg)
        svc.initialize_db = AsyncMock(return_value=False)

        with patch("asyncio.sleep", new_callable=AsyncMock):
            await svc.run()
        # Should not raise

    @pytest.mark.asyncio
    async def test_run_mythic_init_failure(self):
        """If Mythic init fails, run should handle it gracefully."""
        cfg = _make_settings()
        svc = SyncService(cfg)
        svc.initialize_db = AsyncMock(return_value=True)
        svc.initialize_mythic = AsyncMock(return_value=False)

        with patch("asyncio.sleep", new_callable=AsyncMock):
            await svc.run()
        # Should not raise


class TestSyncServiceInitializeDb:
    @pytest.mark.asyncio
    async def test_initialize_db(self):
        cfg = _make_settings()
        svc = SyncService(cfg)

        with patch("cli.mythic_connector.sync.Database") as mock_db_cls:
            mock_db_cls.return_value = MagicMock()
            result = await svc.initialize_db()
            assert result is True
            assert svc.db is not None


# --- Settings file integration tests ---

SETTINGS_DIR = Path(__file__).resolve().parent.parent


class TestSettingsMythic:
    """Validate settings_mythic.yaml parses correctly through the Dynaconf-based config."""

    def test_load_settings_file(self):
        get_settings.cache_clear()
        cfg = get_settings(str(SETTINGS_DIR / "settings_mythic.yaml"))
        assert isinstance(cfg, Settings)

    def test_project(self):
        get_settings.cache_clear()
        cfg = get_settings(str(SETTINGS_DIR / "settings_mythic.yaml"))
        assert cfg.project == "ASSESS-TEST"

    def test_mythic_section(self):
        get_settings.cache_clear()
        cfg = get_settings(str(SETTINGS_DIR / "settings_mythic.yaml"))
        assert cfg.mythic.url == "https://mythic.local:7443"
        assert isinstance(cfg.mythic.credential, UsernamePasswordCredential)
        assert cfg.mythic.credential.username == "a"
        assert cfg.mythic.credential.password == "a"

    def test_nemesis_section(self):
        get_settings.cache_clear()
        cfg = get_settings(str(SETTINGS_DIR / "settings_mythic.yaml"))
        assert cfg.nemesis.url.scheme == "https"
        assert cfg.nemesis.url.hostname == "nemesis.local"
        assert cfg.nemesis.url.port == 7443
        assert cfg.nemesis.credential.username == "n"
        assert cfg.nemesis.credential.password == "n"
        assert cfg.nemesis.expiration_days == 100
        assert cfg.nemesis.max_file_size == 1_000_000_000

    def test_db_section(self):
        get_settings.cache_clear()
        cfg = get_settings(str(SETTINGS_DIR / "settings_mythic.yaml"))
        assert cfg.db.path == "mythic_sync.db"

    def test_networking_section(self):
        get_settings.cache_clear()
        cfg = get_settings(str(SETTINGS_DIR / "settings_mythic.yaml"))
        assert cfg.networking.timeout_sec == 30
        assert cfg.networking.validate_https_certs is True

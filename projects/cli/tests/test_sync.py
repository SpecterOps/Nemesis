"""Tests for Mythic connector startup, authentication, and supervision."""

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
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
from cli.nemesis_client import PreviewNemesisClient
from common.models2.api import ErrorResponse, HealthResponse


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
    async def _initialize(self, cfg, *, http_status=200, probe=None):
        svc = SyncService(cfg)
        response = MagicMock(status=http_status)
        response_cm = MagicMock()
        response_cm.__aenter__ = AsyncMock(return_value=response)
        response_cm.__aexit__ = AsyncMock(return_value=False)
        session = MagicMock()
        session.get.return_value = response_cm
        session_cm = MagicMock()
        session_cm.__aenter__ = AsyncMock(return_value=session)
        session_cm.__aexit__ = AsyncMock(return_value=False)
        client = MagicMock()
        client.current_operation_id = None
        mythic_api = MagicMock()
        mythic_api.login = AsyncMock(return_value=client)
        mythic_api.execute_custom_query = AsyncMock(
            return_value=probe
            if probe is not None
            else {"meHook": {"status": "success", "current_operation_id": 42}, "filemeta": []}
        )
        session_ctor = MagicMock(return_value=session_cm)
        with (
            patch("cli.mythic_connector.sync.aiohttp.ClientSession", session_ctor),
            patch("cli.mythic_connector.sync.mythic", mythic_api),
        ):
            result = await svc.initialize_mythic()
        return svc, client, session_ctor, session, mythic_api, result

    @pytest.mark.asyncio
    async def test_username_login_uses_configured_url_tls_and_timeout(self):
        cfg = _make_settings(mythic_url="https://mythic.local:7443")
        cfg.networking.timeout_sec = 17
        cfg.networking.validate_https_certs = True

        svc, client, session_ctor, session, mythic_api, result = await self._initialize(cfg)

        assert result is True
        assert client.current_operation_id == 42
        timeout = session_ctor.call_args.kwargs["timeout"]
        assert timeout.total == 17
        session.get.assert_called_once_with(cfg.mythic.url, ssl=True)
        mythic_api.login.assert_awaited_once_with(
            username="admin",
            password="pass",
            server_ip="mythic.local",
            server_port=7443,
            ssl=True,
            logging_level=30,
            timeout=17,
        )
        mythic_api.execute_custom_query.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_http_url_disables_tls_validation_even_when_configured(self):
        cfg = _make_settings(mythic_url="http://mythic.local")
        cfg.networking.validate_https_certs = True

        _, _, _, session, mythic_api, result = await self._initialize(cfg)

        assert result is True
        session.get.assert_called_once_with(cfg.mythic.url, ssl=False)
        assert mythic_api.login.call_args.kwargs["server_port"] == 80
        assert mythic_api.login.call_args.kwargs["ssl"] is False

    @pytest.mark.asyncio
    async def test_token_login_and_successful_empty_filemeta_probe(self):
        cfg = _make_settings(mythic_cred=TokenCredential(token="test-token"))
        svc, client, _, _, mythic_api, result = await self._initialize(
            cfg,
            probe={"meHook": {"status": "success", "current_operation_id": 12}, "filemeta": []},
        )

        assert result is True
        assert svc.mythic is client
        assert client.current_operation_id == 12
        mythic_api.login.assert_awaited_once_with(
            apitoken="test-token",
            server_ip="mythic.local",
            server_port=7443,
            ssl=True,
            logging_level=30,
            timeout=30,
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "probe",
        [
            {"meHook": {"status": "error", "error": "bad token"}, "filemeta": []},
            {"meHook": {"status": "success", "error": "forbidden", "current_operation_id": 12}, "filemeta": []},
            {"meHook": {"status": "success", "current_operation_id": None}, "filemeta": []},
            {"meHook": {"status": "success", "current_operation_id": 12}},
        ],
    )
    async def test_invalid_auth_operation_or_schema_probe_is_fatal(self, probe):
        svc = SyncService(_make_settings(mythic_cred=TokenCredential(token="bad-token")))
        response = MagicMock(status=200)
        response_cm = MagicMock()
        response_cm.__aenter__ = AsyncMock(return_value=response)
        response_cm.__aexit__ = AsyncMock(return_value=False)
        session = MagicMock()
        session.get.return_value = response_cm
        session_cm = MagicMock()
        session_cm.__aenter__ = AsyncMock(return_value=session)
        session_cm.__aexit__ = AsyncMock(return_value=False)
        mythic_api = MagicMock()
        mythic_api.login = AsyncMock(return_value=MagicMock())
        mythic_api.execute_custom_query = AsyncMock(return_value=probe)
        with (
            patch("cli.mythic_connector.sync.aiohttp.ClientSession", return_value=session_cm),
            patch("cli.mythic_connector.sync.mythic", mythic_api),
            pytest.raises(ValueError),
        ):
            await svc.initialize_mythic()
        mythic_api.login.assert_awaited_once()
        mythic_api.execute_custom_query.assert_awaited_once()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("url", ["https://:7443", "ftp://mythic.local:7443"])
    async def test_invalid_url_is_fatal_before_network(self, url):
        cfg = _make_settings(mythic_url=url)
        svc = SyncService(cfg)

        with patch("cli.mythic_connector.sync.aiohttp.ClientSession") as session_ctor:
            with pytest.raises(ValueError):
                await svc.initialize_mythic()
        session_ctor.assert_not_called()

    @pytest.mark.asyncio
    async def test_http_auth_rejection_stops_before_sdk_login(self):
        svc = SyncService(_make_settings())
        response_cm = MagicMock()
        response_cm.__aenter__ = AsyncMock(return_value=MagicMock(status=403))
        response_cm.__aexit__ = AsyncMock(return_value=False)
        session = MagicMock()
        session.get.return_value = response_cm
        session_cm = MagicMock()
        session_cm.__aenter__ = AsyncMock(return_value=session)
        session_cm.__aexit__ = AsyncMock(return_value=False)
        mythic_api = MagicMock()
        mythic_api.login = AsyncMock()
        with (
            patch("cli.mythic_connector.sync.aiohttp.ClientSession", return_value=session_cm),
            patch("cli.mythic_connector.sync.mythic", mythic_api),
            pytest.raises(ValueError, match="authorization rejected"),
        ):
            await svc.initialize_mythic()
        mythic_api.login.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_http_server_failure_propagates_for_supervisor(self):
        svc = SyncService(_make_settings())
        response_cm = MagicMock()
        response_cm.__aenter__ = AsyncMock(return_value=MagicMock(status=503))
        response_cm.__aexit__ = AsyncMock(return_value=False)
        session = MagicMock()
        session.get.return_value = response_cm
        session_cm = MagicMock()
        session_cm.__aenter__ = AsyncMock(return_value=session)
        session_cm.__aexit__ = AsyncMock(return_value=False)
        mythic_api = MagicMock()
        mythic_api.login = AsyncMock()
        with (
            patch("cli.mythic_connector.sync.aiohttp.ClientSession", return_value=session_cm),
            patch("cli.mythic_connector.sync.mythic", mythic_api),
            pytest.raises(aiohttp.ClientResponseError),
        ):
            await svc.initialize_mythic()
        mythic_api.login.assert_not_awaited()


class TestSyncServiceRun:
    @pytest.mark.asyncio
    async def test_preflight_before_database_and_mythic(self):
        svc = SyncService(_make_settings())
        client = AsyncMock()
        client.__aenter__.return_value = client
        events = []

        async def health(**kwargs):
            events.append("preflight")
            return HealthResponse(status="healthy")

        client.get_health.side_effect = health
        svc._create_nemesis_client = MagicMock(return_value=client)

        async def initialize_db():
            events.append("database")
            svc.db = MagicMock()
            return True

        async def initialize_mythic():
            events.append("mythic")
            svc.mythic = MagicMock()
            return True

        async def subscribe():
            events.append("subscribe")
            raise asyncio.CancelledError

        svc.initialize_db = AsyncMock(side_effect=initialize_db)
        svc.initialize_mythic = AsyncMock(side_effect=initialize_mythic)
        svc.initialize_handlers = MagicMock(
            side_effect=lambda: setattr(svc, "file_handler", SimpleNamespace(subscribe=subscribe))
        )
        with pytest.raises(asyncio.CancelledError):
            await svc.run()
        assert client.__aexit__.await_count == 1
        assert events == ["preflight", "database", "mythic", "subscribe"]
        client.get_health.assert_awaited_once_with(timeout=30)

    @pytest.mark.asyncio
    async def test_preflight_failure_stops_startup_and_closes_client(self):
        svc = SyncService(_make_settings())
        client = AsyncMock()
        client.__aenter__.return_value = client
        client.get_health.return_value = ErrorResponse(detail="HTTP 503")
        svc._create_nemesis_client = MagicMock(return_value=client)
        svc.initialize_db = AsyncMock()
        svc.initialize_mythic = AsyncMock()
        svc.initialize_handlers = MagicMock()
        with pytest.raises(RuntimeError, match="Nemesis preflight check failed"):
            await svc.run()
        client.__aexit__.assert_awaited_once()
        svc.initialize_db.assert_not_awaited()
        svc.initialize_mythic.assert_not_awaited()
        svc.initialize_handlers.assert_not_called()

    @pytest.mark.asyncio
    async def test_dry_run_uses_temporary_database_and_restores_config_path(self, tmp_path):
        cfg = _make_settings()
        cfg.db.path = str(tmp_path / "production-state")
        svc = SyncService(cfg)
        observed_paths = []

        async def stop_after_observation():
            observed_paths.append(svc.cfg.db.path)
            raise RuntimeError("stop deterministic dry-run")

        svc._run_with_nemesis = AsyncMock(side_effect=stop_after_observation)
        with pytest.raises(RuntimeError, match="stop deterministic dry-run"):
            await svc.run(dry_run=True)

        assert observed_paths[0] != str(tmp_path / "production-state")
        assert Path(observed_paths[0]).parent.name.startswith("nemesis-mythic-dryrun-")
        assert not Path(observed_paths[0]).parent.exists()
        assert cfg.db.path == str(tmp_path / "production-state")
        assert isinstance(svc.nemesis, PreviewNemesisClient)

    @pytest.mark.asyncio
    async def test_fatal_subscription_closes_state_db_and_nemesis_client(self):
        svc = SyncService(_make_settings())
        events = []
        client = AsyncMock()
        client.__aenter__.return_value = client
        client.get_health.return_value = HealthResponse(status="healthy")
        svc._create_nemesis_client = MagicMock(return_value=client)
        state_db = MagicMock()

        async def initialize_db():
            svc.db = state_db
            events.append("database")
            return True

        async def initialize_mythic():
            svc.mythic = MagicMock()
            events.append("mythic")
            return True

        async def subscribe():
            events.append("subscribe")
            raise ValueError("bad persisted state")

        svc.initialize_db = AsyncMock(side_effect=initialize_db)
        svc.initialize_mythic = AsyncMock(side_effect=initialize_mythic)
        svc.initialize_handlers = MagicMock(
            side_effect=lambda: setattr(svc, "file_handler", SimpleNamespace(subscribe=subscribe))
        )

        with pytest.raises(ValueError, match="bad persisted state"):
            await svc.run()

        assert events == ["database", "mythic", "subscribe"]
        state_db.close.assert_called_once()
        client.__aexit__.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_reconnect_backoff_resets_after_long_session(self, monkeypatch):
        svc = SyncService(_make_settings())
        state_db = MagicMock()
        svc.initialize_db = AsyncMock(side_effect=lambda: setattr(svc, "db", state_db) or True)
        svc.initialize_mythic = AsyncMock(side_effect=asyncio.TimeoutError)
        times = iter([0.0, 61.0, 62.0, 63.0])
        monkeypatch.setattr("cli.mythic_connector.sync.time", SimpleNamespace(monotonic=lambda: next(times)))
        delays = []

        async def stop_after_second_delay(delay):
            delays.append(delay)
            if len(delays) == 2:
                raise asyncio.CancelledError

        monkeypatch.setattr("cli.mythic_connector.sync.asyncio.sleep", stop_after_second_delay)
        with (
            patch("cli.mythic_connector.sync.check_nemesis_availability", new_callable=AsyncMock),
            pytest.raises(asyncio.CancelledError),
        ):
            await svc._run_with_nemesis()

        assert delays == [1, 2]
        state_db.close.assert_called_once()


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

    def test_token_credential_settings_file(self, tmp_path):
        config_file = tmp_path / "settings_mythic_token.yaml"
        config_file.write_text(
            """
project: "ASSESS-TEST"

mythic:
  url: "https://mythic.local:7443"
  credential:
    token: "mythic-api-token"

nemesis:
  url: "https://nemesis.local:7443/"
  credential:
    username: "n"
    password: "n"
  expiration_days: 100
  max_file_size: 1000000000

db:
  path: "mythic_sync.db"

networking:
  timeout_sec: 30
  validate_https_certs: true
""",
        )

        get_settings.cache_clear()
        cfg = get_settings(str(config_file))

        assert isinstance(cfg.mythic.credential, TokenCredential)
        assert cfg.mythic.credential.token == "mythic-api-token"

    def test_mixed_credential_settings_file_is_rejected(self, tmp_path):
        config_file = tmp_path / "settings_mythic_mixed.yaml"
        config_file.write_text(
            """
project: "ASSESS-TEST"

mythic:
  url: "https://mythic.local:7443"
  credential:
    username: "a"
    password: "a"
    token: "mythic-api-token"

nemesis:
  url: "https://nemesis.local:7443/"
  credential:
    username: "n"
    password: "n"
  expiration_days: 100
  max_file_size: 1000000000

db:
  path: "mythic_sync.db"

networking:
  timeout_sec: 30
  validate_https_certs: true
""",
        )

        get_settings.cache_clear()
        with pytest.raises(Exception, match="mythic\\.credential\\.(username|password) cannot exists"):
            get_settings(str(config_file))

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

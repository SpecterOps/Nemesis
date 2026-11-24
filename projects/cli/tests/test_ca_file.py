"""Optional CA file support: --ca-file / NEMESIS_CA_FILE for submit and monitor, and ca_file in connector configs."""

import ssl
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import certifi
import pytest
from cli import tls_trust
from cli.cobaltstrike_connector.cobaltstrike_client import CobaltStrikeClient
from cli.config import CobaltStrikeConfig, NemesisConfig, OutflankConfig
from cli.main import cli
from cli.monitor import NewFileHandler, monitor_main
from cli.mythic_connector import config as mythic_config
from cli.mythic_connector.sync import SyncService
from cli.nemesis_client import NemesisClient
from cli.stage1_connector.outflankc2_client import OutflankC2Client
from cli.submit import create_session_with_retries, submit_files
from click.testing import CliRunner
from pydantic import ValidationError

CREDENTIAL = {"username": "u", "password": "p"}


@pytest.fixture(autouse=True)
def _clear_envvars(monkeypatch):
    monkeypatch.delenv(tls_trust.CA_FILE_ENVVAR, raising=False)
    monkeypatch.delenv("NEMESIS_IGNORE_CERT_ERRORS", raising=False)


@pytest.fixture
def ca_file(tmp_path):
    path = tmp_path / "nemesis-ca.pem"
    path.write_bytes(Path(certifi.where()).read_bytes())
    return path


@pytest.fixture
def recorded_cafiles(monkeypatch):
    """Record the cafile each verifying context is built with, while still building a real context."""
    seen = []
    real = ssl.create_default_context

    def create(*args, **kwargs):
        seen.append(kwargs.get("cafile"))
        return real(*args, **kwargs)

    monkeypatch.setattr(tls_trust.ssl, "create_default_context", create)
    return seen


# --- shared helpers ---


class TestResolveCaFile:
    def test_none_means_system_store(self):
        assert tls_trust.resolve_ca_file(None) is None

    def test_expands_user_and_resolves(self, tmp_path, monkeypatch, ca_file):
        monkeypatch.setenv("HOME", str(tmp_path))
        assert tls_trust.resolve_ca_file("~/nemesis-ca.pem") == str(ca_file.resolve())

    @pytest.mark.parametrize("value", ["", "  "])
    def test_rejects_empty(self, value):
        with pytest.raises(ValueError, match="nonempty"):
            tls_trust.resolve_ca_file(value, "nemesis.ca_file")

    def test_rejects_missing_file(self, tmp_path):
        with pytest.raises(ValueError, match="nemesis.ca_file not found"):
            tls_trust.resolve_ca_file(tmp_path / "missing.pem", "nemesis.ca_file")

    def test_rejects_directory(self, tmp_path):
        with pytest.raises(ValueError, match="not found"):
            tls_trust.resolve_ca_file(tmp_path)


class TestTrustArguments:
    def test_requests_verify(self, ca_file):
        assert tls_trust.requests_verify(True) is True
        assert tls_trust.requests_verify(True, str(ca_file)) == str(ca_file)
        assert tls_trust.requests_verify(False, str(ca_file)) is False

    @pytest.mark.parametrize("builder", [tls_trust.aiohttp_ssl, tls_trust.httpx_verify])
    def test_context_builders_use_ca_file(self, builder, ca_file, recorded_cafiles):
        context = builder(True, str(ca_file))
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        assert recorded_cafiles == [str(ca_file)]

    @pytest.mark.parametrize("builder", [tls_trust.aiohttp_ssl, tls_trust.httpx_verify])
    def test_context_builders_default_to_system_store(self, builder, recorded_cafiles):
        assert builder(True).verify_mode == ssl.CERT_REQUIRED
        assert recorded_cafiles == [None]

    @pytest.mark.parametrize("builder", [tls_trust.aiohttp_ssl, tls_trust.httpx_verify])
    def test_disabled_verification_ignores_ca_file(self, builder, ca_file):
        assert builder(False, str(ca_file)) is False

    def test_invalid_pem_fails(self, tmp_path):
        bad = tmp_path / "bad.pem"
        bad.write_text("not a certificate")
        with pytest.raises(ssl.SSLError):
            tls_trust.verifying_context(str(bad))


# --- submit / monitor ---


class TestSubmit:
    def test_session_uses_ca_bundle(self, ca_file):
        assert create_session_with_retries(verify_ssl=str(ca_file)).verify == str(ca_file)

    def test_ca_file_reaches_auth_check_and_session(self, tmp_path, ca_file):
        target = tmp_path / "file.txt"
        target.write_text("data")
        with (
            patch("cli.submit.validate_auth", return_value=True) as mock_auth,
            patch("cli.submit.create_session_with_retries") as mock_session,
            patch("cli.submit.upload_file", return_value=(True, None, 4)),
        ):
            assert submit_files([target], ca_file=str(ca_file)) is True
        assert mock_auth.call_args.kwargs["verify_ssl"] == str(ca_file)
        assert mock_session.call_args.kwargs["verify_ssl"] == str(ca_file)

    def test_ignore_cert_errors_wins_over_ca_file(self, tmp_path, ca_file):
        target = tmp_path / "file.txt"
        target.write_text("data")
        with (
            patch("cli.submit.validate_auth", return_value=False) as mock_auth,
            patch("cli.submit.logger") as mock_logger,
        ):
            assert submit_files([target], verify_ssl=False, ca_file=str(ca_file)) is False
        assert mock_auth.call_args.kwargs["verify_ssl"] is False
        assert any("Ignoring the CA file" in c.args[0] for c in mock_logger.warning.call_args_list)

    @patch("cli.main.submit_main")
    def test_cli_option(self, mock_submit_main, tmp_path, ca_file):
        result = CliRunner().invoke(cli, ["submit", str(tmp_path), "--ca-file", str(ca_file)])
        assert result.exit_code == 0, result.output
        assert mock_submit_main.call_args.kwargs["ca_file"] == str(ca_file.resolve())

    @patch("cli.main.submit_main")
    def test_cli_envvar(self, mock_submit_main, tmp_path, ca_file):
        result = CliRunner().invoke(cli, ["submit", str(tmp_path)], env={tls_trust.CA_FILE_ENVVAR: str(ca_file)})
        assert result.exit_code == 0, result.output
        assert mock_submit_main.call_args.kwargs["ca_file"] == str(ca_file.resolve())

    @patch("cli.main.submit_main")
    def test_cli_default_is_system_store(self, mock_submit_main, tmp_path):
        result = CliRunner().invoke(cli, ["submit", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert mock_submit_main.call_args.kwargs["ca_file"] is None

    @patch("cli.main.submit_main")
    def test_cli_rejects_missing_file(self, mock_submit_main, tmp_path):
        result = CliRunner().invoke(cli, ["submit", str(tmp_path), "--ca-file", str(tmp_path / "missing.pem")])
        assert result.exit_code != 0
        mock_submit_main.assert_not_called()

    def test_help_documents_option_and_envvar(self):
        result = CliRunner().invoke(cli, ["submit", "--help"])
        assert "--ca-file" in result.output and tls_trust.CA_FILE_ENVVAR in result.output


class TestMonitor:
    @patch("cli.main.monitor_main")
    def test_cli_option(self, mock_monitor_main, tmp_path, ca_file):
        result = CliRunner().invoke(cli, ["monitor", str(tmp_path), "--ca-file", str(ca_file)])
        assert result.exit_code == 0, result.output
        assert mock_monitor_main.call_args.kwargs["ca_file"] == str(ca_file.resolve())

    @patch("cli.monitor.submit_files")
    def test_handler_passes_ca_file(self, mock_submit, ca_file):
        handler = NewFileHandler("h:1", "u", "p", "proj", "agent", MagicMock(), ca_file=str(ca_file))
        handler.submit_path(Path("/tmp/new.txt"))
        assert mock_submit.call_args.kwargs["ca_file"] == str(ca_file)

    @patch("cli.monitor.Observer")
    @patch("cli.monitor.time.sleep", side_effect=KeyboardInterrupt)
    @patch("cli.monitor.submit_files", return_value=True)
    def test_monitor_main_passes_ca_file(self, mock_submit, _sleep, mock_observer, tmp_path, ca_file):
        monitor_main(str(tmp_path), False, "h:1", "u", "p", "proj", "agent", False, 1, False, ca_file=str(ca_file))
        assert mock_submit.call_args.kwargs["ca_file"] == str(ca_file)
        assert mock_observer.return_value.schedule.call_args.args[0].ca_file == str(ca_file)


# --- connector configs and clients ---


class TestConnectorConfig:
    @pytest.mark.parametrize(
        ("model", "extra"),
        [(NemesisConfig, {}), (OutflankConfig, {}), (CobaltStrikeConfig, {"project": "p"})],
    )
    def test_ca_file_optional_and_validated(self, model, extra, ca_file, tmp_path):
        base = {"url": "https://server.local:7443", "credential": CREDENTIAL, **extra}
        assert model(**base).ca_file is None
        assert model(**base, ca_file=str(ca_file)).ca_file == str(ca_file.resolve())
        with pytest.raises(ValidationError, match="not found"):
            model(**base, ca_file=str(tmp_path / "missing.pem"))

    def test_mythic_nemesis_ca_file(self, ca_file, tmp_path):
        data = {"url": "https://n:7443", "credential": CREDENTIAL, "expiration_days": 1, "max_file_size": 1}
        assert mythic_config.NemesisConfig.from_dict(data).ca_file is None
        assert mythic_config.NemesisConfig.from_dict({**data, "ca_file": str(ca_file)}).ca_file == str(
            ca_file.resolve()
        )
        with pytest.raises(ValueError, match="nemesis.ca_file not found"):
            mythic_config.NemesisConfig.from_dict({**data, "ca_file": str(tmp_path / "x.pem")})


class TestNemesisClient:
    @pytest.mark.asyncio
    async def test_uses_config_ca_file(self, ca_file, recorded_cafiles):
        cfg = NemesisConfig(url="https://n:7443", credential=CREDENTIAL, ca_file=str(ca_file))
        with patch("cli.nemesis_client.httpx.AsyncClient") as mock_client:
            mock_client.return_value.aclose = MagicMock()
            client = NemesisClient(cfg)
            await client.__aenter__()
        verify = mock_client.call_args.kwargs["verify"]
        assert isinstance(verify, ssl.SSLContext) and verify.verify_mode == ssl.CERT_REQUIRED
        assert recorded_cafiles == [str(ca_file.resolve())]

    @pytest.mark.asyncio
    async def test_explicit_ca_file_and_disabled_verification(self, ca_file):
        cfg = NemesisConfig(url="https://n:7443", credential=CREDENTIAL)
        assert NemesisClient(cfg, ca_file=str(ca_file)).ca_file == str(ca_file)
        with patch("cli.nemesis_client.httpx.AsyncClient") as mock_client:
            await NemesisClient(cfg, verify_ssl=False, ca_file=str(ca_file)).__aenter__()
        assert mock_client.call_args.kwargs["verify"] is False


class TestC2Clients:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("client_cls", [CobaltStrikeClient, OutflankC2Client])
    async def test_c2_client_uses_ca_file(self, client_cls, ca_file, recorded_cafiles):
        async with client_cls("https://c2.local:50443", ca_file=str(ca_file)) as client:
            context = client._session.connector._ssl
        assert isinstance(context, ssl.SSLContext) and context.verify_mode == ssl.CERT_REQUIRED
        assert recorded_cafiles == [str(ca_file)]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("client_cls", [CobaltStrikeClient, OutflankC2Client])
    async def test_c2_client_verification_disabled(self, client_cls, ca_file):
        async with client_cls("https://c2.local:50443", verify_ssl=False, ca_file=str(ca_file)) as client:
            assert client._session.connector._ssl is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize("client_cls", [CobaltStrikeClient, OutflankC2Client])
    async def test_c2_client_defaults_to_system_store(self, client_cls, recorded_cafiles):
        async with client_cls("https://c2.local:50443") as client:
            assert client._session.connector._ssl.verify_mode == ssl.CERT_REQUIRED
        assert recorded_cafiles == [None]


class TestMythicNemesisClient:
    def test_mythic_passes_nemesis_ca_file(self, ca_file):
        cfg = SimpleNamespace(
            nemesis=mythic_config.NemesisConfig.from_dict(
                {
                    "url": "https://n:7443",
                    "credential": CREDENTIAL,
                    "expiration_days": 1,
                    "max_file_size": 1,
                    "ca_file": str(ca_file),
                }
            ),
            networking=mythic_config.NetworkingConfig(timeout_sec=5, validate_https_certs=True),
        )
        client = SyncService(cfg)._create_nemesis_client()
        assert client.ca_file == str(ca_file.resolve())
        assert client.verify_ssl is True

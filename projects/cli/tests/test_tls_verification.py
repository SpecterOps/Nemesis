"""Tests for HTTPS certificate verification defaults and the --ignore-cert-errors / env var opt-out."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests
from cli.config import Config
from cli.main import IGNORE_CERT_ERRORS_ENVVAR, apply_ignore_cert_errors, cli
from cli.monitor import NewFileHandler, monitor_main
from cli.submit import create_session_with_retries, submit_files, upload_file, validate_auth
from click.testing import CliRunner

CLI_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _clear_envvar(monkeypatch):
    monkeypatch.delenv(IGNORE_CERT_ERRORS_ENVVAR, raising=False)


def _ok_response(status: int = 200) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.raise_for_status.return_value = None
    return response


def _connector_config(validate: bool = True) -> Config:
    return Config(
        validate_https_certs=validate,
        nemesis={"url": "https://nemesis.local:7443", "credential": {"username": "u", "password": "p"}},
    )


# --- submit.py ---


class TestValidateAuth:
    @patch("cli.submit.requests.get")
    def test_verifies_by_default(self, mock_get):
        mock_get.return_value = _ok_response()
        assert validate_auth("nemesis:7443", ("u", "p")) is True
        assert mock_get.call_args.kwargs["verify"] is True

    @patch("cli.submit.requests.get")
    def test_verification_can_be_disabled(self, mock_get):
        mock_get.return_value = _ok_response()
        assert validate_auth("nemesis:7443", ("u", "p"), verify_ssl=False) is True
        assert mock_get.call_args.kwargs["verify"] is False

    @patch("cli.submit.logger")
    @patch("cli.submit.requests.get", side_effect=requests.exceptions.SSLError("self-signed certificate"))
    def test_certificate_error_fails_and_suggests_opt_out(self, _mock_get, mock_logger):
        assert validate_auth("nemesis:7443", ("u", "p")) is False
        message = mock_logger.error.call_args.args[0]
        assert "--ignore-cert-errors" in message
        assert IGNORE_CERT_ERRORS_ENVVAR in message

    @patch("cli.submit.logger")
    @patch("cli.submit.requests.get", side_effect=requests.exceptions.ConnectionError("refused"))
    def test_connection_error_still_handled(self, _mock_get, mock_logger):
        assert validate_auth("nemesis:7443", None) is False
        assert "Could not connect" in mock_logger.error.call_args.args[0]


class TestSessionVerification:
    def test_session_verifies_by_default(self):
        assert create_session_with_retries().verify is True

    def test_session_verification_can_be_disabled(self):
        assert create_session_with_retries(verify_ssl=False).verify is False

    def test_upload_does_not_override_session_verification(self, tmp_path):
        target = tmp_path / "file.txt"
        target.write_text("data")
        session = MagicMock()
        session.post.return_value = _ok_response()

        success, error, size = upload_file(target, "nemesis:7443", session)

        assert (success, error, size) == (True, None, 4)
        assert "verify" not in session.post.call_args.kwargs


class TestSubmitFilesVerification:
    @pytest.mark.parametrize("verify_ssl", [True, False])
    def test_setting_reaches_auth_check_and_session(self, tmp_path, verify_ssl):
        target = tmp_path / "file.txt"
        target.write_text("data")
        with (
            patch("cli.submit.validate_auth", return_value=True) as mock_auth,
            patch("cli.submit.create_session_with_retries") as mock_session,
            patch("cli.submit.upload_file", return_value=(True, None, 4)),
        ):
            assert submit_files([target], verify_ssl=verify_ssl) is True

        assert mock_auth.call_args.kwargs["verify_ssl"] is verify_ssl
        assert mock_session.call_args.kwargs["verify_ssl"] is verify_ssl

    @pytest.mark.parametrize(("verify_ssl", "warned"), [(False, True), (True, False)])
    def test_warns_only_when_verification_disabled(self, tmp_path, verify_ssl, warned):
        target = tmp_path / "file.txt"
        target.write_text("data")
        with (
            patch("cli.submit.validate_auth", return_value=False),
            patch("cli.submit.logger") as mock_logger,
        ):
            assert submit_files([target], verify_ssl=verify_ssl) is False
        warnings = [c.args[0] for c in mock_logger.warning.call_args_list]
        assert any("certificate verification is disabled" in w for w in warnings) is warned

    def test_auth_failure_stops_before_upload(self, tmp_path):
        target = tmp_path / "file.txt"
        target.write_text("data")
        with (
            patch("cli.submit.validate_auth", return_value=False),
            patch("cli.submit.upload_file") as mock_upload,
        ):
            assert submit_files([target]) is False
        mock_upload.assert_not_called()


# --- monitor.py ---


class TestMonitorVerification:
    def test_handler_defaults_to_verifying(self):
        handler = NewFileHandler("h:1", "u", "p", "proj", "agent", MagicMock())
        assert handler.verify_ssl is True

    @patch("cli.monitor.submit_files")
    def test_handler_passes_setting_to_submit(self, mock_submit):
        handler = NewFileHandler("h:1", "u", "p", "proj", "agent", MagicMock(), verify_ssl=False)
        handler.submit_path(Path("/tmp/new.txt"))
        assert mock_submit.call_args.kwargs["verify_ssl"] is False

    @patch("cli.monitor.Observer")
    @patch("cli.monitor.time.sleep", side_effect=KeyboardInterrupt)
    @patch("cli.monitor.submit_files", return_value=True)
    def test_monitor_main_passes_setting_to_initial_submit_and_handler(
        self, mock_submit, _mock_sleep, mock_observer, tmp_path
    ):
        monitor_main(str(tmp_path), False, "h:1", "u", "p", "proj", "agent", False, 1, False, verify_ssl=False)

        assert mock_submit.call_args.kwargs["verify_ssl"] is False
        handler = mock_observer.return_value.schedule.call_args.args[0]
        assert handler.verify_ssl is False


# --- CLI options and environment variable ---


class TestSubmitAndMonitorOptions:
    @patch("cli.main.submit_main")
    def test_submit_verifies_by_default(self, mock_submit_main, tmp_path):
        result = CliRunner().invoke(cli, ["submit", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert mock_submit_main.call_args.kwargs["verify_ssl"] is True

    @patch("cli.main.submit_main")
    def test_submit_flag_disables_verification(self, mock_submit_main, tmp_path):
        result = CliRunner().invoke(cli, ["submit", str(tmp_path), "--ignore-cert-errors"])
        assert result.exit_code == 0, result.output
        assert mock_submit_main.call_args.kwargs["verify_ssl"] is False

    @pytest.mark.parametrize("value", ["1", "true", "yes"])
    @patch("cli.main.submit_main")
    def test_submit_envvar_disables_verification(self, mock_submit_main, value, tmp_path):
        result = CliRunner().invoke(cli, ["submit", str(tmp_path)], env={IGNORE_CERT_ERRORS_ENVVAR: value})
        assert result.exit_code == 0, result.output
        assert mock_submit_main.call_args.kwargs["verify_ssl"] is False

    @pytest.mark.parametrize("value", ["0", "false", "no"])
    @patch("cli.main.submit_main")
    def test_submit_falsey_envvar_keeps_verification(self, mock_submit_main, value, tmp_path):
        result = CliRunner().invoke(cli, ["submit", str(tmp_path)], env={IGNORE_CERT_ERRORS_ENVVAR: value})
        assert result.exit_code == 0, result.output
        assert mock_submit_main.call_args.kwargs["verify_ssl"] is True

    @patch("cli.main.submit_main")
    def test_submit_invalid_envvar_is_rejected(self, mock_submit_main, tmp_path):
        result = CliRunner().invoke(cli, ["submit", str(tmp_path)], env={IGNORE_CERT_ERRORS_ENVVAR: "maybe"})
        assert result.exit_code != 0
        mock_submit_main.assert_not_called()

    @patch("cli.main.submit_main")
    def test_submit_short_flag_disables_verification(self, mock_submit_main, tmp_path):
        result = CliRunner().invoke(cli, ["submit", str(tmp_path), "-k"])
        assert result.exit_code == 0, result.output
        assert mock_submit_main.call_args.kwargs["verify_ssl"] is False

    @patch("cli.main.monitor_main")
    def test_monitor_short_flag_disables_verification(self, mock_monitor_main, tmp_path):
        result = CliRunner().invoke(cli, ["monitor", str(tmp_path), "-k"])
        assert result.exit_code == 0, result.output
        assert mock_monitor_main.call_args.kwargs["verify_ssl"] is False

    @pytest.mark.parametrize("command", ["connect-mythic", "connect-outflank", "connect-cobaltstrike"])
    def test_connectors_accept_short_flag(self, command):
        result = CliRunner().invoke(cli, [command, "--help"])
        assert result.exit_code == 0, result.output
        assert "-k, --ignore-cert-errors" in result.output

    @patch("cli.main.monitor_main")
    def test_monitor_verifies_by_default(self, mock_monitor_main, tmp_path):
        result = CliRunner().invoke(cli, ["monitor", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert mock_monitor_main.call_args.kwargs["verify_ssl"] is True

    @patch("cli.main.monitor_main")
    def test_monitor_flag_disables_verification(self, mock_monitor_main, tmp_path):
        result = CliRunner().invoke(cli, ["monitor", str(tmp_path), "--ignore-cert-errors"])
        assert result.exit_code == 0, result.output
        assert mock_monitor_main.call_args.kwargs["verify_ssl"] is False

    def test_help_documents_flag_and_envvar(self):
        result = CliRunner().invoke(cli, ["submit", "--help"])
        assert "-k, --ignore-cert-errors" in result.output
        assert IGNORE_CERT_ERRORS_ENVVAR in result.output


class TestConnectorOptions:
    def test_apply_leaves_config_alone_without_flag(self):
        assert apply_ignore_cert_errors(_connector_config(True), False).validate_https_certs is True

    def test_apply_disables_verification_with_flag(self):
        assert apply_ignore_cert_errors(_connector_config(True), True).validate_https_certs is False

    def test_apply_never_reenables_verification(self):
        assert apply_ignore_cert_errors(_connector_config(False), False).validate_https_certs is False

    @pytest.mark.parametrize(
        ("command", "runner"),
        [("connect-outflank", "run_outflank_connector"), ("connect-cobaltstrike", "run_cobaltstrike_connector")],
    )
    @pytest.mark.parametrize(
        ("args", "env", "expected"),
        [
            ([], {}, True),
            (["--ignore-cert-errors"], {}, False),
            ([], {IGNORE_CERT_ERRORS_ENVVAR: "1"}, False),
        ],
    )
    def test_connector_flag_and_envvar(self, command, runner, args, env, expected, tmp_path):
        config_path = tmp_path / "connector.yaml"
        config_path.write_text("{}")
        with (
            patch("cli.main.load_config", return_value=_connector_config(True)),
            patch(f"cli.main.{runner}", new=MagicMock()) as mock_run,
            patch("cli.main.asyncio.run"),
        ):
            result = CliRunner().invoke(cli, [command, "--config", str(config_path), *args], env=env)

        assert result.exit_code == 0, result.output
        assert mock_run.call_args.args[0].validate_https_certs is expected

    @pytest.mark.parametrize(
        ("args", "env", "expected"),
        [
            ([], {}, False),
            (["--ignore-cert-errors"], {}, True),
            ([], {IGNORE_CERT_ERRORS_ENVVAR: "true"}, True),
        ],
    )
    def test_mythic_flag_and_envvar(self, args, env, expected, tmp_path):
        config_path = tmp_path / "settings.yaml"
        config_path.write_text("{}")
        with (
            patch("cli.main.start", new=MagicMock()) as mock_start,
            patch("cli.main.asyncio.run"),
        ):
            result = CliRunner().invoke(cli, ["connect-mythic", "--config", str(config_path), *args], env=env)

        assert result.exit_code == 0, result.output
        assert mock_start.call_args.kwargs["ignore_cert_errors"] is expected


class TestMythicStart:
    @pytest.mark.asyncio
    async def test_ignore_cert_errors_overrides_config_without_mutating_cache(self):
        from cli.mythic_connector.config import get_settings
        from cli.mythic_connector.mythic_connector import start

        config_path = str(CLI_DIR / "settings_mythic.yaml")
        get_settings.cache_clear()
        assert get_settings(config_path).networking.validate_https_certs is True

        with patch("cli.mythic_connector.sync.SyncService") as mock_service:
            mock_service.return_value.run = MagicMock(side_effect=lambda **_: _noop())
            await start(config_path, debug=False, ignore_cert_errors=True)

        assert mock_service.call_args.args[0].networking.validate_https_certs is False
        assert get_settings(config_path).networking.validate_https_certs is True
        get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_config_setting_kept_without_flag(self):
        from cli.mythic_connector.config import get_settings
        from cli.mythic_connector.mythic_connector import start

        config_path = str(CLI_DIR / "settings_mythic.yaml")
        get_settings.cache_clear()
        with patch("cli.mythic_connector.sync.SyncService") as mock_service:
            mock_service.return_value.run = MagicMock(side_effect=lambda **_: _noop())
            await start(config_path, debug=False)

        assert mock_service.call_args.args[0].networking.validate_https_certs is True
        get_settings.cache_clear()


async def _noop():
    return None


# --- shipped example configs ---


@pytest.mark.parametrize("name", ["settings_cobaltstrike.yaml", "settings_outflank.yaml"])
def test_shipped_connector_configs_verify_certs(name):
    import yaml

    assert yaml.safe_load((CLI_DIR / name).read_text())["validate_https_certs"] is True


def test_shipped_mythic_config_verifies_certs():
    import yaml

    assert yaml.safe_load((CLI_DIR / "settings_mythic.yaml").read_text())["networking"]["validate_https_certs"] is True
